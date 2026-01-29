// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/ftwhttp"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/coreruleset/go-ftw/v2/utils"
	"github.com/coreruleset/go-ftw/v2/waflog"
)

// Run runs your tests with the specified Config.
func Run(runnerConfig *config.RunnerConfig, tests []*test.FTWTest, out *output.Output) (*TestRunContext, error) {
	out.Println("%s", out.Message("** Running go-ftw!"))

	logLines, err := waflog.NewFTWLogLines(runnerConfig)
	if err != nil {
		return &TestRunContext{}, err
	}

	client, err := ftwhttp.NewClient(runnerConfig)
	if err != nil {
		return &TestRunContext{}, err
	}

	runContext := &TestRunContext{
		RunnerConfig:   runnerConfig,
		Include:        runnerConfig.Include,
		Exclude:        runnerConfig.Exclude,
		IncludeTags:    runnerConfig.IncludeTags,
		ShowTime:       runnerConfig.ShowTime,
		Output:         out,
		ShowOnlyFailed: runnerConfig.ShowOnlyFailed,
		Stats:          NewRunStats(),
		Client:         client,
		LogLines:       logLines,
	}

	for _, tc := range tests {
		if err := RunTest(runContext, tc); err != nil {
			return &TestRunContext{}, err
		}
		if runnerConfig.FailFast && runContext.Stats.TotalFailed() > 0 {
			break
		}
	}

	runContext.Stats.printSummary(out)

	defer cleanLogs(logLines)

	return runContext, nil
}

// RunTest runs an individual test.
// runContext contains information for the current test run
// ftwTest is the test you want to run
func RunTest(runContext *TestRunContext, ftwTest *test.FTWTest) error {
	changed := true

	for _, testCase := range ftwTest.Tests {
		// if we received a particular test ID, skip until we find it
		if needToSkipTest(runContext, &testCase) {
			runContext.Stats.addResultToStats(Skipped, &testCase)
			continue
		}
		runContext.StartTest()
		// Clear previous response when starting a new test
		// (follow_redirect should only work within the same test case)
		runContext.LastStageResponse = nil

		test.ApplyPlatformOverrides(runContext.RunnerConfig, &testCase)
		// this is just for printing once the next test
		if changed && !runContext.ShowOnlyFailed {
			runContext.Output.Println(runContext.Output.Message("=> executing tests in file %s"), ftwTest.Meta.Name)
			changed = false
		}

		if !runContext.ShowOnlyFailed {
			runContext.Output.Printf("\trunning %s: ", testCase.IdString())
		}
		// Iterate over stages
		for _, stage := range testCase.Stages {
			ftwCheck, err := NewCheck(runContext)
			if err != nil {
				return err
			}
			if err := RunStage(runContext, ftwCheck, testCase, stage); err != nil {
				if err.Error() == "retry-once" {
					log.Info().Msgf("Retrying test once: %s", testCase.IdString())
					if err = RunStage(runContext, ftwCheck, testCase, stage); err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}
		runContext.EndTest(&testCase)
		if runContext.RunnerConfig.FailFast && runContext.Stats.TotalFailed() > 0 {
			break
		}
	}

	return nil
}

// RunStage runs an individual test stage.
// runContext contains information for the current test run
// ftwCheck is the current check utility
// testCase is the test case the stage belongs to
// stage is the stage you want to run
//
//gocyclo:ignore
func RunStage(runContext *TestRunContext, ftwCheck *FTWCheck, testCase schema.Test, stage schema.Stage) error {
	runContext.StartStage()
	stageId := utils.GenerateStageId(testCase.RuleId, testCase.TestId)
	// Apply global overrides initially
	testInput := test.NewInput(&stage.Input)
	test.ApplyInputOverrides(runContext.RunnerConfig, testInput)
	expectedOutput := stage.Output
	expectErr := false
	if expectedOutput.ExpectError != nil {
		expectErr = *expectedOutput.ExpectError
	}

	// Check sanity first
	if err := checkTestSanity(&stage); err != nil {
		return err
	}

	// Handle follow_redirect if enabled
	if stage.Input.FollowRedirect != nil && *stage.Input.FollowRedirect {
		redirectLocation, err := extractRedirectLocation(runContext.LastStageResponse, testInput)
		if err != nil {
			return fmt.Errorf("follow_redirect enabled but failed to extract redirect location: %w", err)
		}
		applyRedirectToInput(testInput, redirectLocation)
	}

	// Do not even run test if result is overridden. Directly set and display the overridden result.
	if overridden := overriddenTestResult(ftwCheck, &testCase); overridden != Failed {
		runContext.Result = overridden
		displayResult(&testCase, runContext, overridden, time.Duration(0))
		return nil
	}

	// Destination is needed for a request
	dest := &ftwhttp.Destination{
		DestAddr: testInput.GetDestAddr(),
		Port:     testInput.GetPort(),
		Protocol: testInput.GetProtocol(),
	}

	if notRunningInCloudMode(ftwCheck) {
		startId := utils.CreateStartMarker(stageId)
		startMarker, err := markAndFlush(runContext, testInput, startId)
		if err != nil && !expectErr {
			return fmt.Errorf("failed to find start marker: %w", err)
		}
		ftwCheck.SetStartMarker(startMarker)
	}

	req, err := getRequestFromTest(testInput)
	if err != nil {
		return fmt.Errorf("failed to read request from test specification: %w", err)
	}

	err = runContext.Client.NewConnection(*dest)

	if err != nil && !expectErr {
		return fmt.Errorf("can't connect to destination %+v: %w", dest, err)
	}
	runContext.Client.StartTrackingTime()

	response, responseErr := runContext.Client.Do(*req)

	runContext.Client.StopTrackingTime()
	if responseErr != nil && !expectErr {
		return fmt.Errorf("failed sending request to destination %+v: %w", dest, responseErr)
	}

	if notRunningInCloudMode(ftwCheck) {
		endId := utils.CreateEndMarker(stageId)
		endMarker, err := markAndFlush(runContext, testInput, endId)
		if err != nil && !expectErr {
			return fmt.Errorf("failed to find end marker: %w", err)

		}
		ftwCheck.SetEndMarker(endMarker)
	}

	// Set expected test output in check
	ftwCheck.SetExpectTestOutput((*test.Output)(&expectedOutput))

	// now get the test result based on output
	testResult := checkResult(ftwCheck, response, responseErr)
	if testResult == Failed && expectedOutput.RetryOnce != nil && *expectedOutput.RetryOnce {
		return errors.New("retry-once")
	}

	roundTripTime := runContext.Client.GetRoundTripTime().RoundTripDuration()

	runContext.EndStage(&testCase, testResult, ftwCheck.GetTriggeredRules())

	// Store the response for potential use by follow_redirect in next stage
	runContext.LastStageResponse = response

	// show the result unless quiet was passed in the command line
	displayResult(&testCase, runContext, testResult, roundTripTime)

	return nil
}

func markAndFlush(runContext *TestRunContext, testInput *test.Input, stageId string) ([]byte, error) {
	req := buildMarkerRequest(runContext, testInput, stageId)
	dest := &ftwhttp.Destination{
		DestAddr: testInput.GetDestAddr(),
		Port:     testInput.GetPort(),
		Protocol: testInput.GetProtocol(),
	}
	for i := runContext.RunnerConfig.MaxMarkerRetries; i > 0; i-- {
		err := runContext.Client.NewOrReusedConnection(*dest)
		if err != nil {
			return nil, fmt.Errorf("ftw/run: can't connect to destination %+v: %w", dest, err)
		}

		_, err = runContext.Client.Do(*req)
		if err != nil {
			return nil, fmt.Errorf("ftw/run: failed sending request to %+v: %w", dest, err)
		}

		marker := runContext.LogLines.CheckLogForMarker(stageId, runContext.RunnerConfig.MaxMarkerLogLines)
		if marker != nil {
			return marker, nil
		}
	}
	return nil, fmt.Errorf("can't find log marker. Am I reading the correct log? Log file: %s", runContext.RunnerConfig.LogFilePath)
}

func buildMarkerRequest(runContext *TestRunContext, testInput *test.Input, stageId string) *ftwhttp.Request {
	host := "localhost"
	if testInput.VirtualHostMode {
		// Use the value of the `Host` header of the test for
		// internal requests as well, so that all requests target
		// the same virtual host.
		headers := testInput.GetHeaders()
		if !headers.HasAny("Host") {
			log.Error().Msg("'VirtualHostMode' enabled but no 'Host' header specified")
		} else {
			hostHeaders := headers.GetAll("Host")
			if len(hostHeaders) > 1 {
				log.Error().Msg("'VirtualHostMode' enabled but more than one 'Host' header specified")
			} else {
				host = hostHeaders[0].Value
			}
		}
	}

	header := ftwhttp.NewHeader()
	header.Add("Accept", "*/*")
	header.Add("User-Agent", "go-ftw test agent")
	header.Add("Host", host)
	header.Add(runContext.RunnerConfig.LogMarkerHeaderName, stageId)

	rline := &ftwhttp.RequestLine{
		Method: "GET",
		// Use the `/status` endpoint of `httpbin` (http://httpbingo.org), if possible,
		// to minimize the amount of data transferred and in the log.
		// `httpbin` is used by the CRS test setup.
		URI:     "/status/200",
		Version: "HTTP/1.1",
	}

	return ftwhttp.NewRequest(rline, header, nil, true)
}

func needToSkipTest(runContext *TestRunContext, testCase *schema.Test) bool {
	include := runContext.Include
	exclude := runContext.Exclude
	includeTags := runContext.IncludeTags

	// never skip enabled explicit inclusions
	if include != nil {
		if include.MatchString(testCase.IdString()) {
			// inclusion always wins over exclusion
			return false
		}
	}

	// if the test's tags do not match the passed ones
	// it needs to be skipped
	if includeTags != nil {
		if !utils.MatchSlice(includeTags, testCase.Tags) {
			return true
		}
	}

	// if we need to exclude tests, and the ID matches,
	// it needs to be skipped
	if exclude != nil {
		if exclude.MatchString(testCase.IdString()) {
			return true
		}
	}

	// if we need to include tests, but the ID does not match
	// it needs to be skipped
	if include != nil {
		if !include.MatchString(testCase.IdString()) {
			return true
		}
	}

	return false
}

func checkTestSanity(stage *schema.Stage) error {
	if utils.IsNotEmpty(stage.Input.Data) && stage.Input.EncodedRequest != "" {
		return errors.New("'data' and 'encoded_request' must not be set simultaneously")
	}
	if len(stage.Output.Log.ExpectIds) != 1 && stage.Output.Isolated {
		return errors.New("'isolated' is only valid if 'expected_ids' has exactly one entry")
	}

	return nil
}

func displayResult(testCase *schema.Test, rc *TestRunContext, result TestResult, roundTripTime time.Duration) {
	switch result {
	case Success:
		if !rc.ShowOnlyFailed {
			rc.Output.Println(rc.Output.Message("+ passed in %s (RTT %s)"), rc.CurrentStageDuration, roundTripTime)
		}
	case Failed:
		rc.Output.Println(rc.Output.Message("- %s failed in %s (RTT %s)"), testCase.IdString(), rc.CurrentStageDuration, roundTripTime)
	case Ignored:
		if !rc.ShowOnlyFailed {
			rc.Output.Println(rc.Output.Message(":information:test ignored"))
		}
	case ForceFail:
		rc.Output.Println(rc.Output.Message(":information:test forced to fail"))
	case ForcePass:
		if !rc.ShowOnlyFailed {
			rc.Output.Println(rc.Output.Message(":information:test forced to pass"))
		}
	default:
		// don't print anything if skipped test
	}
}

func overriddenTestResult(c *FTWCheck, testCase *schema.Test) TestResult {
	if c.ForcedIgnore(testCase) {
		return Ignored
	}

	if c.ForcedFail(testCase) {
		return ForceFail
	}

	if c.ForcedPass(testCase) {
		return ForcePass
	}

	return Failed
}

// checkResult has the logic for verifying the result for the test sent
func checkResult(c *FTWCheck, response *ftwhttp.Response, responseError error) TestResult {
	// Request might return an error, but it could be expected, we check that first
	if expected, succeeded := c.AssertExpectError(responseError); expected {
		if succeeded {
			return Success
		}
		return Failed
	}

	// In case of an unexpected error skip other checks
	if responseError != nil {
		log.Debug().Msgf("Encountered unexpected error: %v", responseError)
		return Failed
	}

	// We should have a response here
	if response == nil {
		log.Error().Msg("No response to check")
		return Failed
	}

	if !c.AssertStatus(response.Parsed.StatusCode) {
		return Failed
	}
	if !c.AssertResponseContains(response.GetFullResponse()) {
		return Failed
	}
	// Lastly, check logs
	if !c.AssertLogs() {
		return Failed
	}

	return Success
}

func getRequestFromTest(testInput *test.Input) (*ftwhttp.Request, error) {
	if utils.IsNotEmpty(testInput.EncodedRequest) {
		data, err := base64.StdEncoding.DecodeString(testInput.EncodedRequest)
		if err != nil {
			return nil, err
		}
		return ftwhttp.NewRawRequest(data), nil
	}

	rline := &ftwhttp.RequestLine{
		Method:  testInput.GetMethod(),
		URI:     testInput.GetURI(),
		Version: testInput.GetVersion(),
	}

	data := testInput.GetData()
	//nolint:staticcheck
	return ftwhttp.NewRequest(rline, testInput.GetHeaders(),
		data, *testInput.AutocompleteHeaders), nil
}

func notRunningInCloudMode(c *FTWCheck) bool {
	return !c.CloudMode()
}

func cleanLogs(logLines *waflog.FTWLogLines) {
	if err := logLines.Cleanup(); err != nil {
		log.Error().Err(err).Msg("Failed to cleanup log file")
	}
}
