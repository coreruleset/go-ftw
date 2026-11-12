// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	schema "github.com/coreruleset/ftw-tests-schema/v3/types"
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
	defer cleanLogs(logLines)

	client, err := ftwhttp.NewClient(runnerConfig)
	if err != nil {
		return &TestRunContext{}, err
	}

	runContext := &TestRunContext{
		RunnerConfig:           runnerConfig,
		Include:                runnerConfig.Include,
		Exclude:                runnerConfig.Exclude,
		IncludeTags:            runnerConfig.IncludeTags,
		ShowTime:               runnerConfig.ShowTime,
		Output:                 out,
		ShowOnlyFailed:         runnerConfig.ShowOnlyFailed,
		StoreFailureWafLogs:    runnerConfig.StoreFailureLogs,
		FailureWafLogsFilePath: runnerConfig.FailureWafLogsFilePath,
		Stats:                  NewRunStats(),
		Client:                 client,
		LogLines:               logLines,
	}

	runContext.Stats.FailOnStaleOverrides = runnerConfig.TestOverride.FailOnStaleOverrides()

	for _, tc := range tests {
		if err := RunTest(runContext, tc); err != nil {
			return &TestRunContext{}, err
		}
		if runnerConfig.FailFast && runContext.Stats.TotalFailed() > 0 {
			break
		}
	}

	runContext.Stats.printSummary(out)

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
		// Clear previous response and input when starting a new test
		// (follow_redirect should only work within the same test case)
		runContext.LastStageResponse = nil
		runContext.LastStageInput = nil

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
			skipRemainingStages, err := runStageAllowingOverrides(runContext, ftwCheck, testCase, stage)
			if errors.Is(err, errRetryOnce) {
				log.Info().Msgf("Retrying test once: %s", testCase.IdString())
				skipRemainingStages, err = runStageAllowingOverrides(runContext, ftwCheck, testCase, stage)
				if errors.Is(err, errRetryOnce) && isOverridden(runContext, &testCase) {
					// The retry failed as well. Overrides exist to tolerate failing tests.
					skipRemainingStages, err = completeFailedStage(runContext, &testCase), nil
				}
			}
			if err != nil {
				return fmt.Errorf("%s (test %s): %w", ftwTest.FileName, testCase.IdString(), err)
			}
			if skipRemainingStages {
				break
			}
		}
		runContext.EndTest(&testCase)
		if runContext.RunnerConfig.FailFast && runContext.Stats.TotalFailed() > 0 {
			break
		}
	}

	return nil
}

// errRetryOnce is returned for failed stages that are to be retried once.
var errRetryOnce = errors.New("retry-once")

// transportError marks errors that occur while communicating with the target (connecting, sending
// requests, finding log markers), as opposed to errors in the definition of a test.
type transportError struct {
	err error
}

func (e *transportError) Error() string {
	return e.err.Error()
}

func (e *transportError) Unwrap() error {
	return e.err
}

func newTransportError(format string, args ...any) error {
	return &transportError{err: fmt.Errorf(format, args...)}
}

// runStageAllowingOverrides runs a stage like RunStage, but does not fail on errors that occur
// while communicating with the target if the test is overridden: overrides may exist to avoid
// exactly such errors. The stage is counted as failed in this case.
// Returns true if the remaining stages of the test are to be skipped, because they can't be
// expected to work after a transport error.
// Errors in the definition of a test are never tolerated, they would be hidden by the override.
func runStageAllowingOverrides(runContext *TestRunContext, ftwCheck *FTWCheck, testCase schema.Test, stage schema.Stage) (bool, error) {
	err := RunStage(runContext, ftwCheck, testCase, stage)
	var transportErr *transportError
	if err == nil || !errors.As(err, &transportErr) || !isOverridden(runContext, &testCase) {
		return false, err
	}

	log.Warn().Err(err).Msgf("Transport error in overridden test %s, counting the actual result as failed and skipping remaining stages", testCase.IdString())
	return completeFailedStage(runContext, &testCase), nil
}

// completeFailedStage records the failure of a stage that did not produce a usable response.
// Returns true: the remaining stages of the test are to be skipped, they can't be expected to work.
func completeFailedStage(runContext *TestRunContext, testCase *schema.Test) bool {
	// there is no usable response for a following stage to redirect to
	runContext.LastStageResponse = nil
	runContext.LastStageInput = nil
	completeStage(runContext, testCase, Failed, nil, time.Duration(0))
	return true
}

func isOverridden(runContext *TestRunContext, testCase *schema.Test) bool {
	_, _, overridden := overrideFor(runContext.RunnerConfig, testCase)
	return overridden
}

// RunStage runs an individual test stage.
// runContext contains information for the current test run
// ftwCheck is the current check utility
// testCase is the test case the stage belongs to
// stage is the stage you want to run
//
// Returns errRetryOnce if the stage failed and is to be retried.
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
		redirectLocation, err := extractRedirectLocation(runContext.LastStageResponse, runContext.LastStageInput)
		if err != nil {
			return fmt.Errorf("follow_redirect enabled but failed to extract redirect location: %w", err)
		}
		applyRedirectToInput(testInput, redirectLocation)
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
			return newTransportError("failed to find start marker: %w", err)
		}
		ftwCheck.SetStartMarker(startMarker)
	}

	req, err := getRequestFromTest(testInput)
	if err != nil {
		return fmt.Errorf("failed to read request from test specification: %w", err)
	}

	err = runContext.Client.NewConnection(*dest)

	if err != nil && !expectErr {
		return newTransportError("can't connect to destination %+v: %w", dest, err)
	}
	runContext.Client.StartTrackingTime()

	response, responseErr := runContext.Client.Do(*req)

	runContext.Client.StopTrackingTime()
	if responseErr != nil && !expectErr {
		return newTransportError("failed sending request to destination %+v: %w", dest, responseErr)
	}

	if notRunningInCloudMode(ftwCheck) {
		endId := utils.CreateEndMarker(stageId)
		endMarker, err := markAndFlush(runContext, testInput, endId)
		if err != nil && !expectErr {
			return newTransportError("failed to find end marker: %w", err)

		}
		ftwCheck.SetEndMarker(endMarker)
	}

	// Set expected test output in check
	ftwCheck.SetExpectTestOutput((*test.Output)(&expectedOutput))

	// now get the test result based on output
	testResult := checkResult(ftwCheck, response, responseErr)
	if testResult == Failed && expectedOutput.RetryOnce != nil && *expectedOutput.RetryOnce {
		return errRetryOnce
	}

	roundTripTime := runContext.Client.GetRoundTripTime().RoundTripDuration()

	triggeredRules, err := ftwCheck.GetTriggeredRules()
	if err != nil {
		return err
	}

	// Store the response and input for potential use by follow_redirect in next stage
	runContext.LastStageResponse = response
	runContext.LastStageInput = testInput

	// record the result, apply overrides, and show the result unless quiet was passed in the command line
	completeStage(runContext, &testCase, testResult, triggeredRules, roundTripTime)

	if notRunningInCloudMode(ftwCheck) && runContext.StoreFailureWafLogs {
		if testResult == Failed {
			if err := appendFailureWafLogs(runContext); err != nil {
				log.Error().Err(err).Msg("Failed to append to failed tests log")
			}
		}
	}

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

// completeStage records the actual result of a stage, applies overrides to get the effective
// result, and displays the result.
func completeStage(rc *TestRunContext, testCase *schema.Test, actual TestResult, triggeredRules []uint, roundTripTime time.Duration) {
	effective := actual
	if forced, reason, overridden := overrideFor(rc.RunnerConfig, testCase); overridden {
		effective = forced
		rc.OverrideReason = reason
	}
	if actual == Failed {
		rc.ActualResult = Failed
	}
	rc.EndStage(testCase, effective, triggeredRules)
	displayResult(testCase, rc, effective, actual, roundTripTime)
}

func displayResult(testCase *schema.Test, rc *TestRunContext, result TestResult, actual TestResult, roundTripTime time.Duration) {
	// Always reset to notice afterwards so other output is not mislabeled.
	defer rc.Output.SetSeverity(output.AnnotationNotice)
	switch result {
	case Success:
		if !rc.ShowOnlyFailed {
			rc.Output.Println(rc.Output.Message("+ passed in %s (RTT %s)"), rc.CurrentStageDuration, roundTripTime)
		}
	case Failed:
		rc.Output.SetSeverity(output.AnnotationError)
		rc.Output.Println(rc.Output.Message("- %s failed in %s (RTT %s)"), testCase.IdString(), rc.CurrentStageDuration, roundTripTime)
	case ForceFail:
		rc.Output.Println(rc.Output.Message(":information:test forced to fail (actual: %s)%s"), actualString(actual), reasonSuffix(rc.OverrideReason))
	case ForcePass:
		if !rc.ShowOnlyFailed {
			rc.Output.Println(rc.Output.Message(":information:test forced to pass (actual: %s)%s"), actualString(actual), reasonSuffix(rc.OverrideReason))
		}
	default:
		// don't print anything if skipped test
	}
}

func actualString(actual TestResult) string {
	if actual == Success {
		return passedName
	}
	return failedName
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " - " + reason
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
	logsCheck, err := c.AssertLogs()
	if err != nil {
		log.Error().Err(err).Msg("failed to assert logs")
		return Failed
	}
	if !logsCheck {
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

// appendFailureWafLogs writes the marked log lines for a failed test stage to the failed-tests log file.
func appendFailureWafLogs(runContext *TestRunContext) error {
	lines, err := runContext.LogLines.GetMarkedLines()
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}

	f, err := os.OpenFile(runContext.FailureWafLogsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open failure logs file %q: %w", runContext.FailureWafLogsFilePath, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("Failed to close failures logs file")
		}
	}()

	for _, line := range lines {
		if _, err := f.Write(line); err != nil {
			return fmt.Errorf("failed to write to failure logs file: %w", err)
		}
		if _, err := f.Write([]byte("\n")); err != nil {
			return fmt.Errorf("failed to write newline to failures logs file: %w", err)
		}
	}
	return nil
}
