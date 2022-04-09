package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/fzipi/go-ftw/check"
	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/ftwhttp"
	"github.com/fzipi/go-ftw/test"
	"github.com/fzipi/go-ftw/utils"
	"github.com/fzipi/go-ftw/waflog"
	"github.com/google/uuid"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog/log"
)

// Run runs your tests
// testid is the name of the unique test you want to run
// exclude is a regexp that matches the test name: e.g. "920*", excludes all tests starting with "920"
// Returns error if some test failed
func Run(include string, exclude string, showTime bool, output bool, ftwtests []test.FTWTest) TestRunContext {
	printUnlessQuietMode(output, ":rocket:Running go-ftw!\n")

	client := ftwhttp.NewClient()
	runContext := TestRunContext{
		Include:  include,
		Exclude:  exclude,
		ShowTime: showTime,
		Output:   output,
		Client:   client,
	}

	for _, test := range ftwtests {
		RunTest(&runContext, test)
	}

	printSummary(output, runContext.Stats)

	return runContext
}

// RunTest runs an individual test.
// runContext contains information for the current test run
// ftwTest is the test you want to run
func RunTest(runContext *TestRunContext, ftwTest test.FTWTest) {
	changed := true

	for _, testCase := range ftwTest.Tests {
		// if we received a particular testid, skip until we find it
		if needToSkipTest(runContext.Include, runContext.Exclude, testCase.TestTitle, ftwTest.Meta.Enabled) {
			addResultToStats(Skipped, testCase.TestTitle, &runContext.Stats)
			printUnlessQuietMode(runContext.Output, "Skipping test %s\n", testCase.TestTitle)
			continue
		}
		// this is just for printing once the next test
		if changed {
			printUnlessQuietMode(runContext.Output, ":point_right:executing tests in file %s\n", ftwTest.Meta.Name)
			changed = false
		}

		// can we use goroutines here?
		printUnlessQuietMode(runContext.Output, "\trunning %s: ", testCase.TestTitle)
		// Iterate over stages
		for _, stage := range testCase.Stages {
			ftwCheck := check.NewCheck(config.FTWConfig)
			RunStage(runContext, ftwCheck, testCase, stage.Stage)
		}
	}
}

// RunStage runs an individual test stage.
// runContext contains information for the current test run
// ftwCheck is the current check utility
// testCase is the test case the stage belongs to
// stage is the stage you want to run
func RunStage(runContext *TestRunContext, ftwCheck *check.FTWCheck, testCase test.Test, stage test.Stage) {
	stageID := uuid.NewString()
	// Apply global overrides initially
	testRequest := stage.Input
	err := applyInputOverride(&testRequest)
	if err != nil {
		log.Debug().Msgf("ftw/run: problem overriding input: %s", err.Error())
	}
	expectedOutput := stage.Output

	// Check sanity first
	if checkTestSanity(testRequest) {
		log.Fatal().Msgf("ftw/run: bad test: choose between data, encoded_request, or raw_request")
	}

	// Do not even run test if result is overriden. Just use the override.
	if overriden := overridenTestResult(ftwCheck, testCase.TestTitle); overriden != Failed {
		addResultToStats(overriden, testCase.TestTitle, &runContext.Stats)
		return
	}

	var req *ftwhttp.Request

	// Destination is needed for an request
	dest := &ftwhttp.Destination{
		DestAddr: testRequest.GetDestAddr(),
		Port:     testRequest.GetPort(),
		Protocol: testRequest.GetProtocol(),
	}

	startMarker, err := markAndFlush(runContext.Client, dest, stageID)
	if err != nil && !expectedOutput.ExpectError {
		log.Fatal().Caller().Err(err).Msg("Failed to find start marker")
	}
	ftwCheck.SetStartMarker(startMarker)

	req = getRequestFromTest(testRequest)

	err = runContext.Client.NewConnection(*dest)

	if err != nil && !expectedOutput.ExpectError {
		log.Fatal().Caller().Err(err).Msgf("can't connect to destination %+v - unexpected error found. Is your waf running?", dest)
	}
	runContext.Client.StartTrackingTime()

	response, responseErr := runContext.Client.Do(*req)

	runContext.Client.StopTrackingTime()
	if responseErr != nil && !expectedOutput.ExpectError {
		log.Fatal().Caller().Err(err).Msgf("can't connect to destination %+v - unexpected error found. Is your waf running?", dest)
	}

	endMarker, err := markAndFlush(runContext.Client, dest, stageID)
	if err != nil && !expectedOutput.ExpectError {
		log.Fatal().Caller().Err(err).Msg("Failed to find end marker")

	}
	ftwCheck.SetEndMarker(endMarker)

	// Set expected test output in check
	ftwCheck.SetExpectTestOutput(&expectedOutput)

	// now get the test result based on output
	testResult := checkResult(ftwCheck, response, responseErr)

	duration := runContext.Client.GetRoundTripTime().RoundTripDuration()

	addResultToStats(testResult, testCase.TestTitle, &runContext.Stats)

	runContext.Result = testResult

	// show the result unless quiet was passed in the command line
	displayResult(runContext.Output, testResult, duration)

	runContext.Stats.Run++
	runContext.Stats.RunTime += duration
}

func markAndFlush(client *ftwhttp.Client, dest *ftwhttp.Destination, stageID string) ([]byte, error) {
	var req *ftwhttp.Request
	var logLines = &waflog.FTWLogLines{
		FileName: config.FTWConfig.LogFile,
	}

	rline := &ftwhttp.RequestLine{
		Method:  "GET",
		URI:     "/",
		Version: "HTTP/1.0",
	}

	headers := &ftwhttp.Header{
		"Accept":                             "*/*",
		"User-Agent":                         "go-ftw test agent",
		"Host":                               "localhost",
		config.FTWConfig.LogMarkerHeaderName: stageID,
	}

	req = ftwhttp.NewRequest(rline, *headers, nil, true)

	// 20 is a very conservative number. The web server should flush its
	// buffer a lot earlier but we have absolutely no control over that.
	for range [20]int{} {
		err := client.NewConnection(*dest)
		if err != nil {
			return nil, fmt.Errorf("ftw/run: can't connect to destination %+v - unexpected error found. Is your waf running?", dest)
		}

		_, err = client.Do(*req)
		if err != nil {
			return nil, fmt.Errorf("ftw/run: failed sending request to %+v - unexpected error found. Is your waf running?", dest)
		}

		marker := logLines.CheckLogForMarker(stageID)
		if marker != nil {
			return marker, nil
		}
	}
	return nil, fmt.Errorf("can't find log marker. Am I reading the correct log? Log file: %s", logLines.FileName)
}

func needToSkipTest(include string, exclude string, title string, enabled bool) bool {
	// skip disabled tests
	if !enabled {
		return true
	}

	// never skip enabled explicit inclusions
	if include != "" {
		ok, err := regexp.MatchString(include, title)
		if ok && err == nil {
			// inclusion always wins over exclusion
			return false
		}
	}

	result := false
	// if we need to exclude tests, and the title matches,
	// it needs to be skipped
	if exclude != "" {
		ok, err := regexp.MatchString(exclude, title)
		if ok && err == nil {
			result = true
		}
	}

	// if we need to include tests, but the title does not match
	// it needs to be skipped
	if include != "" {
		ok, err := regexp.MatchString(include, title)
		if !ok && err == nil {
			result = true
		}
	}

	return result
}

func checkTestSanity(testRequest test.Input) bool {
	return (utils.IsNotEmpty(testRequest.Data) && testRequest.EncodedRequest != "") ||
		(utils.IsNotEmpty(testRequest.Data) && testRequest.RAWRequest != "") ||
		(testRequest.EncodedRequest != "" && testRequest.RAWRequest != "")
}

func displayResult(quiet bool, result TestResult, duration time.Duration) {
	switch result {
	case Success:
		printUnlessQuietMode(quiet, ":check_mark:passed in %s\n", duration)
	case Failed:
		printUnlessQuietMode(quiet, ":collision:failed in %s\n", duration)
	case Ignored:
		printUnlessQuietMode(quiet, ":equal:test result ignored in %s\n", duration)
	default:
		// don't print anything if skipped test
	}
}

func overridenTestResult(c *check.FTWCheck, id string) TestResult {
	if c.ForcedIgnore(id) {
		return Ignored
	}

	if c.ForcedFail(id) {
		return ForceFail
	}

	if c.ForcedPass(id) {
		return ForcePass
	}

	return Failed
}

// checkResult has the logic for verifying the result for the test sent
func checkResult(c *check.FTWCheck, response *ftwhttp.Response, responseError error) TestResult {
	// Request might return an error, but it could be expected, we check that first
	if responseError != nil && c.AssertExpectError(responseError) {
		return Success
	}

	// If there was no error, perform the remaining checks
	if responseError != nil {
		return Failed
	}
	if c.CloudMode() {
		// Cloud mode assumes that we cannot read logs. So we rely entirely on status code
		c.SetCloudMode()
	}

	// If we didn't expect an error, check the actual response from the waf
	if response != nil {
		if c.AssertStatus(response.Parsed.StatusCode) {
			return Success
		}
		// Check response
		if c.AssertResponseContains(response.GetBodyAsString()) {
			return Success
		}
	}
	// Lastly, check logs
	if c.AssertLogContains() {
		return Success
	}
	// We assume that the they were already setup, for comparing
	if c.AssertNoLogContains() {
		return Success
	}

	return Failed
}

func getRequestFromTest(testRequest test.Input) *ftwhttp.Request {
	var req *ftwhttp.Request
	// get raw request, if anything
	raw, err := testRequest.GetRawRequest()
	if err != nil {
		log.Error().Msgf("ftw/run: error getting raw data: %s\n", err.Error())
	}

	// If we use raw or encoded request, then we don't use other fields
	if raw != nil {
		req = ftwhttp.NewRawRequest(raw, !testRequest.StopMagic)
	} else {
		rline := &ftwhttp.RequestLine{
			Method:  testRequest.GetMethod(),
			URI:     testRequest.GetURI(),
			Version: testRequest.GetVersion(),
		}

		data := testRequest.ParseData()
		// create a new request
		req = ftwhttp.NewRequest(rline, testRequest.Headers,
			data, !testRequest.StopMagic)

	}
	return req
}

// We want to have output unless we are in quiet mode
func printUnlessQuietMode(quiet bool, format string, a ...interface{}) {
	if !quiet {
		emoji.Printf(format, a...)
	}
}

// applyInputOverride will check if config had global overrides and write that into the test.
func applyInputOverride(testRequest *test.Input) error {
	var retErr error
	overrides := config.FTWConfig.TestOverride.Input
	for s, v := range overrides {
		value := v
		switch s {
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil {
				retErr = errors.New("ftw/run: error getting overriden port")
			}
			*testRequest.Port = port
		case "dest_addr":
			oDestAddr := &value
			testRequest.DestAddr = oDestAddr
		case "protocol":
			oProtocol := &value
			testRequest.Protocol = oProtocol
		default:
			retErr = fmt.Errorf("ftw/run: override of '%s' not implemented yet", s)
		}
	}
	return retErr
}
