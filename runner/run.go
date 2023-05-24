package runner

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/coreruleset/go-ftw/config"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/check"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/test"
	"github.com/coreruleset/go-ftw/utils"
	"github.com/coreruleset/go-ftw/waflog"
)

var errBadTestRequest = errors.New("ftw/run: bad test: choose between data, encoded_request, or raw_request")

// Run runs your tests with the specified Config.
func Run(cfg *config.FTWConfiguration, tests []test.FTWTest, c RunnerConfig, out *output.Output) (*TestRunContext, error) {
	out.Println("%s", out.Message("** Running go-ftw!"))

	logLines, err := waflog.NewFTWLogLines(cfg)
	if err != nil {
		return &TestRunContext{}, err
	}

	conf := ftwhttp.NewClientConfig()
	if c.ConnectTimeout != 0 {
		conf.ConnectTimeout = c.ConnectTimeout
	}
	if c.ReadTimeout != 0 {
		conf.ReadTimeout = c.ReadTimeout
	}
	client, err := ftwhttp.NewClient(conf)
	if err != nil {
		return &TestRunContext{}, err
	}

	runContext := &TestRunContext{
		Config:         cfg,
		Include:        c.Include,
		Exclude:        c.Exclude,
		ShowTime:       c.ShowTime,
		Output:         out,
		ShowOnlyFailed: c.ShowOnlyFailed,
		Stats:          NewRunStats(),
		Client:         client,
		LogLines:       logLines,
	}

	for _, tc := range tests {
		if err := RunTest(runContext, tc); err != nil {
			return &TestRunContext{}, err
		}
	}

	runContext.Stats.printSummary(out)

	defer cleanLogs(logLines)

	return runContext, nil
}

// RunTest runs an individual test.
// runContext contains information for the current test run
// ftwTest is the test you want to run
func RunTest(runContext *TestRunContext, ftwTest test.FTWTest) error {
	changed := true

	for _, testCase := range ftwTest.Tests {
		// if we received a particular testid, skip until we find it
		if needToSkipTest(runContext.Include, runContext.Exclude, testCase.TestTitle, ftwTest.Meta.Enabled) {
			runContext.Stats.addResultToStats(Skipped, testCase.TestTitle, 0)
			if !ftwTest.Meta.Enabled && !runContext.ShowOnlyFailed {
				runContext.Output.Println("\tskipping %s - (enabled: false) in file.", testCase.TestTitle)
			}
			continue
		}
		// this is just for printing once the next test
		if changed && !runContext.ShowOnlyFailed {
			runContext.Output.Println(runContext.Output.Message("=> executing tests in file %s"), ftwTest.Meta.Name)
			changed = false
		}

		if !runContext.ShowOnlyFailed {
			runContext.Output.Printf("\trunning %s: ", testCase.TestTitle)
		}
		// Iterate over stages
		for _, stage := range testCase.Stages {
			ftwCheck := check.NewCheck(runContext.Config)
			if err := RunStage(runContext, ftwCheck, testCase, stage.Stage); err != nil {
				return err
			}
		}
	}

	return nil
}

// RunStage runs an individual test stage.
// runContext contains information for the current test run
// ftwCheck is the current check utility
// testCase is the test case the stage belongs to
// stage is the stage you want to run
func RunStage(runContext *TestRunContext, ftwCheck *check.FTWCheck, testCase test.Test, stage test.Stage) error {
	stageStartTime := time.Now()
	stageID := uuid.NewString()
	// Apply global overrides initially
	testRequest := stage.Input
	err := applyInputOverride(runContext.Config.TestOverride, &testRequest)
	if err != nil {
		log.Debug().Msgf("ftw/run: problem overriding input: %s", err.Error())
	}
	expectedOutput := stage.Output

	// Check sanity first
	if checkTestSanity(testRequest) {
		return errBadTestRequest
	}

	// Do not even run test if result is overridden. Just use the override and display the overridden result.
	if overridden := overriddenTestResult(ftwCheck, testCase.TestTitle); overridden != Failed {
		runContext.Stats.addResultToStats(overridden, testCase.TestTitle, 0)
		displayResult(runContext, overridden, time.Duration(0), time.Duration(0))
		return nil
	}

	var req *ftwhttp.Request

	// Destination is needed for a request
	dest := &ftwhttp.Destination{
		DestAddr: testRequest.GetDestAddr(),
		Port:     testRequest.GetPort(),
		Protocol: testRequest.GetProtocol(),
	}

	if notRunningInCloudMode(ftwCheck) {
		startMarker, err := markAndFlush(runContext, dest, stageID)
		if err != nil && !expectedOutput.ExpectError {
			return fmt.Errorf("failed to find start marker: %w", err)
		}
		ftwCheck.SetStartMarker(startMarker)
	}

	req = getRequestFromTest(testRequest)

	err = runContext.Client.NewConnection(*dest)

	if err != nil && !expectedOutput.ExpectError {
		return fmt.Errorf("can't connect to destination %+v: %w", dest, err)
	}
	runContext.Client.StartTrackingTime()

	response, responseErr := runContext.Client.Do(*req)

	runContext.Client.StopTrackingTime()
	if responseErr != nil && !expectedOutput.ExpectError {
		return fmt.Errorf("failed sending request to destination %+v: %w", dest, responseErr)
	}

	if notRunningInCloudMode(ftwCheck) {
		endMarker, err := markAndFlush(runContext, dest, stageID)
		if err != nil && !expectedOutput.ExpectError {
			return fmt.Errorf("failed to find end marker: %w", err)

		}
		ftwCheck.SetEndMarker(endMarker)
	}

	// Set expected test output in check
	ftwCheck.SetExpectTestOutput(&expectedOutput)

	// now get the test result based on output
	testResult := checkResult(ftwCheck, response, responseErr)

	roundTripTime := runContext.Client.GetRoundTripTime().RoundTripDuration()
	stageTime := time.Since(stageStartTime)

	runContext.Stats.addResultToStats(testResult, testCase.TestTitle, stageTime)

	runContext.Result = testResult

	// show the result unless quiet was passed in the command line
	displayResult(runContext, testResult, roundTripTime, stageTime)

	runContext.Stats.Run++
	runContext.Stats.TotalTime += stageTime

	return nil
}

func markAndFlush(runContext *TestRunContext, dest *ftwhttp.Destination, stageID string) ([]byte, error) {
	rline := &ftwhttp.RequestLine{
		Method: "GET",
		// Use the `/status` endpoint of `httpbin` (http://httpbin.org), if possible,
		// to minimize the amount of data transferred and in the log.
		// `httpbin` is used by the CRS test setup.
		URI:     "/status/200",
		Version: "HTTP/1.1",
	}

	headers := &ftwhttp.Header{
		"Accept":                              "*/*",
		"User-Agent":                          "go-ftw test agent",
		"Host":                                "localhost",
		runContext.Config.LogMarkerHeaderName: stageID,
	}

	req := ftwhttp.NewRequest(rline, *headers, nil, true)

	for i := runContext.Config.MaxMarkerRetries; i > 0; i-- {
		err := runContext.Client.NewOrReusedConnection(*dest)
		if err != nil {
			return nil, fmt.Errorf("ftw/run: can't connect to destination %+v: %w", dest, err)
		}

		_, err = runContext.Client.Do(*req)
		if err != nil {
			return nil, fmt.Errorf("ftw/run: failed sending request to %+v: %w", dest, err)
		}

		marker := runContext.LogLines.CheckLogForMarker(stageID, runContext.Config.MaxMarkerLogLines)
		if marker != nil {
			return marker, nil
		}
	}
	return nil, fmt.Errorf("can't find log marker. Am I reading the correct log? Log file: %s", runContext.Config.LogFile)
}

func needToSkipTest(include *regexp.Regexp, exclude *regexp.Regexp, title string, enabled bool) bool {
	// skip disabled tests
	if !enabled {
		return true
	}

	// never skip enabled explicit inclusions
	if include != nil {
		if include.MatchString(title) {
			// inclusion always wins over exclusion
			return false
		}
	}

	result := false
	// if we need to exclude tests, and the title matches,
	// it needs to be skipped
	if exclude != nil {
		if exclude.MatchString(title) {
			result = true
		}
	}

	// if we need to include tests, but the title does not match
	// it needs to be skipped
	if include != nil {
		if !include.MatchString(title) {
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

func displayResult(rc *TestRunContext, result TestResult, roundTripTime time.Duration, stageTime time.Duration) {
	switch result {
	case Success:
		if !rc.ShowOnlyFailed {
			rc.Output.Println(rc.Output.Message("+ passed in %s (RTT %s)"), stageTime, roundTripTime)
		}
	case Failed:
		rc.Output.Println(rc.Output.Message("- failed in %s (RTT %s)"), stageTime, roundTripTime)
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

func overriddenTestResult(c *check.FTWCheck, id string) TestResult {
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
		// Cloud mode assumes that we cannot read logs. So we rely entirely on status code and response
		c.SetCloudMode()
	}

	// If we didn't expect an error, check the actual response from the waf
	if response != nil {
		if c.StatusCodeRequired() && !c.AssertStatus(response.Parsed.StatusCode) {
			return Failed
		}
		// Check if text is contained in the full raw response
		if c.ResponseContainsRequired() && !c.AssertResponseContains(response.GetFullResponse()) {
			return Failed
		}
	}
	// Lastly, check logs
	if c.LogContainsRequired() && !c.AssertLogContains() {
		return Failed
	}
	// We assume that they were already setup, for comparing
	if c.NoLogContainsRequired() && !c.AssertNoLogContains() {
		return Failed
	}

	return Success
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

// applyInputOverride will check if config had global overrides and write that into the test.
func applyInputOverride(o config.FTWTestOverride, testRequest *test.Input) error {
	overrides := o.Overrides
	if overrides.Port != nil {
		testRequest.Port = overrides.Port
	}

	if overrides.Headers != nil {
		if testRequest.Headers == nil {
			testRequest.Headers = ftwhttp.Header{}
		}
		for k, v := range overrides.Headers {
			testRequest.Headers.Set(k, v)
		}
	}

	if overrides.DestAddr != nil {
		testRequest.DestAddr = overrides.DestAddr
		if testRequest.Headers == nil {
			testRequest.Headers = ftwhttp.Header{}
		}
		if overrides.OverrideEmptyHostHeader && testRequest.Headers.Get("Host") == "" {
			testRequest.Headers.Set("Host", *overrides.DestAddr)
		}
	}
	if overrides.Protocol != nil {
		testRequest.Protocol = overrides.Protocol
	}

	return nil
}

func notRunningInCloudMode(c *check.FTWCheck) bool {
	return !c.CloudMode()
}

func cleanLogs(logLines *waflog.FTWLogLines) {
	if err := logLines.Cleanup(); err != nil {
		log.Error().Err(err).Msg("Failed to cleanup log file")
	}
}
