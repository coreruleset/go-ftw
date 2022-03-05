package runner

import (
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/fzipi/go-ftw/check"
	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/ftwhttp"
	"github.com/fzipi/go-ftw/test"
	"github.com/fzipi/go-ftw/utils"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog/log"
)

// Run runs your tests
// testid is the name of the unique test you want to run
// exclude is a regexp that matches the test name: e.g. "920*", excludes all tests starting with "920"
// Returns error if some test failed
func Run(include string, exclude string, showTime bool, output bool, ftwtests []test.FTWTest) int {
	var testResult TestResult
	var stats TestStats
	var duration time.Duration

	printUnlessQuietMode(output, ":rocket:Running go-ftw!\n")

	client := ftwhttp.NewClient()

	for _, tests := range ftwtests {
		changed := true
		for _, t := range tests.Tests {
			// if we received a particular testid, skip until we find it
			if needToSkipTest(include, exclude, t.TestTitle, tests.Meta.Enabled) {
				addResultToStats(Skipped, t.TestTitle, &stats)
				continue
			}
			// this is just for printing once the next text
			if changed {
				printUnlessQuietMode(output, ":point_right:executing tests in file %s\n", tests.Meta.Name)
				changed = false
			}

			// can we use goroutines here?
			printUnlessQuietMode(output, "\trunning %s: ", t.TestTitle)
			// Iterate over stages
			for _, stage := range t.Stages {
				// Apply global overrides initially
				testRequest := stage.Stage.Input
				err := applyInputOverride(&testRequest)
				if err != nil {
					log.Debug().Msgf("ftw/run: problem overriding input: %s", err.Error())
				}
				expectedOutput := stage.Stage.Output

				// Check sanity first
				if checkTestSanity(testRequest) {
					log.Fatal().Msgf("ftw/run: bad test: choose between data, encoded_request, or raw_request")
				}

				// Create a new check
				ftwcheck := check.NewCheck(config.FTWConfig)

				// Do not even run test if result is overriden. Just use the override.
				if overriden := overridenTestResult(ftwcheck, t.TestTitle); overriden != Failed {
					addResultToStats(overriden, t.TestTitle, &stats)
					continue
				}

				var req *ftwhttp.Request

				// Destination is needed for an request
				dest := &ftwhttp.Destination{
					DestAddr: testRequest.GetDestAddr(),
					Port:     testRequest.GetPort(),
					Protocol: testRequest.GetProtocol(),
				}

				err = client.NewConnection(*dest)

				if err != nil && !expectedOutput.ExpectError {
					log.Fatal().Msgf("ftw/run: can't connect to destination %+v - unexpected error found. Is your waf running?", dest)
				}

				req = getRequestFromTest(testRequest)

				client.StartTrackingTime()

				response, err := client.Do(*req)

				client.StopTrackingTime()

				ftwcheck.SetRoundTripTime(client.GetRoundTripTime().StartTime(), client.GetRoundTripTime().StopTime())

				// Set expected test output in check
				ftwcheck.SetExpectTestOutput(&expectedOutput)

				// now get the test result based on output
				testResult = checkResult(ftwcheck, response, err)

				duration = client.GetRoundTripTime().RoundTripDuration()

				addResultToStats(testResult, t.TestTitle, &stats)

				// show the result unless quiet was passed in the command line
				displayResult(output, testResult, duration)

				stats.Run++
				stats.RunTime += duration
			}
		}
	}

	return printSummary(output, stats)
}

func needToSkipTest(include string, exclude string, title string, skip bool) bool {
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

	// if the test itself is disabled, needs to be skipped
	if !skip {
		result = true
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
	if c.AssertStatus(response.Parsed.StatusCode) {
		return Success
	}
	// Check response
	if c.AssertResponseContains(response.GetBodyAsString()) {
		return Success
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
			retErr = errors.New("ftw/run: override setting not implemented yet")
		}
	}
	return retErr
}
