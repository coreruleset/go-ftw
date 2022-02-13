package runner

import (
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/fzipi/go-ftw/check"
	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/http"
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

	client := http.NewClient()

	for _, tests := range ftwtests {
		changed := true
		for _, t := range tests.Tests {
			// if we received a particular testid, skip until we find it
			if needToSkipTest(include, exclude, t.TestTitle, tests.Meta.Enabled) {
				log.Trace().Msgf("ftw/run: skipping test %s", t.TestTitle)
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
				testRequest, err := applyInputOverride(stage.Stage.Input)
				if err != nil {
					log.Debug().Msgf("ftw/run: problem overriding input: %s", err.Error())
				}
				expectedOutput := stage.Stage.Output

				// Check sanity first
				if checkTestSanity(testRequest) {
					log.Fatal().Msgf("ftw/run: bad test: choose between data, encoded_request, or raw_request")
				}

				var req *http.Request

				// Destination is needed for an request
				dest := &http.Destination{
					DestAddr: testRequest.GetDestAddr(),
					Port:     testRequest.GetPort(),
					Protocol: testRequest.GetProtocol(),
				}

				err = client.NewConnection(*dest)

				if err != nil && !expectedOutput.ExpectError {
					log.Fatal().Msgf("ftw/run: can't connect to destination %+v - unexpected error found. Is your waf running?", dest)
					addResultToStats(Skipped, t.TestTitle, &stats)
					continue
				}

				req = getRequestFromTest(testRequest)

				client.StartTrackingTime()

				response, err := client.Do(*req)

				client.StopTrackingTime()

				// Create a new check
				ftwcheck := check.NewCheck(config.FTWConfig)
				ftwcheck.SetRoundTripTime(client.GetRoundTripTime().StartTime(), client.GetRoundTripTime().StopTime())

				// Set expected test output in check
				ftwcheck.SetExpectTestOutput(&expectedOutput)

				// now get the test result based on output
				testResult = checkResult(ftwcheck, t.TestTitle, response, err)

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

	log.Trace().Msgf("ftw/run: need to include \"%s\", and to exclude \"%s\". Test title \"%s\" and skip is %t", include, exclude, title, skip)

	// if we need to exclude tests, and the title matches,
	// it needs to be skipped
	if exclude != "" {
		if ok, _ := regexp.MatchString(exclude, title); ok {
			log.Trace().Msgf("ftw/run: %s matches %s, so exclude is true", title, exclude)
			result = true
		}
	}

	// if we need to include tests, but the title does not match
	// it needs to be skipped
	if include != "" {
		log.Trace().Msgf("ftw/run: include is %s", include)
		if ok, _ := regexp.MatchString(include, title); !ok {
			log.Trace().Msgf("ftw/run: include false")
			result = true
		} else {
			result = false
		}
	}

	// if the test itself is disabled, needs to be skipped
	if !skip {
		log.Trace().Msgf("ftw/run: test not enabled")
		result = true
	}

	log.Trace().Msgf("ftw/run: need to exclude? %t", result)

	return result
}

func checkTestSanity(testRequest test.Input) bool {
	log.Trace().Msgf("ftw/run: checking test sanity")

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

// checkResult has the logic for verifying the result for the test sent
func checkResult(c *check.FTWCheck, id string, response *http.Response, responseError error) TestResult {
	var result TestResult

	// Set to failed initially
	result = Failed

	if c.ForcedIgnore(id) {
		result = Ignored
	}

	if c.ForcedFail(id) {
		result = ForceFail
	}

	if c.ForcedPass(id) {
		result = ForcePass
	}

	// Request might return an error, but it could be expected, we check that first
	if responseError != nil && c.AssertExpectError(responseError) {
		log.Trace().Msgf("ftw/check: found expected error")
		result = Success
	}

	// If there was no error, perform the remaining checks
	if responseError == nil {
		// If we didn't expect an error, check the actual response from the waf
		if c.AssertStatus(response.Parsed.StatusCode) {
			log.Debug().Msgf("ftw/check: found expected response with status %d", response.Parsed.StatusCode)
			result = Success
		}
		// Check response
		if c.AssertResponseContains(response.GetBodyAsString()) {
			log.Debug().Msgf("ftw/check: found response content has \"%s\"", response.GetBodyAsString())
			result = Success
		}
		// Lastly, check logs
		if c.AssertLogContains() {
			result = Success
		}
		// We assume that the they were already setup, for comparing
		if c.AssertNoLogContains() {
			result = Success
		}
	}

	return result
}

func getRequestFromTest(testRequest test.Input) *http.Request {
	var req *http.Request
	// get raw request, if anything
	raw, err := testRequest.GetRawRequest()
	if err != nil {
		log.Error().Msgf("ftw/run: error getting raw data: %s\n", err.Error())
	}

	// If we use raw or encoded request, then we don't use other fields
	if raw != nil {
		req = http.NewRawRequest(raw, !testRequest.StopMagic)
	} else {
		rline := &http.RequestLine{
			Method:  testRequest.GetMethod(),
			URI:     testRequest.GetURI(),
			Version: testRequest.GetVersion(),
		}

		data := testRequest.ParseData()
		// create a new request
		req = http.NewRequest(rline, testRequest.Headers,
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
func applyInputOverride(testRequest test.Input) (test.Input, error) {
	var retErr error
	overrides := config.FTWConfig.TestOverride.Input
	for setting, value := range overrides {
		switch setting {
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil {
				retErr = errors.New("ftw/run: error getting overriden port")
			}
			testRequest.Port = &port
		case "dest_addr":
			newValue := value
			testRequest.DestAddr = &newValue
		default:
			retErr = errors.New("ftw/run: override setting not implemented yet")
		}
	}
	return testRequest, retErr
}
