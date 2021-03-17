package runner

import (
	"regexp"
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
// Returns true if no test failed, or false otherwise.
func Run(testid string, exclude string, showTime bool, output bool, ftwtests []test.FTWTest) bool {
	var testResult TestResult
	var stats TestStats
	var duration time.Duration

	printUnlessQuietMode(output, ":rocket:Running!")

	for _, tests := range ftwtests {
		changed := true
		for _, t := range tests.Tests {
			// if we received a particular testid, skip until we find it
			if needToSkipTest(testid, t.TestTitle, tests.Meta.Enabled) {
				addResultToStats(Skipped, t.TestTitle, &stats)
				continue
			} else if exclude != "" {
				if ok, _ := regexp.MatchString(exclude, t.TestTitle); ok {
					log.Debug().Msgf("matched: %s matched %s", exclude, t.TestTitle)
					addResultToStats(Skipped, t.TestTitle, &stats)
					continue
				}
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
				var responseError error
				var responseText string
				var responseCode int

				testRequest := stage.Stage.Input
				expectedOutput := stage.Stage.Output

				// Check sanity first
				if checkTestSanity(testRequest) {
					log.Fatal().Msgf("bad test: choose between data, encoded_request, or raw_request")
				}

				var client *http.Connection
				var req *http.Request

				// Destination is needed for an request
				dest := &http.Destination{
					DestAddr: testRequest.GetDestAddr(),
					Port:     testRequest.GetPort(),
					Protocol: testRequest.GetProtocol(),
				}

				client, err := http.NewConnection(*dest)

				if err != nil && !expectedOutput.ExpectError {
					log.Fatal().Msgf("ftw/run: can't connect to destination %+v - unexpected error found. Is your waf running?", dest)
					addResultToStats(Skipped, t.TestTitle, &stats)
					continue
				}

				req = getRequestFromTest(testRequest)

				log.Debug().Msgf("ftw/run: sending request")

				startSendingRequest := time.Now()

				client, err = client.Request(req)
				if err != nil {
					log.Error().Msgf("ftw/run: error sending request: %s\n", err.Error())
					// Just jump to next test for now
					continue
				}
				log.Trace().Msgf("ftw/run: send took %d", time.Since(startSendingRequest))

				// We wrap go stdlib http for the response
				log.Debug().Msgf("ftw/check: getting response")
				startReceivingResponse := time.Now()

				response, responseError := client.Response()
				if responseError != nil {
					log.Debug().Msgf("ftw/run: error receiving response: %s\n", responseError.Error())
					// This error might be expected. Let's continue
					responseText = ""
					responseCode = 0
				} else {
					responseText = response.GetBodyAsString()
					responseCode = response.Parsed.StatusCode
				}
				log.Trace().Msgf("ftw/run: response took %d", time.Since(startReceivingResponse))

				// Create a new check
				ftwcheck := check.NewCheck(config.FTWConfig)

				// Logs need a timespan to check
				ftwcheck.SetRoundTripTime(client.GetRoundTripTime().StartTime(), client.GetRoundTripTime().StopTime())
				// Set expected test output in check
				ftwcheck.SetExpectTestOutput(&expectedOutput)

				// now get the test result based on output
				testResult = checkResult(ftwcheck, responseCode, responseError, responseText)

				duration = client.GetRoundTripTime().RoundTripDuration()

				addResultToStats(testResult, t.TestTitle, &stats)

				// show the result unless quiet was passed in the command line
				displayResult(output, testResult, duration)

				stats.Run++
				stats.RunTime += duration
			}
		}
	}

	printSummary(output, stats)

	return len(stats.Failed) == 0
}

func needToSkipTest(id string, title string, skip bool) bool {
	return id != "" && id != title || !skip
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
	default:
		// don't print anything if skipped test
	}
}

// checkResult has the logic for verifying the result for the test sent
func checkResult(c *check.FTWCheck, responseCode int, responseError error, responseText string) TestResult {
	var result TestResult

	// Set to failed initially
	result = Failed
	// Request might return an error, but it could be expected, we check that first
	if c.AssertExpectError(responseError) {
		log.Debug().Msgf("ftw/check: found expected error")
		result = Success
	}
	// If we didn't expect an error, check the actual response from the waf
	if c.AssertStatus(responseCode) {
		log.Debug().Msgf("ftw/check: checking if we expected response with status %d", responseCode)
		result = Success
	}
	// Check response
	if c.AssertResponseContains(responseText) {
		log.Debug().Msgf("ftw/check: checking if response contains \"%s\"", responseText)
		result = Success
	}
	// Lastly, check logs
	if c.AssertLogContains() {
		log.Debug().Msgf("ftw/check: checking if log contains")
		result = Success
	}
	// We assume that the they were already setup, for comparing
	if c.AssertNoLogContains() {
		log.Debug().Msgf("ftw/check: checking if log does not contains")
		result = Success
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
