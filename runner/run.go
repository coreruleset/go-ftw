package runner

import (
	"os"
	"regexp"
	"time"

	"github.com/fzipi/go-ftw/check"
	"github.com/fzipi/go-ftw/http"
	"github.com/fzipi/go-ftw/test"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog/log"
)

// TestStats accumulates test statistics
type TestStats struct {
	Run         int
	Failed      int
	FailedTests []string
	Skipped     int
	Success     int
	RunTime     time.Duration
}

// Run runs your tests
// testid is the name of the unique test you want to run
// exclude is a regexp that matches the test name: e.g. "920*", excludes all tests starting with "920"
func Run(testid string, exclude string, showTime bool, quiet bool, ftwtests []test.FTWTest) {
	var result bool
	var stats TestStats
	var duration time.Duration

	emoji.Println(":rocket:Running!")

	for _, tests := range ftwtests {
		changed := true
		for _, t := range tests.Tests {
			// if we received a particular testid, skip until we find it
			if needToSkipTest(testid, t.TestTitle, tests.Meta.Enabled) {
				stats.Skipped++
				continue
			} else if exclude != "" {
				if ok, _ := regexp.MatchString(exclude, t.TestTitle); ok {
					log.Debug().Msgf("matched: %s matched %s", exclude, t.TestTitle)
					stats.Skipped++
					continue
				}
			}
			// this is just for printing once the next text
			if changed {
				emoji.Printf(":point_right:executing tests in file %s\n", tests.Meta.Name)
				changed = false
			}

			// can we use goroutines here?
			emoji.Printf("\trunning %s: ", t.TestTitle)
			// Iterate over stages
			for _, stage := range t.Stages {
				testRequest := stage.Stage.Input

				// Check sanity first
				if checkTestSanity(testRequest) {
					log.Fatal().Msgf("bad test: choose between data, encoded_request, or raw_request")
				}

				var client *http.Connection
				var req *http.Request

				dest := &http.Destination{
					DestAddr: testRequest.GetDestAddr(),
					Port:     testRequest.GetPort(),
					Protocol: testRequest.GetProtocol(),
				}

				rline := &http.RequestLine{
					Method:  testRequest.GetMethod(),
					URI:     testRequest.GetURI(),
					Version: testRequest.GetVersion(),
				}

				// get raw data, if anything
				raw, err := testRequest.GetRawData(testRequest.RAWRequest, testRequest.EncodedRequest)
				if err != nil {
					log.Error().Msgf("ftw/run: error getting raw data: %s\n", err.Error())
				}
				// create a new request
				req = req.NewRequest(dest, rline, testRequest.Headers, []byte(testRequest.Data), raw, !testRequest.StopMagic)

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
				response, err := client.Response()
				if err != nil {
					log.Error().Msgf("ftw/run: error receiving response: %s\n", err.Error())
					// Just jump to next test for now
					continue
				}
				log.Trace().Msgf("ftw/run: response took %d", time.Since(startReceivingResponse))

				// Logs need a timespan to check
				since, until := client.GetTrackedTime().Begin, client.GetTrackedTime().End
				// now get the test result based on output
				result = checkResult(stage.Stage.Output, response, since, until, err)

				duration = client.GetTrackedTime().End.Sub(client.GetTrackedTime().Begin)

				addResultToStats(result, t.TestTitle, &stats)

				// show the result unless quiet was passed in the command line
				if !quiet {
					displayResult(result, duration)
				}

				stats.Run++
				stats.RunTime += duration
			}
		}
	}
	if !quiet {
		printSummary(stats)
	}
}

func needToSkipTest(id string, title string, skip bool) bool {
	return id != "" && id != title || !skip
}

func checkTestSanity(testRequest test.Input) bool {
	return (testRequest.Data != "" && testRequest.EncodedRequest != "") ||
		(testRequest.Data != "" && testRequest.RAWRequest != "") ||
		(testRequest.EncodedRequest != "" && testRequest.RAWRequest != "")
}

func displayResult(result bool, duration time.Duration) {
	if result {
		emoji.Printf(":check_mark:passed in %s\n", duration)
	} else {
		emoji.Printf(":collision:failed in %s\n", duration)
	}
}

func addResultToStats(result bool, title string, stats *TestStats) {
	if result {
		stats.Success++
	} else {
		stats.Failed++
		stats.FailedTests = append(stats.FailedTests, title)
	}
}

func printSummary(stats TestStats) {
	emoji.Printf(":plus:run %d total tests in %s\n", stats.Run, stats.RunTime)
	emoji.Printf(":next_track_button:skept %d tests\n", stats.Skipped)
	if stats.Failed == 0 && stats.Run > 0 {
		emoji.Println(":tada:All tests successful!")
		os.Exit(0)
	} else if stats.Failed > 0 {
		emoji.Printf(":minus:%d test(s) failed to run: %+q\n", stats.Failed, stats.FailedTests)
		os.Exit(1)
	}
}

// checkResult has the logic for veryfying the result for the test sent
func checkResult(output test.Output, response *http.Response, since time.Time, until time.Time, err error) bool {
	// Request might return an error, but it could be expected, we check that first
	if check.ExpectedError(err, output.ExpectError) {
		log.Debug().Msgf("ftw/check: found expected error")
		return true
	}
	// If we didn't expect an error, check the actual response from the waf
	if output.Status != nil {
		log.Debug().Msgf("ftw/check: checking if we expected response with status %d", response.Parsed.StatusCode)
		return check.Status(response.Parsed.StatusCode, output.Status)
	}
	// Check response
	if output.ResponseContains != "" {
		log.Debug().Msgf("ftw/check: checking if response contains \"%s\"", output.ResponseContains)
		return check.ResponseContains(response.Parsed.Body, output.ResponseContains)
	}
	// Lastly, check logs
	if output.NoLogContains != "" {
		log.Debug().Msgf("ftw/check: checking if log does not have \"%s\"", output.NoLogContains)
		return check.NoLogContains(output.NoLogContains, since, until)
	}
	if output.LogContains != "" {
		log.Debug().Msgf("ftw/check: checking if log has \"%s\"", output.LogContains)
		return check.LogContains(output.LogContains, since, until)
	}

	return false
}
