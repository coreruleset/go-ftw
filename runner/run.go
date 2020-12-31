package runner

import (
	"ftw/check"
	"ftw/ftwtest"
	"ftw/http"
	"os"
	"regexp"
	"time"

	"github.com/creasty/defaults"
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
func Run(testid string, exclude string, showTime bool, quiet bool, ftwtests []ftwtest.FTWTest) {
	var result bool
	var stats TestStats
	var duration time.Duration

	emoji.Println(":rocket:Running!")

	result = false
	for _, tests := range ftwtests {
		changed := true
		for _, t := range tests.Tests {
			// if we received a particular testid, skip until we find it
			if testid != "" && testid != t.TestTitle || tests.Meta.Enabled == false {
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
				if (testRequest.Data != "" && testRequest.EncodedRequest != "") ||
					(testRequest.Data != "" && testRequest.RAWRequest != "") ||
					(testRequest.EncodedRequest != "" && testRequest.RAWRequest != "") {
					log.Fatal().Msgf("bad test: choose between data, encoded_request, or raw_request")
				}

				request := &http.FTWHTTPRequest{
					NoDefaults: testRequest.StopMagic,
					DestAddr:   testRequest.DestAddr,
					Port:       testRequest.Port,
					Method:     testRequest.Method,
					Protocol:   testRequest.Protocol,
					Version:    testRequest.Version,
					URI:        testRequest.URI,
					Headers:    testRequest.Headers,
					Data:       []byte(testRequest.Data),
					Raw:        []byte(testRequest.RAWRequest),
					Encoded:    testRequest.EncodedRequest,
				}

				if err := defaults.Set(request); err != nil {
					log.Fatal().Msgf(err.Error())
				}
				log.Debug().Msgf("ftw/run: sending request")
				a := time.Now()
				conn, err := http.Request(request)
				log.Debug().Msgf("ftw/run: send took %d", time.Since(a))
				// We wrap go stdlib http for the response
				log.Debug().Msgf("ftw/check: getting response")
				b := time.Now()
				response, err := conn.Response()
				log.Debug().Msgf("ftw/run: respnse took %d", time.Since(b))

				// Request might return an error, but it could be expected, we check that first
				if (err != nil) && (stage.Stage.Output.ExpectError) {
					log.Debug().Msgf("ftw/check: found expected error")
					result = true
				} else {
					// If we didn't expect an error, check the actual response from the waf
					if stage.Stage.Output.Status != nil {
						log.Debug().Msgf("ftw/check: checking if we expected response with status %d", response.Parsed.StatusCode)
						result = check.Status(response.Parsed.StatusCode, stage.Stage.Output.Status)
					}

					if stage.Stage.Output.ResponseContains != "" {
						log.Debug().Msgf("ftw/check: checking if response contains \"%s\"", stage.Stage.Output.ResponseContains)
						result = check.ResponseContains(response.Parsed.Body, stage.Stage.Output.ResponseContains)
					}

					// Lastly, test logs to see what they contain
					// Logs need a timespan to check
					since, until := conn.GetTrackedTime().Begin, conn.GetTrackedTime().End

					if stage.Stage.Output.NoLogContains != "" {
						log.Debug().Msgf("ftw/check: checking if log does not have \"%s\"", stage.Stage.Output.NoLogContains)
						result = check.NoLogContains(stage.Stage.Output.NoLogContains, since, until)
					}

					if stage.Stage.Output.LogContains != "" {
						log.Debug().Msgf("ftw/check: checking if log has \"%s\"", stage.Stage.Output.LogContains)
						result = check.LogContains(stage.Stage.Output.LogContains, since, until)
					}
				}
				if showTime {
					duration = conn.GetTrackedTime().End.Sub(conn.GetTrackedTime().Begin)
				}
				if result {
					emoji.Printf(":check_mark:passed %s\n", duration)
					stats.Success++
				} else {
					emoji.Printf(":collision:failed\n")
					stats.Failed++
					stats.FailedTests = append(stats.FailedTests, t.TestTitle)
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
