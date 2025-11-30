// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"wait4x.dev/v3/checker"
	"wait4x.dev/v3/checker/http"
	"wait4x.dev/v3/waiter"

	"github.com/coreruleset/go-ftw/cmd/internal"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
)

const (
	connectTimeoutFlag           = "connect-timeout"
	dirFlag                      = "dir"
	globFlag                     = "glob"
	excludeFlag                  = "exclude"
	failFastFlag                 = "fail-fast"
	fileFlag                     = "file"
	includeFlag                  = "include"
	includeTagsFlag              = "include-tags"
	logFileFlag                  = "log-file"
	maxMarkerRetriesFlag         = "max-marker-retries"
	maxMarkerLogLinesFlag        = "max-marker-log-lines"
	outputFlag                   = "output"
	readTimeoutFlag              = "read-timeout"
	rateLimitFlag                = "rate-limit"
	showFailuresOnlyFlag         = "show-failures-only"
	skipTlsVerificationFlag      = "skip-tls-verification"
	timeFlag                     = "time"
	waitDelayFlag                = "wait-delay"
	waitForConnectionTimeoutFlag = "wait-for-connection-timeout"
	waitForExpectBodyJsonFlag    = "wait-for-expect-body-json"
	waitForExpectBodyRegexFlag   = "wait-for-expect-body-regex"
	waitForExpectBodyXpathFlag   = "wait-for-expect-body-xpath"
	waitForExpectHeaderFlag      = "wait-for-expect-header"
	waitForExpectStatusCodeFlag  = "wait-for-expect-status-code"
	waitForHostFlag              = "wait-for-host"
	waitForNoRedirectFlag        = "wait-for-no-redirect"
	waitForTimeoutFlag           = "wait-for-timeout"
	reportTriggeredRulesFlag     = "report-triggered-rules"
)

// NewRunCmd represents the run command
func New(cmdContext *internal.CommandContext) *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run Tests",
		Long:  `Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.`,
		RunE:  runE(cmdContext),
	}

	runCmd.Flags().StringP(excludeFlag, "e", "", "exclude tests matching this Go regular expression (e.g. to exclude all tests beginning with \"91\", use \"^91.*\"). \nIf you want more permanent exclusion, check the 'exclude' option in the config file.")
	runCmd.Flags().StringP(includeFlag, "i", "", "include only tests matching this Go regular expression (e.g. to include only tests beginning with \"91\", use \"^91.*\"). \nIf you want more permanent inclusion, check the 'include' option in the config file.")
	runCmd.Flags().StringP(includeTagsFlag, "T", "", "include tests tagged with labels matching this Go regular expression (e.g. to include all tests being tagged with \"cookie\", use \"^cookie$\").")
	runCmd.Flags().StringP(dirFlag, "d", ".", "recursively find yaml tests in this directory")
	runCmd.Flags().StringP(globFlag, "g", "*.y*ml", "override the filename glob pattern for matching test files")
	runCmd.Flags().StringP(outputFlag, "o", "normal", "output type for ftw tests. \"normal\" is the default.")
	runCmd.Flags().StringP(fileFlag, "f", "", "output file path for ftw tests. Prints to standard output by default.")
	runCmd.Flags().StringP(logFileFlag, "l", "", "path to log file to watch for WAF events")
	runCmd.Flags().BoolP(timeFlag, "t", false, "show time spent per test")
	runCmd.Flags().BoolP(showFailuresOnlyFlag, "", false, "shows only the results of failed tests")
	runCmd.Flags().Duration(connectTimeoutFlag, 3*time.Second, "timeout for connecting to endpoints during test execution")
	runCmd.Flags().Duration(readTimeoutFlag, 10*time.Second, "timeout for receiving responses during test execution")
	runCmd.Flags().Uint(maxMarkerRetriesFlag, 20, "maximum number of times the search for log markers will be repeated.\nEach time an additional request is sent to the web server, eventually forcing the log to be flushed")
	runCmd.Flags().Uint(maxMarkerLogLinesFlag, 500, "maximum number of lines to search for a marker before aborting")
	runCmd.Flags().Bool(skipTlsVerificationFlag, http.DefaultInsecureSkipTLSVerify, "Skips TLS certificate checks. Useful for testing domains with self-signed TLS ceritificates.")
	runCmd.Flags().String(waitForHostFlag, "", "Wait for host to be available before running tests.")
	runCmd.Flags().Duration(waitDelayFlag, 1*time.Second, "Time to wait between retries for all wait operations.")
	runCmd.Flags().Duration(waitForTimeoutFlag, 10*time.Second, "Sets the timeout for all wait operations, 0 is unlimited.")
	runCmd.Flags().Int(waitForExpectStatusCodeFlag, 0, "Expect response code e.g. 200, 204, ... .")
	runCmd.Flags().String(waitForExpectBodyRegexFlag, "", "Expect response body pattern.")
	runCmd.Flags().String(waitForExpectBodyJsonFlag, "", "Expect response body JSON pattern.")
	runCmd.Flags().String(waitForExpectBodyXpathFlag, "", "Expect response body XPath pattern.")
	runCmd.Flags().String(waitForExpectHeaderFlag, "", "Expect response header pattern.")
	runCmd.Flags().Duration(waitForConnectionTimeoutFlag, http.DefaultConnectionTimeout, "Http connection timeout, The timeout includes connection time, any redirects, and reading the response body.")
	runCmd.Flags().Bool(waitForNoRedirectFlag, http.DefaultNoRedirect, "Do not follow HTTP 3xx redirects.")
	runCmd.Flags().DurationP(rateLimitFlag, "r", 0, "Limit the request rate to the server to 1 request per specified duration. 0 is the default, and disables rate limiting.")
	runCmd.Flags().Bool(failFastFlag, false, "Fail on first failed test")
	runCmd.Flags().Bool(reportTriggeredRulesFlag, false, "Report triggered rules for each test")

	return runCmd
}

func runE(cmdContext *internal.CommandContext) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		cmd.SilenceUsage = true
		runnerConfig, err := buildRunnerConfig(cmd, cmdContext)
		if err != nil {
			return err
		}
		out, err := buildOutput(cmd)
		if err != nil {
			return err
		}

		tests, err := loadTests(cmd)
		if err != nil {
			return err
		}
		_ = out.Println("%s", out.Message("** Starting tests!"))

		currentRun, err := runner.Run(runnerConfig, tests, out)

		if err != nil {
			return err
		}

		if currentRun.Stats.TotalFailed() > 0 {
			return fmt.Errorf("failed %d tests", currentRun.Stats.TotalFailed())
		}

		return nil
	}
}

//gocyclo:ignore
func buildRunnerConfig(cmd *cobra.Command, cmdContext *internal.CommandContext) (*config.RunnerConfig, error) {
	exclude, err := cmd.Flags().GetString(excludeFlag)
	if err != nil {
		return nil, err
	}
	include, err := cmd.Flags().GetString(includeFlag)
	if err != nil {
		return nil, err
	}
	includeTags, err := cmd.Flags().GetString(includeTagsFlag)
	if err != nil {
		return nil, err
	}
	logFilePath, err := cmd.Flags().GetString(logFileFlag)
	if err != nil {
		return nil, err
	}
	skipTlsVerification, err := cmd.Flags().GetBool(skipTlsVerificationFlag)
	if err != nil {
		return nil, err
	}
	// wait4x flags
	waitForHost, err := cmd.Flags().GetString(waitForHostFlag)
	if err != nil {
		return nil, err
	}
	timeout, err := cmd.Flags().GetDuration(waitForTimeoutFlag)
	if err != nil {
		return nil, err
	}
	interval, err := cmd.Flags().GetDuration(waitDelayFlag)
	if err != nil {
		return nil, err
	}
	expectStatusCode, err := cmd.Flags().GetInt(waitForExpectStatusCodeFlag)
	if err != nil {
		return nil, err
	}
	expectBodyRegex, err := cmd.Flags().GetString(waitForExpectBodyRegexFlag)
	if err != nil {
		return nil, err
	}
	expectBodyJSON, err := cmd.Flags().GetString(waitForExpectBodyJsonFlag)
	if err != nil {
		return nil, err
	}
	expectBodyXPath, err := cmd.Flags().GetString(waitForExpectBodyXpathFlag)
	if err != nil {
		return nil, err
	}
	expectHeader, err := cmd.Flags().GetString(waitForExpectHeaderFlag)
	if err != nil {
		return nil, err
	}
	connectionTimeout, err := cmd.Flags().GetDuration(waitForConnectionTimeoutFlag)
	if err != nil {
		return nil, err
	}
	noRedirect, err := cmd.Flags().GetBool(waitForNoRedirectFlag)
	if err != nil {
		return nil, err
	}

	if exclude != "" && include != "" {
		cmd.SilenceUsage = false
		return nil, fmt.Errorf("inlusion *and* exclusion specified. You need to choose either --%s (%s) or --%s (%s)", includeFlag, include, excludeFlag, exclude)
	}

	runnerConfig := config.NewRunnerConfiguration(cmdContext.Configuration)
	runnerConfig.ShowTime, err = cmd.Flags().GetBool(timeFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.ShowOnlyFailed, err = cmd.Flags().GetBool(showFailuresOnlyFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.ConnectTimeout, err = cmd.Flags().GetDuration(connectTimeoutFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.ReadTimeout, err = cmd.Flags().GetDuration(readTimeoutFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.MaxMarkerRetries, err = cmd.Flags().GetUint(maxMarkerRetriesFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.MaxMarkerLogLines, err = cmd.Flags().GetUint(maxMarkerLogLinesFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.RateLimit, err = cmd.Flags().GetDuration(rateLimitFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.FailFast, err = cmd.Flags().GetBool(failFastFlag)
	if err != nil {
		return nil, err
	}
	runnerConfig.SkipTlsVerification = skipTlsVerification

	if cmdContext.CloudMode {
		runnerConfig.RunMode = config.CloudRunMode
	}
	if logFilePath != "" {
		runnerConfig.LogFilePath = logFilePath
	}

	if include != "" {
		if runnerConfig.Include, err = regexp.Compile(include); err != nil {
			return nil, fmt.Errorf("invalid --%s regular expression: %w", includeFlag, err)
		}
	}
	if exclude != "" {
		if runnerConfig.Exclude, err = regexp.Compile(exclude); err != nil {
			return nil, fmt.Errorf("invalid --%s regular expression: %w", excludeFlag, err)
		}
	}
	if includeTags != "" {
		if runnerConfig.IncludeTags, err = regexp.Compile(includeTags); err != nil {
			return nil, fmt.Errorf("invalid --%s regular expression: %w", includeTagsFlag, err)
		}
	}
	// Add wait4x checkers
	if waitForHost != "" {
		_, err := url.Parse(waitForHost)
		if err != nil {
			return nil, err
		}

		hc := http.New(waitForHost,
			http.WithExpectStatusCode(expectStatusCode),
			http.WithExpectBodyRegex(expectBodyRegex),
			http.WithExpectBodyJSON(expectBodyJSON),
			http.WithExpectBodyXPath(expectBodyXPath),
			http.WithExpectHeader(expectHeader),
			http.WithTimeout(connectionTimeout),
			http.WithInsecureSkipTLSVerify(skipTlsVerification),
			http.WithNoRedirect(noRedirect),
		)
		checkers := []checker.Checker{hc}

		Logger := zerologr.New(&log.Logger)
		waiterErr := waiter.WaitParallelContext(
			cmd.Context(),
			checkers,
			waiter.WithTimeout(timeout),
			waiter.WithInterval(interval),
			waiter.WithLogger(Logger),
		)
		if waiterErr != nil {
			return nil, waiterErr
		}
	}

	err = runnerConfig.LoadPlatformOverrides(cmdContext.OverridesFileName)
	if err != nil {
		log.Fatal().Msg("failed to load platform overrides")
	}
	return runnerConfig, nil
}

func buildOutput(cmd *cobra.Command) (*output.Output, error) {
	outputFilename, _ := cmd.Flags().GetString(fileFlag)
	wantedOutput, _ := cmd.Flags().GetString(outputFlag)

	// use outputFile to write to file
	var outputFile *os.File
	var err error
	if outputFilename == "" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.Create(outputFilename)
		if err != nil {
			return nil, err
		}
	}
	return output.NewOutput(wantedOutput, outputFile), nil
}

func loadTests(cmd *cobra.Command) ([]*test.FTWTest, error) {
	dir, _ := cmd.Flags().GetString(dirFlag)
	filenameGlob, _ := cmd.Flags().GetString(globFlag)
	files := fmt.Sprintf("%s/**/%s", dir, filenameGlob)
	tests, err := test.GetTestsFromFiles(files)
	if err != nil {
		return nil, err
	}
	return tests, nil
}
