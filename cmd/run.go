package cmd

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog/log"
	"wait4x.dev/v2/waiter"

	"wait4x.dev/v2/checker"
	"wait4x.dev/v2/checker/http"

	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
	"github.com/spf13/cobra"
)

// NewRunCmd represents the run command
func NewRunCommand() *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run Tests",
		Long:  `Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.`,
		RunE:  runE,
	}

	runCmd.Flags().StringP("exclude", "e", "", "exclude tests matching this Go regexp (e.g. to exclude all tests beginning with \"91\", use \"91.*\"). \nIf you want more permanent exclusion, check the 'testoverride' option in the config file.")
	runCmd.Flags().StringP("include", "i", "", "include only tests matching this Go regexp (e.g. to include only tests beginning with \"91\", use \"91.*\").")
	_ = runCmd.Flags().MarkDeprecated("id", "This flag will be removed in v2.0. Use --include matching your test only.")
	runCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	runCmd.Flags().StringP("output", "o", "normal", "output type for ftw tests. \"normal\" is the default.")
	runCmd.Flags().StringP("file", "f", "", "output file path for ftw tests. Prints to standard output by default.")
	runCmd.Flags().BoolP("time", "t", false, "show time spent per test")
	runCmd.Flags().BoolP("show-failures-only", "", false, "shows only the results of failed tests")
	runCmd.Flags().Duration("connect-timeout", 3*time.Second, "timeout for connecting to endpoints during test execution")
	runCmd.Flags().Duration("read-timeout", 1*time.Second, "timeout for receiving responses during test execution")
	runCmd.Flags().Int("max-marker-retries", 20, "maximum number of times the search for log markers will be repeated.\nEach time an additional request is sent to the web server, eventually forcing the log to be flushed")
	runCmd.Flags().Int("max-marker-log-lines", 500, "maximum number of lines to search for a marker before aborting")
	runCmd.Flags().String("wait-for-host", "", "Wait for host to be available before running tests.")
	runCmd.Flags().Duration("wait-delay", 1*time.Second, "Time to wait between retries for all wait operations.")
	runCmd.Flags().Duration("wait-for-timeout", 10*time.Second, "Sets the timeout for all wait operations, 0 is unlimited.")
	runCmd.Flags().Int("wait-for-expect-status-code", 0, "Expect response code e.g. 200, 204, ... .")
	runCmd.Flags().String("wait-for-expect-body-regex", "", "Expect response body pattern.")
	runCmd.Flags().String("wait-for-expect-body-json", "", "Expect response body JSON pattern.")
	runCmd.Flags().String("wait-for-expect-body-xpath", "", "Expect response body XPath pattern.")
	runCmd.Flags().String("wait-for-expect-header", "", "Expect response header pattern.")
	runCmd.Flags().Duration("wait-for-connection-timeout", http.DefaultConnectionTimeout, "Http connection timeout, The timeout includes connection time, any redirects, and reading the response body.")
	runCmd.Flags().Bool("wait-for-insecure-skip-tls-verify", http.DefaultInsecureSkipTLSVerify, "Skips tls certificate checks for the HTTPS request.")
	runCmd.Flags().Bool("wait-for-no-redirect", http.DefaultNoRedirect, "Do not follow HTTP 3xx redirects.")

	return runCmd
}

func runE(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	exclude, _ := cmd.Flags().GetString("exclude")
	include, _ := cmd.Flags().GetString("include")
	dir, _ := cmd.Flags().GetString("dir")
	outputFilename, _ := cmd.Flags().GetString("file")
	showTime, _ := cmd.Flags().GetBool("time")
	showOnlyFailed, _ := cmd.Flags().GetBool("show-failures-only")
	wantedOutput, _ := cmd.Flags().GetString("output")
	connectTimeout, _ := cmd.Flags().GetDuration("connect-timeout")
	readTimeout, _ := cmd.Flags().GetDuration("read-timeout")
	maxMarkerRetries, _ := cmd.Flags().GetInt("max-marker-retries")
	maxMarkerLogLines, _ := cmd.Flags().GetInt("max-marker-log-lines")
	// wait4x flags
	waitForHost, _ := cmd.Flags().GetString("wait-for-host")
	timeout, _ := cmd.Flags().GetDuration("wait-for-timeout")
	interval, _ := cmd.Flags().GetDuration("wait-for-interval")
	expectStatusCode, _ := cmd.Flags().GetInt("wait-for-expect-status-code")
	expectBodyRegex, _ := cmd.Flags().GetString("wait-for-expect-body-regex")
	expectBodyJSON, _ := cmd.Flags().GetString("wait-for-expect-body-json")
	expectBodyXPath, _ := cmd.Flags().GetString("wait-for-expect-body-xpath")
	expectHeader, _ := cmd.Flags().GetString("wait-for-expect-header")
	connectionTimeout, _ := cmd.Flags().GetDuration("wait-for-connection-timeout")
	insecureSkipTLSVerify, _ := cmd.Flags().GetBool("wait-for-insecure-skip-tls-verify")
	noRedirect, _ := cmd.Flags().GetBool("wait-for-no-redirect")

	if exclude != "" && include != "" {
		cmd.SilenceUsage = false
		return fmt.Errorf("you need to choose one: use --include (%s) or --exclude (%s)", include, exclude)
	}
	if maxMarkerRetries != 0 {
		cfg.WithMaxMarkerRetries(maxMarkerRetries)
	}
	if maxMarkerLogLines != 0 {
		cfg.WithMaxMarkerLogLines(maxMarkerLogLines)
	}
	files := fmt.Sprintf("%s/**/*.yaml", dir)
	tests, err := test.GetTestsFromFiles(files)

	if err != nil {
		return err
	}

	var includeRE *regexp.Regexp
	if include != "" {
		includeRE = regexp.MustCompile(include)
	}
	var excludeRE *regexp.Regexp
	if exclude != "" {
		excludeRE = regexp.MustCompile(exclude)
	}

	// Add wait4x checkers
	if waitForHost != "" {
		_, err := url.Parse(waitForHost)
		if err != nil {
			return err
		}

		hc := http.New(waitForHost,
			http.WithExpectStatusCode(expectStatusCode),
			http.WithExpectBodyRegex(expectBodyRegex),
			http.WithExpectBodyJSON(expectBodyJSON),
			http.WithExpectBodyXPath(expectBodyXPath),
			http.WithExpectHeader(expectHeader),
			http.WithTimeout(connectionTimeout),
			http.WithInsecureSkipTLSVerify(insecureSkipTLSVerify),
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
			return waiterErr
		}
	}
	// use outputFile to write to file
	var outputFile *os.File
	if outputFilename == "" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.Open(outputFilename)
		if err != nil {
			return err
		}
	}
	out := output.NewOutput(wantedOutput, outputFile)
	_ = out.Println("%s", out.Message("** Starting tests!"))

	currentRun, err := runner.Run(cfg, tests, runner.RunnerConfig{
		Include:        includeRE,
		Exclude:        excludeRE,
		ShowTime:       showTime,
		ShowOnlyFailed: showOnlyFailed,
		ConnectTimeout: connectTimeout,
		ReadTimeout:    readTimeout,
	}, out)

	if err != nil {
		return err
	}
	if currentRun.Stats.TotalFailed() > 0 {
		return fmt.Errorf("failed %d tests", currentRun.Stats.TotalFailed())
	}
	return nil
}
