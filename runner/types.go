package runner

import (
	"regexp"
	"time"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/waflog"
)

// Config provides configuration for the test runner.
type Config struct {
	// Include is a regular expression to filter tests to include. If nil, all tests are included.
	Include *regexp.Regexp
	// Exclude is a regular expression to filter tests to exclude. If nil, no tests are excluded.
	Exclude *regexp.Regexp
	// ShowTime determines whether to show the time taken to run each test.
	ShowTime bool
	// Quiet determines whether to output informational messages.
	Quiet bool
	// ConnectTimeout is the timeout for connecting to endpoints during test execution.
	ConnectTimeout time.Duration
	// ReadTimeout is the timeout for receiving responses during test execution.
	ReadTimeout time.Duration
}

// TestRunContext carries information about the current test run.
// This includes both configuration information as well as statistics
// and results.
type TestRunContext struct {
	Include  *regexp.Regexp
	Exclude  *regexp.Regexp
	ShowTime bool
	Output   bool
	Stats    TestStats
	Result   TestResult
	Duration time.Duration
	Client   *ftwhttp.Client
	LogLines *waflog.FTWLogLines
	RunMode  config.RunMode
}
