package runner

import (
	"regexp"
	"time"

	"github.com/coreruleset/go-ftw/output"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/waflog"
)

// RunnerConfig provides configuration for the test runner.
type RunnerConfig struct {
	// Include is a regular expression to filter tests to include. If nil, all tests are included.
	Include *regexp.Regexp
	// Exclude is a regular expression to filter tests to exclude. If nil, no tests are excluded.
	Exclude *regexp.Regexp
	// ShowTime determines whether to show the time taken to run each test.
	ShowTime bool
	// ShowOnlyFailed will only output information related to failed tests
	ShowOnlyFailed bool
	// Output determines the type of output the user wants.
	Output output.Type
	// ConnectTimeout is the timeout for connecting to endpoints during test execution.
	ConnectTimeout time.Duration
	// ReadTimeout is the timeout for receiving responses during test execution.
	ReadTimeout time.Duration
}

// TestRunContext carries information about the current test run.
// This includes configuration information as well as statistics
// and results.
type TestRunContext struct {
	Config         *config.FTWConfiguration
	Include        *regexp.Regexp
	Exclude        *regexp.Regexp
	ShowTime       bool
	ShowOnlyFailed bool
	Output         *output.Output
	Stats          *RunStats
	Result         TestResult
	Duration       time.Duration
	Client         *ftwhttp.Client
	LogLines       *waflog.FTWLogLines
}
