package runner

import (
	"os"
	"time"

	"github.com/fzipi/go-ftw/ftwhttp"
	"github.com/fzipi/go-ftw/waflog"
)

// TestRunContext carries information about the current test run.
// This includes both configuration information as well as statistics
// and results.
type TestRunContext struct {
	Include  string
	Exclude  string
	ShowTime bool
	Output   bool
	Stats    TestStats
	Result   TestResult
	Duration time.Duration
	Client   *ftwhttp.Client
	LogLines *waflog.FTWLogLines
	LogFile  *os.File
}
