package runner

import (
	"time"

	"github.com/fzipi/go-ftw/ftwhttp"
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
}
