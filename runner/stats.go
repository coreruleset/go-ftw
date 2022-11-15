package runner

import (
	"encoding/json"
	"time"

	"github.com/coreruleset/go-ftw/output"
	"github.com/rs/zerolog/log"
)

// TestResult type are the values that the result of a test can have
type TestResult int

// Handy constants for test results
const (
	Success TestResult = iota
	Failed
	Skipped
	Ignored
	ForcePass
	ForceFail
)

// RunStats accumulates test statistics.
type RunStats struct {
	// Run is the amount of tests executed in this run.
	Run int `json:"run"`
	// Success is a list containing the tests that were successful.
	Success []string `json:"success"`
	// Failed is a list containing the failed tests.
	Failed []string `json:"failed"`
	// Skipped is a list containing the tests that were skipped.
	Skipped    []string `json:"skipped"`
	Ignored    []string `json:"ignored"`
	ForcedPass []string `json:"forced-pass"`
	ForcedFail []string `json:"forced-fail"`
	// RunTime maps the time taken to run each test.
	RunTime map[string]time.Duration `json:"runtime"`
	// TotalTime is the duration over all runs, the sum of all individual run times.
	TotalTime time.Duration
}

// NewRunStats creates and initializes a new Stats struct.
func NewRunStats() *RunStats {
	return &RunStats{
		Run:        0,
		Success:    nil,
		Failed:     nil,
		Skipped:    nil,
		Ignored:    nil,
		ForcedPass: nil,
		ForcedFail: nil,
		RunTime:    make(map[string]time.Duration),
		TotalTime:  0,
	}
}

func (stats *RunStats) TotalFailed() int {
	return len(stats.Failed) + len(stats.ForcedFail)
}

func (stats *RunStats) addResultToStats(result TestResult, title string, testTime time.Duration) {
	switch result {
	case Success:
		stats.Success = append(stats.Success, title)
		stats.RunTime[title] = testTime
	case Failed:
		stats.Failed = append(stats.Failed, title)
		stats.RunTime[title] = testTime
	case Skipped:
		stats.Skipped = append(stats.Skipped, title)
	case Ignored:
		stats.Ignored = append(stats.Ignored, title)
	case ForceFail:
		stats.ForcedFail = append(stats.ForcedFail, title)
		stats.RunTime[title] = testTime
	case ForcePass:
		stats.ForcedPass = append(stats.ForcedPass, title)
		stats.RunTime[title] = testTime
	default:
		log.Info().Msgf("runner/stats: don't know how to handle TestResult %d", result)
	}
}

func (stats *RunStats) printSummary(out *output.Output) {
	if stats.Run > 0 {
		if out.IsJson() {
			b, _ := json.Marshal(stats)
			out.RawPrint(string(b))
		} else {
			out.Println(out.Message("+ run %d total tests in %s"), stats.Run, stats.TotalTime)
			out.Println(out.Message(">> skipped %d tests"), len(stats.Skipped))
			if len(stats.Ignored) > 0 {
				out.Println(out.Message("- ignored %d tests"), len(stats.Ignored))
			}
			if len(stats.ForcedPass) > 0 {
				out.Println(out.Message("- forced to pass %d tests"), len(stats.ForcedPass))
			}
			if stats.TotalFailed() == 0 {
				out.Println(out.Message("\\o/ All tests successful!"))
			} else {
				out.Println(out.Message("- %d test(s) failed to run: %+q"), len(stats.Failed), stats.Failed)
				if len(stats.ForcedFail) > 0 {
					out.Println(out.Message("-  %d test(s) were forced to fail: %+q"), len(stats.ForcedFail), stats.ForcedFail)
				}
			}
		}
	} else {
		out.Println(out.Message("¯\\_(ツ)_/¯ No tests were run"))
	}
}
