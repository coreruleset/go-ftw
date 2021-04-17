package runner

import (
	"time"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog/log"
)

// TestResult type are the values that the result of a test can have
type TestResult int

// Handy contants for test results
const (
	Success TestResult = iota
	Failed
	Skipped
	Ignored
	ForcePass
	ForceFail
)

// TestStats accumulates test statistics
type TestStats struct {
	Run        int
	Failed     []string
	Skipped    []string
	Ignored    []string
	ForcedPass []string
	ForcedFail []string
	Success    int
	RunTime    time.Duration
}

func addResultToStats(result TestResult, title string, stats *TestStats) {
	switch result {
	case Success:
		stats.Success++
	case Failed:
		stats.Failed = append(stats.Failed, title)
	case Skipped:
		stats.Skipped = append(stats.Skipped, title)
	case Ignored:
		stats.Ignored = append(stats.Ignored, title)
	case ForceFail:
		stats.ForcedFail = append(stats.ForcedFail, title)
	case ForcePass:
		stats.ForcedPass = append(stats.ForcedPass, title)
	default:
		log.Info().Msgf("runner/stats: don't know how to handle TestResult %d", result)
	}
}

func printSummary(quiet bool, stats TestStats) int {
	totalFailed := len(stats.Failed) + len(stats.ForcedFail)

	if !quiet {
		if stats.Run > 0 {
			emoji.Printf(":plus:run %d total tests in %s\n", stats.Run, stats.RunTime)
			emoji.Printf(":next_track_button: skept %d tests\n", len(stats.Skipped))
			if len(stats.Ignored) > 0 {
				emoji.Printf(":index_pointing_up: ignored %d tests\n", len(stats.Ignored))
			}
			if len(stats.ForcedPass) > 0 {
				emoji.Printf(":index_pointing_up: forced to pass %d tests\n", len(stats.ForcedPass))
			}
			if totalFailed == 0 {
				emoji.Println(":tada:All tests successful!")
			} else {
				emoji.Printf(":thumbs_down:%d test(s) failed to run: %+q\n", len(stats.Failed), stats.Failed)
				if len(stats.ForcedFail) > 0 {
					emoji.Printf(":index_pointing_up:%d test(s) were forced to fail: %+q\n", len(stats.ForcedFail), stats.ForcedFail)
				}
			}
		} else {
			emoji.Println(":person_shrugging:No tests were run")
		}
	}

	return totalFailed
}
