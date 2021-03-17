package runner

import (
	"os"
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
)

// TestStats accumulates test statistics
type TestStats struct {
	Run     int
	Failed  []string
	Skipped []string
	Success int
	RunTime time.Duration
}

func addResultToStats(result TestResult, title string, stats *TestStats) {
	switch result {
	case Success:
		stats.Success++
	case Failed:
		stats.Failed = append(stats.Failed, title)
	case Skipped:
		stats.Skipped = append(stats.Skipped, title)
	default:
		log.Info().Msgf("runner/stats: don't know how to handle TestResult %d", result)
	}
}

func printSummary(quiet bool, stats TestStats) {
	var exitCode int
	if len(stats.Failed) == 0 && stats.Run > 0 {
		if !quiet {
			emoji.Printf(":plus:run %d total tests in %s\n", stats.Run, stats.RunTime)
			emoji.Printf(":next_track_button: skept %d tests\n", len(stats.Skipped))
			emoji.Println(":tada:All tests successful!")
		}
		exitCode = 0
	} else if len(stats.Failed) > 0 {
		if !quiet {
			emoji.Printf(":minus:%d test(s) failed to run: %+q\n", len(stats.Failed), stats.Failed)
		}
		exitCode = 1
	}
	os.Exit(exitCode)
}
