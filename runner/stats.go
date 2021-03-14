package runner

import (
	"os"
	"time"

	"github.com/kyokomi/emoji"
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

func addResultToStats(result bool, title string, stats *TestStats) {
	if result {
		stats.Success++
	} else {
		stats.Failed++
		stats.FailedTests = append(stats.FailedTests, title)
	}
}

func printSummary(quiet bool, stats TestStats) {
	if !quiet {
		emoji.Printf(":plus:run %d total tests in %s\n", stats.Run, stats.RunTime)
		emoji.Printf(":next_track_button: skept %d tests\n", stats.Skipped)
		if stats.Failed == 0 && stats.Run > 0 {
			emoji.Println(":tada:All tests successful!")
			os.Exit(0)
		} else if stats.Failed > 0 {
			emoji.Printf(":minus:%d test(s) failed to run: %+q\n", stats.Failed, stats.FailedTests)
			os.Exit(1)
		}
	} else { // just exit with proper status code
		if stats.Failed == 0 && stats.Run > 0 {
			os.Exit(0)
		} else if stats.Failed > 0 {
			os.Exit(1)
		}
	}
}
