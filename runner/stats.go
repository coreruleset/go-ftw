// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
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
	// TriggeredRules maps triggered rules to stages of tests
	TriggeredRules map[string][][]uint `json:"triggered-rules"`
}

// type rulesByStage struct {
// 	Stages map[uint][]uint `json:"stages"`
// }

// NewRunStats creates and initializes a new Stats struct.
func NewRunStats() *RunStats {
	return &RunStats{
		Run:            0,
		Success:        []string{},
		Failed:         []string{},
		Skipped:        []string{},
		Ignored:        []string{},
		ForcedPass:     []string{},
		ForcedFail:     []string{},
		RunTime:        make(map[string]time.Duration),
		TotalTime:      0,
		TriggeredRules: make(map[string][][]uint),
	}
}

func (stats *RunStats) TotalFailed() int {
	return len(stats.Failed) + len(stats.ForcedFail)
}

func (stats *RunStats) addResultToStats(result TestResult, testCase *schema.Test) {
	title := testCase.IdString()
	stats.Run++

	switch result {
	case Success:
		stats.Success = append(stats.Success, title)
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

func (stats *RunStats) addStageResultToStats(testCase *schema.Test, stageTime time.Duration, triggeredRules []uint) {
	stats.RunTime[testCase.IdString()] += stageTime
	byStage := stats.TriggeredRules[testCase.IdString()]
	stats.TriggeredRules[testCase.IdString()] = append(byStage, slices.Clone(triggeredRules))
	stats.TotalTime += stageTime
}

func (stats *RunStats) printSummary(out *output.Output, runnerConfig *config.RunnerConfig) {
	if stats.Run > 0 {
		if out.IsJson() {
			b, _ := json.Marshal(stats)
			out.RawPrint(string(b))
		} else {
			out.Println(out.Message("+ run %d total tests in %s"), stats.Run, stats.TotalTime)
			out.Println(out.Message(">> skipped %d tests"), len(stats.Skipped))
			if len(stats.Ignored) > 0 {
				out.Println(out.Message("^ ignored %d tests"), len(stats.Ignored))
			}
			if len(stats.ForcedPass) > 0 {
				out.Println(out.Message("^ forced to pass %d tests"), len(stats.ForcedPass))
			}
			if stats.TotalFailed() == 0 {
				out.Println(out.Message("\\o/ All tests successful!"))
			} else {
				out.Println(out.Message("- %d test(s) failed to run: %+q"), len(stats.Failed), stats.Failed)
				if len(stats.ForcedFail) > 0 {
					out.Println(out.Message("- %d test(s) were forced to fail: %+q"), len(stats.ForcedFail), stats.ForcedFail)
				}
			}
		}

		// Write summary to GITHUB_STEP_SUMMARY when in GitHub output mode
		if out.OutputType == output.GitHub {
			stats.writeGitHubSummary()
		}
	} else {
		out.Println(out.Message("¯\\_(ツ)_/¯ No tests were run"))
	}
}

// writeTestTable writes a markdown table with test IDs and durations
func (stats *RunStats) writeTestTable(summary *strings.Builder, tests []string) {
	summary.WriteString("| Test ID | Duration |\n")
	summary.WriteString("|---------|----------|\n")
	for _, test := range tests {
		duration := "N/A"
		if d, ok := stats.RunTime[test]; ok {
			duration = d.String()
		}
		summary.WriteString(fmt.Sprintf("| `%s` | %s |\n", test, duration))
	}
	summary.WriteString("\n")
}

func (stats *RunStats) writeGitHubSummary() {
	summaryFile := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryFile == "" {
		log.Warn().Msg("GITHUB_STEP_SUMMARY environment variable is not set, skipping summary")
		return
	}

	// Build markdown summary
	var summary strings.Builder
	summary.WriteString("## FTW Test Results\n\n")

	// Status badge
	if stats.TotalFailed() == 0 {
		summary.WriteString("✅ **All tests passed!**\n\n")
	} else {
		summary.WriteString("❌ **Some tests failed**\n\n")
	}

	// Overall statistics table
	summary.WriteString("### Summary\n\n")
	summary.WriteString("| Metric | Count |\n")
	summary.WriteString("|--------|-------|\n")
	summary.WriteString(fmt.Sprintf("| Total Tests Run | %d |\n", stats.Run))
	summary.WriteString(fmt.Sprintf("| ✅ Passed | %d |\n", len(stats.Success)))
	summary.WriteString(fmt.Sprintf("| ❌ Failed | %d |\n", stats.TotalFailed()))
	summary.WriteString(fmt.Sprintf("| ⏭️ Skipped | %d |\n", len(stats.Skipped)))
	if len(stats.Ignored) > 0 {
		summary.WriteString(fmt.Sprintf("| ℹ️ Ignored | %d |\n", len(stats.Ignored)))
	}
	if len(stats.ForcedPass) > 0 {
		summary.WriteString(fmt.Sprintf("| 🔧 Forced Pass | %d |\n", len(stats.ForcedPass)))
	}
	if len(stats.ForcedFail) > 0 {
		summary.WriteString(fmt.Sprintf("| 🔧 Forced Fail | %d |\n", len(stats.ForcedFail)))
	}
	summary.WriteString(fmt.Sprintf("| ⏱️ Total Time | %s |\n\n", stats.TotalTime))

	// Failed tests details in table format
	if len(stats.Failed) > 0 {
		summary.WriteString("### ❌ Failed Tests\n\n")
		stats.writeTestTable(&summary, stats.Failed)
	}

	if len(stats.ForcedFail) > 0 {
		summary.WriteString("### 🔧 Forced Fail Tests\n\n")
		stats.writeTestTable(&summary, stats.ForcedFail)
	}

	// Write to file (append mode)
	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open GITHUB_STEP_SUMMARY file")
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close GITHUB_STEP_SUMMARY file")
		}
	}()

	if _, err := f.WriteString(summary.String()); err != nil {
		log.Error().Err(err).Msg("Failed to write to GITHUB_STEP_SUMMARY file")
		return
	}

	log.Debug().Msgf("Wrote summary to %s", summaryFile)
}
