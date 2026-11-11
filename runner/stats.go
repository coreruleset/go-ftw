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

	schema "github.com/coreruleset/ftw-tests-schema/v3/types"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/output"
)

// TestResult type are the values that the result of a test can have
type TestResult int

// Handy constants for test results
const (
	Success TestResult = iota
	Failed
	Skipped
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
	ForcedPass []string `json:"forced-pass"`
	ForcedFail []string `json:"forced-fail"`
	// Overridden lists the overridden tests with their forced and their actual result.
	Overridden []OverrideResult `json:"overridden"`
	// FailOnStaleOverrides determines whether stale overrides count as failures
	FailOnStaleOverrides bool `json:"-"`
	// RunTime maps the time taken to run each test.
	RunTime map[string]time.Duration `json:"runtime"`
	// TotalTime is the duration over all runs, the sum of all individual run times.
	TotalTime time.Duration `json:"total-time"`
	// TriggeredRules maps triggered rules to stages of tests
	TriggeredRules map[string][][]uint `json:"triggered-rules"`
}

// OverrideResult describes an overridden test and what its result would have been without the override.
type OverrideResult struct {
	ID string `json:"id"`
	// Override is either "forcepass" or "forcefail"
	Override string `json:"override"`
	// Actual is either "passed" or "failed"
	Actual string `json:"actual"`
	Reason string `json:"reason"`
}

// Stale returns true if the override does not change the result of the test, i.e.,
// a test forced to pass passes anyway or a test forced to fail fails anyway.
func (r OverrideResult) Stale() bool {
	return (r.Override == forcePassName && r.Actual == passedName) ||
		(r.Override == forceFailName && r.Actual == failedName)
}

const (
	forcePassName = "forcepass"
	forceFailName = "forcefail"
	passedName    = "passed"
	failedName    = "failed"
)

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
		ForcedPass:     []string{},
		ForcedFail:     []string{},
		Overridden:     []OverrideResult{},
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
	case ForceFail:
		stats.ForcedFail = append(stats.ForcedFail, title)
	case ForcePass:
		stats.ForcedPass = append(stats.ForcedPass, title)
	default:
		log.Info().Msgf("runner/stats: don't know how to handle TestResult %d", result)
	}
}

func (stats *RunStats) addOverrideToStats(forced TestResult, actual TestResult, reason string, testCase *schema.Test) {
	override := forcePassName
	if forced == ForceFail {
		override = forceFailName
	}
	stats.Overridden = append(stats.Overridden, OverrideResult{
		ID:       testCase.IdString(),
		Override: override,
		Actual:   actualString(actual),
		Reason:   reason,
	})
}

// StaleOverrides returns the IDs of the tests with overrides that do not change the result of the test.
func (stats *RunStats) StaleOverrides() []string {
	stale := []string{}
	for _, overridden := range stats.Overridden {
		if overridden.Stale() {
			stale = append(stale, overridden.ID)
		}
	}
	return stale
}

// FailedOnStaleOverrides returns the number of stale overrides that count as failures.
func (stats *RunStats) FailedOnStaleOverrides() int {
	if !stats.FailOnStaleOverrides {
		return 0
	}
	return len(stats.StaleOverrides())
}

func (stats *RunStats) addStageResultToStats(testCase *schema.Test, stageTime time.Duration, triggeredRules []uint) {
	stats.RunTime[testCase.IdString()] += stageTime
	byStage := stats.TriggeredRules[testCase.IdString()]
	stats.TriggeredRules[testCase.IdString()] = append(byStage, slices.Clone(triggeredRules))
	stats.TotalTime += stageTime
}

func (stats *RunStats) printSummary(out *output.Output) {
	if stats.Run > 0 {
		if out.IsJson() {
			b, _ := json.Marshal(stats)
			out.RawPrint(string(b))
		} else {
			out.Println(out.Message("+ run %d total tests in %s"), stats.Run, stats.TotalTime)
			out.Println(out.Message(">> skipped %d tests"), len(stats.Skipped))
			if len(stats.ForcedPass) > 0 {
				out.Println(out.Message("^ forced to pass %d tests"), len(stats.ForcedPass))
			}
			stale := stats.StaleOverrides()
			if len(stale) > 0 {
				if stats.FailOnStaleOverrides {
					out.Println(out.Message("- %d stale override(s): %+q (set stale_overrides: warn to only report)"), len(stale), stale)
				} else {
					out.Println(out.Message("! %d stale override(s): %+q"), len(stale), stale)
				}
			}
			if stats.TotalFailed() == 0 {
				if stats.FailedOnStaleOverrides() == 0 {
					out.Println(out.Message("\\o/ All tests successful!"))
				}
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
		fmt.Fprintf(summary, "| `%s` | %s |\n", test, duration)
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
	fmt.Fprintf(&summary, "| Total Tests Run | %d |\n", stats.Run)
	fmt.Fprintf(&summary, "| ✅ Passed | %d |\n", len(stats.Success))
	fmt.Fprintf(&summary, "| ❌ Failed | %d |\n", stats.TotalFailed())
	fmt.Fprintf(&summary, "| ⏭️ Skipped | %d |\n", len(stats.Skipped))
	if len(stats.ForcedPass) > 0 {
		fmt.Fprintf(&summary, "| 🔧 Forced Pass | %d |\n", len(stats.ForcedPass))
	}
	if len(stats.ForcedFail) > 0 {
		fmt.Fprintf(&summary, "| 🔧 Forced Fail | %d |\n", len(stats.ForcedFail))
	}
	if stale := stats.StaleOverrides(); len(stale) > 0 {
		fmt.Fprintf(&summary, "| ⚠️ Stale Overrides | %d |\n", len(stale))
	}
	fmt.Fprintf(&summary, "| ⏱️ Total Time | %s |\n\n", stats.TotalTime)

	// Failed tests details in table format
	if len(stats.Failed) > 0 {
		summary.WriteString("### ❌ Failed Tests\n\n")
		stats.writeTestTable(&summary, stats.Failed)
	}

	if len(stats.ForcedFail) > 0 {
		summary.WriteString("### 🔧 Forced Fail Tests\n\n")
		stats.writeTestTable(&summary, stats.ForcedFail)
	}

	if len(stats.Overridden) > 0 {
		summary.WriteString("### 🔧 Overridden Tests\n\n")
		summary.WriteString("| Test ID | Override | Actual | Stale | Reason |\n")
		summary.WriteString("|---------|----------|--------|-------|--------|\n")
		for _, overridden := range stats.Overridden {
			stale := ""
			if overridden.Stale() {
				stale = "⚠️"
			}
			fmt.Fprintf(&summary, "| `%s` | %s | %s | %s | %s |\n", overridden.ID, overridden.Override, overridden.Actual, stale, overridden.Reason)
		}
		summary.WriteString("\n")
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
