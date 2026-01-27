// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
)

type statsTestSuite struct {
	suite.Suite
	tempDir     string
	summaryFile string
}

func (s *statsTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *statsTestSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "ftw-stats-test-*")
	s.Require().NoError(err)

	// Set up GITHUB_STEP_SUMMARY for most tests
	s.summaryFile = filepath.Join(s.tempDir, "summary.md")
	os.Setenv("GITHUB_STEP_SUMMARY", s.summaryFile)
}

func (s *statsTestSuite) TearDownTest() {
	os.Unsetenv("GITHUB_STEP_SUMMARY")
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(statsTestSuite))
}

func (s *statsTestSuite) TestWriteGitHubSummary_Success() {
	stats := &RunStats{
		Run:        10,
		Success:    []string{"test-1", "test-2", "test-3"},
		Failed:     []string{"test-4", "test-5"},
		Skipped:    []string{"test-6"},
		Ignored:    []string{"test-7"},
		ForcedPass: []string{"test-8"},
		ForcedFail: []string{"test-9"},
		RunTime: map[string]time.Duration{
			"test-4": 100 * time.Millisecond,
			"test-5": 200 * time.Millisecond,
			"test-9": 50 * time.Millisecond,
		},
		TotalTime: 5 * time.Second,
	}

	stats.writeGitHubSummary()

	// Read the file and verify content
	content, err := os.ReadFile(s.summaryFile)
	s.Require().NoError(err)

	contentStr := string(content)
	// Verify header
	s.Contains(contentStr, "## FTW Test Results")
	// Verify failure badge
	s.Contains(contentStr, "❌ **Some tests failed**")
	// Verify summary table
	s.Contains(contentStr, "### Summary")
	s.Contains(contentStr, "| Metric | Count |")
	s.Contains(contentStr, "| Total Tests Run | 10 |")
	s.Contains(contentStr, "| ✅ Passed | 3 |")
	s.Contains(contentStr, "| ❌ Failed | 3 |")
	s.Contains(contentStr, "| ⏭️ Skipped | 1 |")
	s.Contains(contentStr, "| ℹ️ Ignored | 1 |")
	s.Contains(contentStr, "| 🔧 Forced Pass | 1 |")
	s.Contains(contentStr, "| 🔧 Forced Fail | 1 |")
	s.Contains(contentStr, "| ⏱️ Total Time | 5s |")
	// Verify failed tests table
	s.Contains(contentStr, "### ❌ Failed Tests")
	s.Contains(contentStr, "| Test ID | Duration |")
	s.Contains(contentStr, "| `test-4` | 100ms |")
	s.Contains(contentStr, "| `test-5` | 200ms |")
	// Verify forced fail tests table
	s.Contains(contentStr, "### 🔧 Forced Fail Tests")
	s.Contains(contentStr, "| `test-9` | 50ms |")
}

func (s *statsTestSuite) TestWriteGitHubSummary_AllPassed() {
	stats := &RunStats{
		Run:       5,
		Success:   []string{"test-1", "test-2", "test-3", "test-4", "test-5"},
		Failed:    []string{},
		Skipped:   []string{},
		TotalTime: 2 * time.Second,
	}

	stats.writeGitHubSummary()

	content, err := os.ReadFile(s.summaryFile)
	s.Require().NoError(err)

	contentStr := string(content)
	// Verify success badge
	s.Contains(contentStr, "✅ **All tests passed!**")
	s.Contains(contentStr, "| Total Tests Run | 5 |")
	s.Contains(contentStr, "| ✅ Passed | 5 |")
	s.Contains(contentStr, "| ❌ Failed | 0 |")
	// Should not contain failed tests section
	s.NotContains(contentStr, "### ❌ Failed Tests")
	s.NotContains(contentStr, "### 🔧 Forced Fail Tests")
}

func (s *statsTestSuite) TestWriteGitHubSummary_NoIgnoredOrForced() {
	stats := &RunStats{
		Run:        3,
		Success:    []string{"test-1", "test-2"},
		Failed:     []string{"test-3"},
		Skipped:    []string{},
		Ignored:    []string{},
		ForcedPass: []string{},
		ForcedFail: []string{},
		TotalTime:  1 * time.Second,
	}

	stats.writeGitHubSummary()

	content, err := os.ReadFile(s.summaryFile)
	s.Require().NoError(err)

	contentStr := string(content)
	// Should not contain ignored or forced rows
	s.NotContains(contentStr, "| ℹ️ Ignored")
	s.NotContains(contentStr, "| 🔧 Forced Pass")
	s.NotContains(contentStr, "| 🔧 Forced Fail |")
}

func (s *statsTestSuite) TestWriteGitHubSummary_NoEnvVar() {
	// Make sure GITHUB_STEP_SUMMARY is not set
	os.Unsetenv("GITHUB_STEP_SUMMARY")

	stats := &RunStats{
		Run:     1,
		Success: []string{"test-1"},
	}

	// Should not panic or error, just log a warning
	stats.writeGitHubSummary()
	// No assertions needed - just ensuring it doesn't crash
}

func (s *statsTestSuite) TestWriteGitHubSummary_AppendMode() {
	// Write initial content
	initialContent := "# Previous Content\n\n"
	err := os.WriteFile(s.summaryFile, []byte(initialContent), 0644)
	s.Require().NoError(err)

	stats := &RunStats{
		Run:       2,
		Success:   []string{"test-1", "test-2"},
		TotalTime: 1 * time.Second,
	}

	stats.writeGitHubSummary()

	content, err := os.ReadFile(s.summaryFile)
	s.Require().NoError(err)

	contentStr := string(content)
	// Should contain both previous and new content
	s.Contains(contentStr, "# Previous Content")
	s.Contains(contentStr, "## FTW Test Results")
}

func (s *statsTestSuite) TestPrintSummary_WithGitHubOutput() {
	var buf bytes.Buffer
	out := output.NewOutput("github", &buf)

	cfg := config.NewDefaultConfig()
	runnerConfig := config.NewRunnerConfiguration(cfg)
	runnerConfig.WriteSummary = true

	stats := &RunStats{
		Run:       3,
		Success:   []string{"test-1", "test-2", "test-3"},
		TotalTime: 1 * time.Second,
	}

	stats.printSummary(out, runnerConfig)

	// Verify summary file was created
	_, err := os.Stat(s.summaryFile)
	s.Require().NoError(err, "Summary file should be created")

	// Verify content
	content, err := os.ReadFile(s.summaryFile)
	s.Require().NoError(err)
	s.Contains(string(content), "## FTW Test Results")
}

func (s *statsTestSuite) TestPrintSummary_WithoutGitHubOutput() {
	var buf bytes.Buffer
	out := output.NewOutput("normal", &buf)

	cfg := config.NewDefaultConfig()
	runnerConfig := config.NewRunnerConfiguration(cfg)
	runnerConfig.WriteSummary = true

	stats := &RunStats{
		Run:       3,
		Success:   []string{"test-1", "test-2", "test-3"},
		TotalTime: 1 * time.Second,
	}

	stats.printSummary(out, runnerConfig)

	// Verify summary file was NOT created (WriteSummary only works with GitHub output)
	_, err := os.Stat(s.summaryFile)
	s.True(os.IsNotExist(err), "Summary file should not be created with non-GitHub output")
}

func (s *statsTestSuite) TestPrintSummary_WriteSummaryDisabled() {
	var buf bytes.Buffer
	out := output.NewOutput("github", &buf)

	cfg := config.NewDefaultConfig()
	runnerConfig := config.NewRunnerConfiguration(cfg)
	runnerConfig.WriteSummary = false

	stats := &RunStats{
		Run:       3,
		Success:   []string{"test-1", "test-2", "test-3"},
		TotalTime: 1 * time.Second,
	}

	stats.printSummary(out, runnerConfig)

	// Verify summary file was NOT created (WriteSummary is disabled)
	_, err := os.Stat(s.summaryFile)
	s.True(os.IsNotExist(err), "Summary file should not be created when WriteSummary is false")
}

func (s *statsTestSuite) TestPrintSummary_NilConfig() {
	var buf bytes.Buffer
	out := output.NewOutput("github", &buf)

	stats := &RunStats{
		Run:       3,
		Success:   []string{"test-1", "test-2", "test-3"},
		TotalTime: 1 * time.Second,
	}

	// Call with nil config - should not crash
	stats.printSummary(out, nil)

	// Verify summary file was NOT created
	_, err := os.Stat(s.summaryFile)
	s.True(os.IsNotExist(err), "Summary file should not be created with nil config")
}

func (s *statsTestSuite) TestPrintSummary_JSON() {
	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	cfg := config.NewDefaultConfig()
	runnerConfig := config.NewRunnerConfiguration(cfg)

	stats := &RunStats{
		Run:       3,
		Success:   []string{"test-1", "test-2", "test-3"},
		TotalTime: 1 * time.Second,
	}

	stats.printSummary(out, runnerConfig)

	// Verify JSON output
	output := buf.String()
	s.Contains(output, `"run":3`)
	s.Contains(output, `"success":["test-1","test-2","test-3"]`)
}

func (s *statsTestSuite) TestPrintSummary_NoTests() {
	var buf bytes.Buffer
	out := output.NewOutput("normal", &buf)

	cfg := config.NewDefaultConfig()
	runnerConfig := config.NewRunnerConfiguration(cfg)

	stats := &RunStats{
		Run: 0,
	}

	stats.printSummary(out, runnerConfig)

	// Verify the "no tests" message
	output := buf.String()
	s.Contains(output, "No tests were run")
}

func (s *statsTestSuite) TestWriteGitHubSummary_WithoutDuration() {
	stats := &RunStats{
		Run:        3,
		Success:    []string{"test-1"},
		Failed:     []string{"test-2"},
		ForcedFail: []string{"test-3"},
		RunTime:    map[string]time.Duration{}, // Empty map
		TotalTime:  1 * time.Second,
	}

	stats.writeGitHubSummary()

	content, err := os.ReadFile(s.summaryFile)
	s.Require().NoError(err)

	contentStr := string(content)
	// Verify N/A appears for tests without duration
	lines := strings.Split(contentStr, "\n")
	var foundNA bool
	for _, line := range lines {
		if strings.Contains(line, "test-2") || strings.Contains(line, "test-3") {
			if strings.Contains(line, "N/A") {
				foundNA = true
				break
			}
		}
	}
	s.True(foundNA, "Should show N/A for tests without duration")
}
