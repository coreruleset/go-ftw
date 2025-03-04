// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"regexp"
	"time"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/waflog"
)

// RunnerConfig provides configuration for the test runner.
type RunnerConfig struct {
	// Include is a regular expression to filter tests to include. If nil, all tests are included.
	Include *regexp.Regexp
	// Exclude is a regular expression to filter tests to exclude. If nil, no tests are excluded.
	Exclude *regexp.Regexp
	// IncludeTags is a regular expression to filter tests to count the ones tagged with the mathing label. If nil, no impact on test runner.
	IncludeTags *regexp.Regexp
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
	// RateLimit is the rate limit for requests to the server. 0 is unlimited.
	RateLimit time.Duration
	// FailFast determines whether to stop running tests when the first failure is encountered.
	FailFast bool
}

// TestRunContext carries information about the current test run.
// This includes configuration information as well as statistics
// and results.
type TestRunContext struct {
	Config                *config.FTWConfiguration
	RunnerConfig          *RunnerConfig
	Include               *regexp.Regexp
	Exclude               *regexp.Regexp
	IncludeTags           *regexp.Regexp
	ShowTime              bool
	ShowOnlyFailed        bool
	Output                *output.Output
	Stats                 *RunStats
	Result                TestResult
	Duration              time.Duration
	Client                *ftwhttp.Client
	LogLines              *waflog.FTWLogLines
	CurrentStageDuration  time.Duration
	currentStageStartTime time.Time
}

func (t *TestRunContext) StartTest() {
}

func (t *TestRunContext) EndTest(testCase *schema.Test) {
	t.Stats.addResultToStats(t.Result, testCase)
}

func (t *TestRunContext) StartStage() {
	t.currentStageStartTime = time.Now()
	t.CurrentStageDuration = time.Duration(0)
}

func (t *TestRunContext) EndStage(testCase *schema.Test, testResult TestResult, triggeredRules []uint) {
	t.CurrentStageDuration = time.Since(t.currentStageStartTime)
	t.Result = testResult
	t.Stats.addStageResultToStats(testCase, t.CurrentStageDuration, triggeredRules)
}
