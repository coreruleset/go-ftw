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

// TestRunContext carries information about the current test run.
// This includes configuration information as well as statistics
// and results.
type TestRunContext struct {
	RunnerConfig          *config.RunnerConfig
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
