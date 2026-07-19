// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/output"
)

type statsTestSuite struct {
	suite.Suite
}

func (s *statsTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(statsTestSuite))
}

func (s *statsTestSuite) TestNewQuantitativeStats() {
	tests := []struct {
		name string
		want *QuantitativeRunStats
	}{
		{
			name: "Test 1",
			want: &QuantitativeRunStats{
				count_:                         0,
				falsePositives:                 0,
				ignoredFalsePositives:          0,
				falsePositiveSentences:         0,
				falsePositivesPerRule:          make(map[int]RuleStats),
				falsePositivesPerParanoiaLevel: make(map[int]int),
				ignoredRules:                   map[int]struct{}{},
				totalTime:                      0,
			},
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			got := NewQuantitativeStats(nil)
			s.Require().Equal(got, tt.want)
		})
	}
}

func (s *statsTestSuite) TestQuantitativeRunStats_MarshalJSON() {
	type fields struct {
		count_                int
		skipped_              int
		totalTime             time.Duration
		falsePositives        int
		falsePositivesPerRule map[int]RuleStats
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name: "Test 1",
			fields: fields{
				count_:                1,
				totalTime:             time.Second,
				falsePositives:        1,
				falsePositivesPerRule: map[int]RuleStats{920010: {ParanoiaLevel: 1, FalsePositives: 1}},
			},
			want:    []byte(`{"corpusSize":1,"count":1,"falsePositiveSentences":0,"falsePositives":1,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"920010":{"paranoiaLevel":1,"falsePositives":1}},"skipped":0,"totalTimeSeconds":1}`),
			wantErr: false,
		},
		{
			name: "Test 2",
			fields: fields{
				count_:                2,
				totalTime:             time.Second * 2,
				falsePositives:        2,
				falsePositivesPerRule: map[int]RuleStats{933100: {ParanoiaLevel: 1, FalsePositives: 2}},
			},
			want:    []byte(`{"corpusSize":2,"count":2,"falsePositiveSentences":0,"falsePositives":2,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"933100":{"paranoiaLevel":1,"falsePositives":2}},"skipped":0,"totalTimeSeconds":2}`),
			wantErr: false,
		},
		{
			name: "Test 3 - corpusSize includes skipped",
			fields: fields{
				count_:                8,
				skipped_:              2,
				totalTime:             time.Second * 3,
				falsePositives:        1,
				falsePositivesPerRule: map[int]RuleStats{941100: {ParanoiaLevel: 2, FalsePositives: 1}},
			},
			want:    []byte(`{"corpusSize":10,"count":8,"falsePositiveSentences":0,"falsePositives":1,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"941100":{"paranoiaLevel":2,"falsePositives":1}},"skipped":2,"totalTimeSeconds":3}`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			q := &QuantitativeRunStats{
				count_:                tt.fields.count_,
				skipped_:              tt.fields.skipped_,
				totalTime:             tt.fields.totalTime,
				falsePositives:        tt.fields.falsePositives,
				falsePositivesPerRule: tt.fields.falsePositivesPerRule,
			}
			got, err := q.MarshalJSON()
			s.Require().NoError(err)
			s.JSONEq(string(tt.want), string(got))
		})
	}
}

func (s *statsTestSuite) TestQuantitativeRunStats_functions() {
	q := NewQuantitativeStats(nil)

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	q.addFalsePositiveSentence()
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.FalsePositiveSentences(), 1)

	q.incrementRun()
	s.Require().Equal(q.Count(), 2)

	q.addFalsePositive(920200, 2)
	q.addFalsePositive(920300, 2)
	q.addFalsePositiveSentence()
	s.Require().Equal(q.FalsePositives(), 3)
	s.Require().Equal(q.FalsePositiveSentences(), 2)

	duration := time.Duration(5000)
	q.SetTotalTime(duration)
	s.Require().Equal(q.TotalTime(), duration)
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_Plain() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	q := NewQuantitativeStats(nil)

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	q.addFalsePositiveSentence()
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.FalsePositiveSentences(), 1)
	s.Require().Equal(q.Skipped(), 0)

	q.printSummary(out)
	s.Require().Equal("Run 1 payloads (0 skipped) in 0s\nTotal False positive ratio: 1/1 = 1.0000\nTotal False positive sentences: 1/1 = 1.0000\nFalse positives per paranoia level:\n  PL1: 1 false positives. FP Ratio: 1/1 = 1.0000\nFalse positives per rule id:\n  920100 (PL1): 1 false positives. FP Ratio: 1/1 = 1.0000\n", b.String())
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_JSON() {
	var b bytes.Buffer
	out := output.NewOutput("json", &b)
	q := NewQuantitativeStats(nil)

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	q.addFalsePositiveSentence()
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.FalsePositiveSentences(), 1)
	s.Require().Equal(q.Skipped(), 0)

	q.printSummary(out)
	s.JSONEq(`{"corpusSize":1,"count":1,"falsePositiveSentences":1,"falsePositives":1,"falsePositivesPerParanoiaLevel":{"1":1},"falsePositivesPerRule":{"920100":{"paranoiaLevel":1,"falsePositives":1}},"skipped":0,"totalTimeSeconds":0}`, b.String())
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_MultiParanoiaLevels_Plain() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	q := NewQuantitativeStats(nil)

	for range 10 {
		q.incrementRun()
	}
	evaluatedLevels, err := NewParanoiaLevels(1, 2, 4)
	s.Require().NoError(err)
	q.SetEvaluatedParanoiaLevels(evaluatedLevels)

	q.addFalsePositive(920100, 1)
	q.addFalsePositive(920200, 2)
	q.addFalsePositive(920201, 2)
	q.addFalsePositive(920400, 4)

	q.printSummary(out)
	s.Require().Equal("Run 10 payloads (0 skipped) in 0s\nTotal False positive ratio at PL4: 4/10 = 0.4000\nFalse positive totals by evaluated paranoia level:\n  PL1: 1 false positives. FP Ratio: 1/10 = 0.1000\n  PL2: 3 false positives. FP Ratio: 3/10 = 0.3000\n  PL4: 4 false positives. FP Ratio: 4/10 = 0.4000\nTotal False positive sentences: 0/10 = 0.0000\nFalse positives per paranoia level:\n  PL1: 1 false positives. FP Ratio: 1/10 = 0.1000\n  PL2: 2 false positives. FP Ratio: 2/10 = 0.2000\n  PL4: 1 false positives. FP Ratio: 1/10 = 0.1000\nFalse positives per rule id:\n  920100 (PL1): 1 false positives. FP Ratio: 1/10 = 0.1000\n  920200 (PL2): 1 false positives. FP Ratio: 1/10 = 0.1000\n  920201 (PL2): 1 false positives. FP Ratio: 1/10 = 0.1000\n  920400 (PL4): 1 false positives. FP Ratio: 1/10 = 0.1000\n", b.String())
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_MultiParanoiaLevels_JSON() {
	var b bytes.Buffer
	out := output.NewOutput("json", &b)
	q := NewQuantitativeStats(nil)

	for range 3 {
		q.incrementRun()
	}
	evaluatedLevels, err := NewParanoiaLevels(1, 2, 4)
	s.Require().NoError(err)
	q.SetEvaluatedParanoiaLevels(evaluatedLevels)

	q.addFalsePositive(920100, 1)
	q.addFalsePositive(920200, 2)
	q.addFalsePositive(920400, 4)

	q.printSummary(out)
	require.JSONEq(s.T(), `{
		"corpusSize": 3,
		"count": 3,
		"evaluatedParanoiaLevels": [1, 2, 4],
		"falsePositiveSentences": 0,
		"falsePositiveTotalsPerParanoiaLevel": {"1": 1, "2": 2, "4": 3},
		"falsePositives": 3,
		"falsePositivesPerParanoiaLevel": {"1": 1, "2": 1, "4": 1},
		"falsePositivesPerRule": {
			"920100": {"paranoiaLevel": 1, "falsePositives": 1},
			"920200": {"paranoiaLevel": 2, "falsePositives": 1},
			"920400": {"paranoiaLevel": 4, "falsePositives": 1}
		},
		"skipped": 0,
		"totalTimeSeconds": 0
	}`, b.String())
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_Markdown() {
	var b bytes.Buffer
	out := output.NewOutput("markdown", &b)
	q := NewQuantitativeStats()

	q.incrementRun()
	q.incrementRun()
	q.incrementSkip()
	q.addFalsePositive(920100, 1)
	q.addFalsePositive(942100, 2)
	q.SetTotalTime(time.Second)

	q.printSummary(out)
	s.Require().Equal(`## Quantitative test results

⚠️ Quantitative testing detected false positives.

| Metric | Value |
|--------|-------|
| Payloads run | 2 |
| Skipped payloads | 1 |
| False positives | 2 |
| Duration | 1s |
| False positive ratio | 2/2 = 1.0000 |

### False positives per rule

| Rule ID | PL | False positives | Ratio |
|---------|----|-----------------|-------|
| 920100 | 1 | 1 | 1/2 = 0.5000 |
| 942100 | 2 | 1 | 1/2 = 0.5000 |
`, b.String())
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_MarkdownNoFalsePositives() {
	var b bytes.Buffer
	out := output.NewOutput("markdown", &b)
	q := NewQuantitativeStats()

	q.incrementRun()

	q.printSummary(out)
	s.Require().Equal(`## Quantitative test results

✅ Quantitative testing did not detect false positives.

| Metric | Value |
|--------|-------|
| Payloads run | 1 |
| Skipped payloads | 0 |
| False positives | 0 |
| Duration | 0s |
| False positive ratio | 0/1 = 0.0000 |

### False positives per rule

_No false positives detected._
`, b.String())
}

func (s *statsTestSuite) TestAddFalsePositiveRace() {
	stats := &QuantitativeRunStats{
		falsePositivesPerRule:          make(map[int]RuleStats),
		falsePositivesPerParanoiaLevel: make(map[int]int),
		ignoredRules:                   make(map[int]struct{}),
		mu:                             sync.Mutex{},
	}

	var wg sync.WaitGroup
	numGoroutines := 100
	for i := range numGoroutines {
		wg.Add(1)
		go func(ruleID int) {
			defer wg.Done()
			stats.addFalsePositive(ruleID, 1)
			stats.addFalsePositiveSentence()
		}(i % 10) // Few rules are getting hit to make the concurrency issue more likely
	}
	wg.Wait()

	// Verify total counts
	s.Require().Equal(numGoroutines, stats.FalsePositives(), "Total false positives should equal number of goroutines")
	s.Require().Equal(numGoroutines, stats.FalsePositiveSentences(), "Total false positive sentences should equal number of goroutines")
	totalPerRule := 0
	for _, ruleStats := range stats.falsePositivesPerRule {
		totalPerRule += ruleStats.FalsePositives
	}
	s.Require().Equal(numGoroutines, totalPerRule, "Sum of per-rule counts should equal number of goroutines")
}

func (s *statsTestSuite) TestIgnoredRules_ExcludedFromAggregate() {
	// Rules 920272 and 920273 are "noisy" and should be ignored in aggregate
	q := NewQuantitativeStats([]int{920272, 920273})
	q.incrementRun()
	q.incrementRun()
	q.incrementRun()

	// This one counts toward aggregate
	q.addFalsePositive(920100, 1)
	// These two should NOT count toward aggregate
	q.addFalsePositive(920272, 3)
	q.addFalsePositive(920273, 4)

	s.Require().Equal(1, q.FalsePositives(), "only non-ignored FPs count toward aggregate")
	s.Require().Equal(2, q.ignoredFalsePositives, "ignored rules' FPs are tracked separately")
	// All three rules appear in per-rule stats
	s.Require().Len(q.falsePositivesPerRule, 3)
	s.Require().False(q.falsePositivesPerRule[920100].Ignored)
	s.Require().True(q.falsePositivesPerRule[920272].Ignored)
	s.Require().True(q.falsePositivesPerRule[920273].Ignored)
	// Paranoia-level aggregate excludes ignored rules
	s.Require().Equal(1, q.falsePositivesPerParanoiaLevel[1])
	s.Require().Equal(0, q.falsePositivesPerParanoiaLevel[3])
	s.Require().Equal(0, q.falsePositivesPerParanoiaLevel[4])
}

func (s *statsTestSuite) TestIgnoredRules_printSummary_Plain() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	q := NewQuantitativeStats([]int{920272})

	q.incrementRun()

	// Non-ignored FP
	q.addFalsePositive(920100, 1)
	// Ignored FP
	q.addFalsePositive(920272, 3)

	q.printSummary(out)
	output := b.String()
	s.Require().Contains(output, "Total False positive ratio: 1/1 = 1.0000 (1 FPs from 1 ignored rules not counted)")
	s.Require().Contains(output, "False positives for ignored rules (not counted in aggregate):")
	s.Require().Contains(output, "920272 (PL3): 1 false positives")
}

func (s *statsTestSuite) TestIgnoredRules_printSummary_OnlyIgnored() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	q := NewQuantitativeStats([]int{920272})

	q.incrementRun()
	// Only an ignored FP, no regular FPs
	q.addFalsePositive(920272, 3)

	q.printSummary(out)
	output := b.String()
	s.Require().Contains(output, "No false positives detected (excluding 1 ignored rules)")
	s.Require().Contains(output, "False positives for ignored rules (not counted in aggregate):")
}

func (s *statsTestSuite) TestIgnoredRules_JSON() {
	var b bytes.Buffer
	out := output.NewOutput("json", &b)
	q := NewQuantitativeStats([]int{920272})

	q.incrementRun()
	q.addFalsePositive(920100, 1)
	q.addFalsePositive(920272, 3)

	q.printSummary(out)
	jsonStr := b.String()
	s.Require().Contains(jsonStr, `"ignoredFalsePositives":1`)
	s.Require().Contains(jsonStr, `"falsePositives":1`)
	s.Require().Contains(jsonStr, `"ignored":true`)
}

func (s *statsTestSuite) TestLoadQuantitativeRunStats() {
	dir := s.T().TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	err := os.WriteFile(baselinePath, []byte(`{"count":10,"skipped":1,"totalTimeSeconds":1.5,"falsePositives":3,"falsePositivesPerRule":{"920100":{"paranoiaLevel":1,"falsePositives":2},"933100":{"paranoiaLevel":2,"falsePositives":1}},"falsePositivesPerParanoiaLevel":{"1":2,"2":1}}`), 0o644)
	s.Require().NoError(err)

	stats, err := LoadQuantitativeRunStats(baselinePath)
	s.Require().NoError(err)
	s.Require().Equal(10, stats.Count())
	s.Require().Equal(1, stats.Skipped())
	s.Require().Equal(3, stats.FalsePositives())
	s.Require().Equal(map[int]RuleStats{
		920100: {ParanoiaLevel: 1, FalsePositives: 2},
		933100: {ParanoiaLevel: 2, FalsePositives: 1},
	}, stats.falsePositivesPerRule)
	s.Require().Equal(map[int]int{1: 2, 2: 1}, stats.falsePositivesPerParanoiaLevel)
	s.Require().Equal(1500*time.Millisecond, stats.TotalTime())
}

func (s *statsTestSuite) TestLoadQuantitativeRunStatsRejectsMalformedJSON() {
	dir := s.T().TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	err := os.WriteFile(baselinePath, []byte(`{not valid json`), 0o644)
	s.Require().NoError(err)

	_, err = LoadQuantitativeRunStats(baselinePath)
	s.Require().Error(err)
	s.Require().ErrorContains(err, "failed to decode baseline results")
}

func (s *statsTestSuite) TestQuantitativeRunStatsCompare() {
	baseline := &QuantitativeRunStats{
		count_:         10,
		falsePositives: 3,
		totalTime:      time.Second,
		falsePositivesPerRule: map[int]RuleStats{
			920100: {ParanoiaLevel: 1, FalsePositives: 2},
			933100: {ParanoiaLevel: 2, FalsePositives: 1},
			941100: {ParanoiaLevel: 1, FalsePositives: 1},
		},
		falsePositivesPerParanoiaLevel: map[int]int{1: 3, 2: 1},
	}
	current := &QuantitativeRunStats{
		count_:         10,
		falsePositives: 5,
		totalTime:      2 * time.Second,
		falsePositivesPerRule: map[int]RuleStats{
			920100: {ParanoiaLevel: 1, FalsePositives: 3},
			941100: {ParanoiaLevel: 1, FalsePositives: 1},
			942100: {ParanoiaLevel: 1, FalsePositives: 1},
		},
		falsePositivesPerParanoiaLevel: map[int]int{1: 5},
	}

	comparison := current.Compare(baseline)
	s.Require().True(comparison.HasRegressions())
	s.Require().Equal(2, comparison.Regressions.FalsePositivesDelta)
	s.Require().Equal(RuleDelta{BaselineParanoiaLevel: 1, CurrentParanoiaLevel: 1, BaselineFalsePositives: 2, CurrentFalsePositives: 3, Delta: 1}, comparison.Regressions.PerRuleDeltas[920100])
	s.Require().Equal(RuleDelta{BaselineParanoiaLevel: 1, CurrentParanoiaLevel: 1, BaselineFalsePositives: 1, CurrentFalsePositives: 1, Delta: 0}, comparison.Regressions.PerRuleDeltas[941100])
	s.Require().Equal(RuleDelta{BaselineParanoiaLevel: 0, CurrentParanoiaLevel: 1, BaselineFalsePositives: 0, CurrentFalsePositives: 1, Delta: 1}, comparison.Regressions.NewlyFiringRules[942100])
	s.Require().Equal(RuleDelta{BaselineParanoiaLevel: 2, CurrentParanoiaLevel: 0, BaselineFalsePositives: 1, CurrentFalsePositives: 0, Delta: -1}, comparison.Regressions.StoppedFiringRules[933100])
}

func (s *statsTestSuite) TestComparisonResultPrintSummaryJSON() {
	comparison := (&QuantitativeRunStats{
		count_:         1,
		falsePositives: 1,
		falsePositivesPerRule: map[int]RuleStats{
			920100: {ParanoiaLevel: 1, FalsePositives: 1},
		},
		falsePositivesPerParanoiaLevel: map[int]int{1: 1},
	}).Compare(&QuantitativeRunStats{
		count_:                         1,
		falsePositivesPerRule:          make(map[int]RuleStats),
		falsePositivesPerParanoiaLevel: make(map[int]int),
	})

	var b bytes.Buffer
	comparison.PrintSummary(output.NewOutput("json", &b))

	var got struct {
		Regressions struct {
			Detected         bool                 `json:"detected"`
			NewlyFiringRules map[string]RuleDelta `json:"newlyFiringRules"`
		} `json:"regressions"`
	}
	s.Require().NoError(json.Unmarshal(b.Bytes(), &got))
	s.Require().True(got.Regressions.Detected)
	s.Require().Equal(RuleDelta{BaselineParanoiaLevel: 0, CurrentParanoiaLevel: 1, BaselineFalsePositives: 0, CurrentFalsePositives: 1, Delta: 1}, got.Regressions.NewlyFiringRules["920100"])
}
