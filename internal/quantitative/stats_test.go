// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"encoding/json"
	"os"
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
				falsePositivesPerRule:          make(map[int]RuleStats),
				falsePositivesPerParanoiaLevel: make(map[int]int),
				totalTime:                      0,
			},
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			got := NewQuantitativeStats()
			s.Require().Equal(got, tt.want)
		})
	}
}

func (s *statsTestSuite) TestQuantitativeRunStats_MarshalJSON() {
	type fields struct {
		count_                int
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
			want:    []byte(`{"count":1,"falsePositives":1,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"920010":{"paranoiaLevel":1,"falsePositives":1}},"skipped":0,"totalTimeSeconds":1}`),
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
			want:    []byte(`{"count":2,"falsePositives":2,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"933100":{"paranoiaLevel":1,"falsePositives":2}},"skipped":0,"totalTimeSeconds":2}`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			q := &QuantitativeRunStats{
				count_:                tt.fields.count_,
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
	q := NewQuantitativeStats()

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	s.Require().Equal(q.FalsePositives(), 1)

	q.incrementRun()
	s.Require().Equal(q.Count(), 2)

	q.addFalsePositive(920200, 2)
	s.Require().Equal(q.FalsePositives(), 2)

	duration := time.Duration(5000)
	q.SetTotalTime(duration)
	s.Require().Equal(q.TotalTime(), duration)
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_Plain() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	q := NewQuantitativeStats()

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.Skipped(), 0)

	q.printSummary(out)
	s.Require().Equal("Run 1 payloads (0 skipped) in 0s\nTotal False positive ratio: 1/1 = 1.0000\nFalse positives per paranoia level:\n  PL1: 1 false positives. FP Ratio: 1/1 = 1.0000\nFalse positives per rule id:\n  920100 (PL1): 1 false positives. FP Ratio: 1/1 = 1.0000\n", b.String())
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary_JSON() {
	var b bytes.Buffer
	out := output.NewOutput("json", &b)
	q := NewQuantitativeStats()

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.Skipped(), 0)

	q.printSummary(out)
	s.JSONEq(`{"count":1,"falsePositives":1,"falsePositivesPerParanoiaLevel":{"1":1},"falsePositivesPerRule":{"920100":{"paranoiaLevel":1,"falsePositives":1}},"skipped":0,"totalTimeSeconds":0}`, b.String())
}

func (s *statsTestSuite) TestAddFalsePositiveRace() {
	stats := &QuantitativeRunStats{
		falsePositivesPerRule:          make(map[int]RuleStats),
		falsePositivesPerParanoiaLevel: make(map[int]int),
		mu:                             sync.Mutex{},
	}

	var wg sync.WaitGroup
	numGoroutines := 100
	for i := range numGoroutines {
		wg.Add(1)
		go func(ruleID int) {
			defer wg.Done()
			stats.addFalsePositive(ruleID, 1)
		}(i % 10) // Few rules are getting hit to make the concurrency issue more likely
	}
	wg.Wait()

	// Verify total counts
	s.Require().Equal(numGoroutines, stats.FalsePositives(), "Total false positives should equal number of goroutines")
	totalPerRule := 0
	for _, ruleStats := range stats.falsePositivesPerRule {
		totalPerRule += ruleStats.FalsePositives
	}
	s.Require().Equal(numGoroutines, totalPerRule, "Sum of per-rule counts should equal number of goroutines")
}

func TestLoadQuantitativeRunStats(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := dir + "/baseline.json"
	err := os.WriteFile(baselinePath, []byte(`{"count":10,"skipped":1,"totalTimeSeconds":1.5,"falsePositives":3,"falsePositivesPerRule":{"920100":{"paranoiaLevel":1,"falsePositives":2},"933100":{"paranoiaLevel":2,"falsePositives":1}},"falsePositivesPerParanoiaLevel":{"1":2,"2":1}}`), 0644)
	require.NoError(t, err)

	stats, err := LoadQuantitativeRunStats(baselinePath)
	require.NoError(t, err)
	require.Equal(t, 10, stats.Count())
	require.Equal(t, 1, stats.Skipped())
	require.Equal(t, 3, stats.FalsePositives())
	require.Equal(t, map[int]RuleStats{
		920100: {ParanoiaLevel: 1, FalsePositives: 2},
		933100: {ParanoiaLevel: 2, FalsePositives: 1},
	}, stats.falsePositivesPerRule)
	require.Equal(t, map[int]int{1: 2, 2: 1}, stats.falsePositivesPerParanoiaLevel)
	require.Equal(t, 1500*time.Millisecond, stats.TotalTime())
}

func TestLoadQuantitativeRunStatsRejectsUnrelatedJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := dir + "/baseline.json"
	err := os.WriteFile(baselinePath, []byte(`{"unexpected":"value"}`), 0644)
	require.NoError(t, err)

	_, err = LoadQuantitativeRunStats(baselinePath)
	require.Error(t, err)
	require.ErrorContains(t, err, "do not look like quantitative output")
}

func TestQuantitativeRunStatsCompare(t *testing.T) {
	t.Parallel()

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
	require.True(t, comparison.HasRegressions())
	require.Equal(t, 2, comparison.Regressions.FalsePositivesDelta)
	require.Equal(t, RuleDelta{ParanoiaLevel: 1, BaselineFalsePositives: 2, CurrentFalsePositives: 3, Delta: 1}, comparison.Regressions.PerRuleDeltas[920100])
	require.NotContains(t, comparison.Regressions.PerRuleDeltas, 941100)
	require.Equal(t, RuleDelta{ParanoiaLevel: 1, BaselineFalsePositives: 0, CurrentFalsePositives: 1, Delta: 1}, comparison.Regressions.NewlyFiringRules[942100])
	require.Equal(t, RuleDelta{ParanoiaLevel: 2, BaselineFalsePositives: 1, CurrentFalsePositives: 0, Delta: -1}, comparison.Regressions.StoppedFiringRules[933100])
}

func TestComparisonResultPrintSummaryJSON(t *testing.T) {
	t.Parallel()

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
	require.NoError(t, json.Unmarshal(b.Bytes(), &got))
	require.True(t, got.Regressions.Detected)
	require.Equal(t, RuleDelta{ParanoiaLevel: 1, BaselineFalsePositives: 0, CurrentFalsePositives: 1, Delta: 1}, got.Regressions.NewlyFiringRules["920100"])
}
