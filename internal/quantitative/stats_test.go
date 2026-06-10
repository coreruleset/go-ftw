// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
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
			want:    []byte(`{"count":1,"falsePositives":1,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"920010":{"paranoiaLevel":1,"falsePositives":1}},"ignoredFalsePositives":0,"skipped":0,"totalTimeSeconds":1}`),
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
			want:    []byte(`{"count":2,"falsePositives":2,"falsePositivesPerParanoiaLevel":null,"falsePositivesPerRule":{"933100":{"paranoiaLevel":1,"falsePositives":2}},"ignoredFalsePositives":0,"skipped":0,"totalTimeSeconds":2}`),
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
			s.Require().Equal(got, tt.want)
		})
	}
}

func (s *statsTestSuite) TestQuantitativeRunStats_functions() {
	q := NewQuantitativeStats(nil)

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
	q := NewQuantitativeStats(nil)

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
	q := NewQuantitativeStats(nil)

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100, 1)
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.Skipped(), 0)

	q.printSummary(out)
	s.Require().Equal(`{"count":1,"falsePositives":1,"falsePositivesPerParanoiaLevel":{"1":1},"falsePositivesPerRule":{"920100":{"paranoiaLevel":1,"falsePositives":1}},"ignoredFalsePositives":0,"skipped":0,"totalTimeSeconds":0}`, b.String())
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
