// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"encoding/json"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/output"
)

// RuleStats holds the statistics for a specific rule
type RuleStats struct {
	ParanoiaLevel  int  `json:"paranoiaLevel"`
	FalsePositives int  `json:"falsePositives"`
	Ignored        bool `json:"ignored,omitempty"`
}

// QuantitativeRunStats accumulates test statistics.
type QuantitativeRunStats struct {
	// count_ is the amount of tests executed in this run.
	count_ int
	// skipped_ is the amount of tests skipped in this run.
	skipped_ int
	// totalTime is the duration over all runs, the sum of all individual run times.
	totalTime time.Duration
	// falsePositives is the total false positives detected (excludes ignored rules)
	falsePositives int
	// ignoredFalsePositives is the total false positives for ignored rules (not counted in aggregate)
	ignoredFalsePositives int
	// falsePositivesPerRule is the aggregated false positives per rule (key is rule ID)
	falsePositivesPerRule map[int]RuleStats
	// falsePositivesPerParanoiaLevel is the aggregated false positives per paranoia level (excludes ignored rules)
	falsePositivesPerParanoiaLevel map[int]int
	// ignoredRules is the set of rule IDs whose false positives are excluded from aggregate metrics
	ignoredRules map[int]struct{}
	// mu is the mutex to protect the falsePositivesPerRule and falsePositivesPerParanoiaLevel maps
	mu sync.Mutex
}

// NewQuantitativeStats returns a new empty stats.
// ignoreRules is an optional list of rule IDs to exclude from aggregate false-positive metrics.
func NewQuantitativeStats(ignoreRules []int) *QuantitativeRunStats {
	ignoredRulesSet := make(map[int]struct{}, len(ignoreRules))
	for _, r := range ignoreRules {
		ignoredRulesSet[r] = struct{}{}
	}
	return &QuantitativeRunStats{
		count_:                         0,
		falsePositives:                 0,
		ignoredFalsePositives:          0,
		falsePositivesPerRule:          make(map[int]RuleStats),
		falsePositivesPerParanoiaLevel: make(map[int]int),
		ignoredRules:                   ignoredRulesSet,
		totalTime:                      0,
		mu:                             sync.Mutex{},
	}
}

// print final statistics
func (s *QuantitativeRunStats) printSummary(out *output.Output) {
	log.Debug().Msg("Printing Stats summary")
	if out.IsJson() {
		b, err := json.Marshal(s)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal stats to JSON")
			return
		}
		out.RawPrint(string(b))
		return
	}

	out.Println("Run %d payloads (%d skipped) in %s", s.count_, s.skipped_, s.totalTime)

	if s.falsePositives == 0 && s.ignoredFalsePositives == 0 {
		out.Println("No false positives detected with the passed corpus")
		return
	}

	// Separate per-rule IDs into regular and ignored
	var regularRuleIDs, ignoredRuleIDs []int
	for ruleID, ruleStats := range s.falsePositivesPerRule {
		if ruleStats.Ignored {
			ignoredRuleIDs = append(ignoredRuleIDs, ruleID)
		} else {
			regularRuleIDs = append(regularRuleIDs, ruleID)
		}
	}
	sortRuleIDsByPLThenID := func(ids []int) {
		slices.SortFunc(ids, func(i, j int) int {
			plSort := s.falsePositivesPerRule[i].ParanoiaLevel - s.falsePositivesPerRule[j].ParanoiaLevel
			if plSort != 0 {
				return plSort
			}
			return i - j
		})
	}
	sortRuleIDsByPLThenID(regularRuleIDs)
	sortRuleIDsByPLThenID(ignoredRuleIDs)

	if s.falsePositives > 0 {
		ratio := float64(s.falsePositives) / float64(s.count_)
		if s.ignoredFalsePositives > 0 {
			out.Println("Total False positive ratio: %d/%d = %.4f (%d FPs from %d ignored rules not counted)", s.falsePositives, s.count_, ratio, s.ignoredFalsePositives, len(ignoredRuleIDs))
		} else {
			out.Println("Total False positive ratio: %d/%d = %.4f", s.falsePositives, s.count_, ratio)
		}

		out.Println("False positives per paranoia level:")
		paranoiaLevels := slices.Sorted(maps.Keys(s.falsePositivesPerParanoiaLevel))
		for _, pl := range paranoiaLevels {
			count := s.falsePositivesPerParanoiaLevel[pl]
			perPLRatio := float64(count) / float64(s.count_)
			out.Println("  PL%d: %d false positives. FP Ratio: %d/%d = %.4f", pl, count, count, s.count_, perPLRatio)
		}

		out.Println("False positives per rule id:")
		for _, ruleID := range regularRuleIDs {
			ruleStats := s.falsePositivesPerRule[ruleID]
			perRuleRatio := float64(ruleStats.FalsePositives) / float64(s.count_)
			out.Println("  %d (PL%d): %d false positives. FP Ratio: %d/%d = %.4f", ruleID, ruleStats.ParanoiaLevel, ruleStats.FalsePositives, ruleStats.FalsePositives, s.count_, perRuleRatio)
		}
	} else if s.ignoredFalsePositives > 0 {
		out.Println("No false positives detected (excluding %d ignored rules)", len(ignoredRuleIDs))
	}

	if s.ignoredFalsePositives > 0 {
		out.Println("False positives for ignored rules (not counted in aggregate):")
		for _, ruleID := range ignoredRuleIDs {
			ruleStats := s.falsePositivesPerRule[ruleID]
			perRuleRatio := float64(ruleStats.FalsePositives) / float64(s.count_)
			out.Println("  %d (PL%d): %d false positives. FP Ratio: %d/%d = %.4f", ruleID, ruleStats.ParanoiaLevel, ruleStats.FalsePositives, ruleStats.FalsePositives, s.count_, perRuleRatio)
		}
	}
}

// addFalsePositive increments the false positive count, the false positive count for the rule
// and the false positive count for the paranoia level.
// If the rule is in the ignored rules set, only the per-rule counter is updated (not the aggregate).
func (s *QuantitativeRunStats) addFalsePositive(ruleID int, paranoiaLevel int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, isIgnored := s.ignoredRules[ruleID]
	if isIgnored {
		s.ignoredFalsePositives++
	} else {
		s.falsePositives++
		s.falsePositivesPerParanoiaLevel[paranoiaLevel]++
	}
	if stats, exists := s.falsePositivesPerRule[ruleID]; exists {
		stats.FalsePositives++
		s.falsePositivesPerRule[ruleID] = stats
		return
	}
	s.falsePositivesPerRule[ruleID] = RuleStats{
		ParanoiaLevel:  paranoiaLevel,
		FalsePositives: 1,
		Ignored:        isIgnored,
	}
}

// FalsePositives returns the total false positives detected
func (s *QuantitativeRunStats) FalsePositives() int {
	return s.falsePositives
}

// incrementRun increments the amount of tests executed in this run.
func (s *QuantitativeRunStats) incrementRun() {
	s.count_++
}

// incrementSkip increments the amount of tests skipped in this run.
func (s *QuantitativeRunStats) incrementSkip() {
	s.skipped_++
}

// Count returns the amount of tests executed in this run.
func (s *QuantitativeRunStats) Count() int {
	return s.count_
}

// Skipped returns the amount of tests skipped in this run.
func (s *QuantitativeRunStats) Skipped() int {
	return s.skipped_
}

// TotalTime returns the duration over all runs, the sum of all individual run times.
func (s *QuantitativeRunStats) TotalTime() time.Duration {
	return s.totalTime
}

// SetTotalTime sets the duration over all runs, the sum of all individual run times.
func (s *QuantitativeRunStats) SetTotalTime(totalTime time.Duration) {
	s.totalTime = totalTime
}

// MarshalJSON marshals the stats to JSON.
func (s *QuantitativeRunStats) MarshalJSON() ([]byte, error) {
	// Custom marshaling logic here
	return json.Marshal(map[string]interface{}{
		"count":                          s.count_,
		"skipped":                        s.skipped_,
		"totalTimeSeconds":               s.totalTime.Seconds(),
		"falsePositives":                 s.falsePositives,
		"ignoredFalsePositives":          s.ignoredFalsePositives,
		"falsePositivesPerRule":          s.falsePositivesPerRule,
		"falsePositivesPerParanoiaLevel": s.falsePositivesPerParanoiaLevel,
	})
}
