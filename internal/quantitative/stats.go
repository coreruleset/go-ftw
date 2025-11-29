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

	"github.com/coreruleset/go-ftw/output"
)

// RuleStats holds the statistics for a specific rule
type RuleStats struct {
	ParanoiaLevel  int `json:"paranoiaLevel"`
	FalsePositives int `json:"falsePositives"`
}

// QuantitativeRunStats accumulates test statistics.
type QuantitativeRunStats struct {
	// count_ is the amount of tests executed in this run.
	count_ int
	// skipped_ is the amount of tests skipped in this run.
	skipped_ int
	// totalTime is the duration over all runs, the sum of all individual run times.
	totalTime time.Duration
	// falsePositives is the total false positives detected
	falsePositives int
	// falsePositivesPerRule is the aggregated false positives per rule (key is rule ID)
	falsePositivesPerRule map[int]RuleStats
	// falsePositivesPerParanoiaLevel is the aggregated false positives per paranoia level
	falsePositivesPerParanoiaLevel map[int]int
	// mu is the mutex to protect the falsePositivesPerRule and falsePositivesPerParanoiaLevel maps
	mu sync.Mutex
}

// NewQuantitativeStats returns a new empty stats
func NewQuantitativeStats() *QuantitativeRunStats {
	return &QuantitativeRunStats{
		count_:                         0,
		falsePositives:                 0,
		falsePositivesPerRule:          make(map[int]RuleStats),
		falsePositivesPerParanoiaLevel: make(map[int]int),
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

	if s.falsePositives == 0 {
		out.Println("No false positives detected with the passed corpus")
		return
	}

	ratio := float64(s.falsePositives) / float64(s.count_)
	out.Println("Total False positive ratio: %d/%d = %.4f", s.falsePositives, s.count_, ratio)
	// Extract and sort the rule IDs
	ruleIDs := slices.Sorted(maps.Keys(s.falsePositivesPerRule))
	slices.SortFunc(ruleIDs, func(i, j int) int {
		// First sort by paranoia level and then by rule ID
		plSort := s.falsePositivesPerRule[i].ParanoiaLevel - s.falsePositivesPerRule[j].ParanoiaLevel
		if plSort > 0 {
			return plSort
		}
		return i - j
	})

	out.Println("False positives per paranoia level:")
	paranoiaLevels := slices.Sorted(maps.Keys(s.falsePositivesPerParanoiaLevel))

	// Print sorted paranoia levels
	for _, pl := range paranoiaLevels {
		count := s.falsePositivesPerParanoiaLevel[pl]
		perPLRatio := float64(count) / float64(s.count_)
		out.Println("  PL%d: %d false positives. FP Ratio: %d/%d = %.4f", pl, count, count, s.count_, perPLRatio)
	}
	out.Println("False positives per rule id:")

	// Print the sorted false positives map
	for _, ruleID := range ruleIDs {
		ruleStats := s.falsePositivesPerRule[ruleID]
		perRuleRatio := float64(ruleStats.FalsePositives) / float64(s.count_)
		out.Println("  %d (PL%d): %d false positives. FP Ratio: %d/%d = %.4f", ruleID, ruleStats.ParanoiaLevel, ruleStats.FalsePositives, ruleStats.FalsePositives, s.count_, perRuleRatio)
	}

}

// addFalsePositive increments the false positive count, the false positive count for the rule
// and the false positive count for the paranoia level.
func (s *QuantitativeRunStats) addFalsePositive(ruleID int, paranoiaLevel int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.falsePositives++
	s.falsePositivesPerParanoiaLevel[paranoiaLevel]++
	if stats, exists := s.falsePositivesPerRule[ruleID]; exists {
		stats.FalsePositives++
		s.falsePositivesPerRule[ruleID] = stats
		return
	}
	s.falsePositivesPerRule[ruleID] = RuleStats{
		ParanoiaLevel:  paranoiaLevel,
		FalsePositives: 1,
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
		"falsePositivesPerRule":          s.falsePositivesPerRule,
		"falsePositivesPerParanoiaLevel": s.falsePositivesPerParanoiaLevel,
	})
}
