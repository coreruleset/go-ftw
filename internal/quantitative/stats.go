// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/output"
)

// RunStats accumulates test statistics.
type QuantitativeRunStats struct {
	// count_ is the amount of tests executed in this run.
	count_ int
	// totalTime is the duration over all runs, the sum of all individual run times.
	totalTime time.Duration
	// falsePositives is the total false positives detected
	falsePositives int
	// falsePositivesPerRule is the aggregated false positives per rule
	falsePositivesPerRule map[int]int
	// mu is the mutex to protect the falsePositivesPerRule map
	mu sync.Mutex
}

// NewQuantitativeStats returns a new empty stats
func NewQuantitativeStats() *QuantitativeRunStats {
	return &QuantitativeRunStats{
		count_:                0,
		falsePositives:        0,
		falsePositivesPerRule: make(map[int]int),
		totalTime:             0,
		mu:                    sync.Mutex{},
	}
}

// print final statistics
func (s *QuantitativeRunStats) printSummary(out *output.Output) {
	log.Debug().Msg("Printing Stats summary")
	if s.falsePositives > 0 {
		if out.IsJson() {
			b, _ := json.Marshal(s)
			out.RawPrint(string(b))
		} else {
			ratio := float64(s.falsePositives) / float64(s.count_)
			out.Println("Run %d payloads in %s", s.count_, s.totalTime)
			out.Println("Total False positive ratio: %d/%d = %.4f", s.falsePositives, s.count_, ratio)
			out.Println("False positives per rule id:")
			// Extract and sort the keys
			rules := make([]int, 0, len(s.falsePositivesPerRule))
			for rule := range s.falsePositivesPerRule {
				rules = append(rules, rule)
			}
			sort.Ints(rules)

			// Print the sorted map
			for _, rule := range rules {
				count := s.falsePositivesPerRule[rule]
				perRuleRatio := float64(count) / float64(s.count_)
				out.Println("  %d: %d false positives. FP Ratio: %d/%d = %.4f", rule, count, count, s.count_, perRuleRatio)
			}
		}
	} else {
		out.Println("No false positives detected with the passed corpus")
	}
}

// addFalsePositive increments the false positive count and the false positive count for the rule.
func (s *QuantitativeRunStats) addFalsePositive(rule int) {
	s.mu.Lock()
	s.falsePositives++
	s.falsePositivesPerRule[rule]++
	s.mu.Unlock()
}

// FalsePositives returns the total false positives detected
func (s *QuantitativeRunStats) FalsePositives() int {
	return s.falsePositives
}

// incrementRun increments the amount of tests executed in this run.
func (s *QuantitativeRunStats) incrementRun() {
	s.count_++
}

// Count returns the amount of tests executed in this run.
func (s *QuantitativeRunStats) Count() int {
	return s.count_
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
		"count":                 s.count_,
		"totalTimeSeconds":      s.totalTime.Seconds(),
		"falsePositives":        s.falsePositives,
		"falsePositivesPerRule": s.falsePositivesPerRule,
	})
}
