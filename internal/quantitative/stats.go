// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/output"
)

// RuleStats holds the statistics for a specific rule
type RuleStats struct {
	ParanoiaLevel  int `json:"paranoiaLevel"`
	FalsePositives int `json:"falsePositives"`
}

type quantitativeRunStatsJSON struct {
	Count                               int               `json:"count"`
	Skipped                             int               `json:"skipped"`
	TotalTimeSeconds                    float64           `json:"totalTimeSeconds"`
	FalsePositives                      int               `json:"falsePositives"`
	FalsePositivesPerRule               map[int]RuleStats `json:"falsePositivesPerRule"`
	FalsePositivesPerParanoiaLevel      map[int]int       `json:"falsePositivesPerParanoiaLevel"`
	EvaluatedParanoiaLevels             []int             `json:"evaluatedParanoiaLevels,omitempty"`
	FalsePositiveTotalsPerParanoiaLevel map[int]int       `json:"falsePositiveTotalsPerParanoiaLevel,omitempty"`
}

// RuleDelta holds the comparison for a single rule. The baseline and current
// paranoia levels are tracked separately because the same rule can live at a
// different paranoia level across two CRS versions.
type RuleDelta struct {
	BaselineParanoiaLevel  int `json:"baselineParanoiaLevel"`
	CurrentParanoiaLevel   int `json:"currentParanoiaLevel"`
	BaselineFalsePositives int `json:"baselineFalsePositives"`
	CurrentFalsePositives  int `json:"currentFalsePositives"`
	Delta                  int `json:"delta"`
}

// paranoiaLevel returns the paranoia level to use for display and sorting,
// preferring the current run and falling back to the baseline.
func (d RuleDelta) paranoiaLevel() int {
	if d.CurrentParanoiaLevel != 0 {
		return d.CurrentParanoiaLevel
	}
	return d.BaselineParanoiaLevel
}

// RegressionSummary contains the structured diff between a current run and its baseline.
type RegressionSummary struct {
	Detected            bool              `json:"detected"`
	FalsePositivesDelta int               `json:"falsePositivesDelta"`
	PerRuleDeltas       map[int]RuleDelta `json:"perRuleDeltas"`
	NewlyFiringRules    map[int]RuleDelta `json:"newlyFiringRules"`
	StoppedFiringRules  map[int]RuleDelta `json:"stoppedFiringRules"`
}

// ComparisonResult holds both quantitative runs and their diff.
type ComparisonResult struct {
	Baseline    *QuantitativeRunStats `json:"baseline"`
	Current     *QuantitativeRunStats `json:"current"`
	Regressions RegressionSummary     `json:"regressions"`
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
	// evaluatedOrderedParanoiaLevels are the paranoia levels requested for reporting cumulative totals.
	evaluatedOrderedParanoiaLevels []int
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

	if len(s.evaluatedOrderedParanoiaLevels) > 1 {
		highestParanoiaLevel := s.evaluatedOrderedParanoiaLevels[len(s.evaluatedOrderedParanoiaLevels)-1]
		ratio := s.falsePositiveRatio(s.falsePositives)
		out.Println("Total False positive ratio at PL%d: %d/%d = %.4f", highestParanoiaLevel, s.falsePositives, s.count_, ratio)
		s.printEvaluatedParanoiaLevelTotals(out)
	} else if s.falsePositives != 0 {
		ratio := s.falsePositiveRatio(s.falsePositives)
		out.Println("Total False positive ratio: %d/%d = %.4f", s.falsePositives, s.count_, ratio)
	}

	// Extract and sort the rule IDs
	ruleIDs := slices.Collect(maps.Keys(s.falsePositivesPerRule))
	slices.SortFunc(ruleIDs, func(i, j int) int {
		// First sort by paranoia level and then by rule ID
		plSort := s.falsePositivesPerRule[i].ParanoiaLevel - s.falsePositivesPerRule[j].ParanoiaLevel
		if plSort != 0 {
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

// Compare returns the structured diff between the current stats and the baseline.
func (s *QuantitativeRunStats) Compare(baseline *QuantitativeRunStats) ComparisonResult {
	perRuleDeltas := make(map[int]RuleDelta)
	newlyFiringRules := make(map[int]RuleDelta)
	stoppedFiringRules := make(map[int]RuleDelta)

	ruleIDs := make([]int, 0, len(s.falsePositivesPerRule)+len(baseline.falsePositivesPerRule))
	for ruleID := range s.falsePositivesPerRule {
		ruleIDs = append(ruleIDs, ruleID)
	}
	for ruleID := range baseline.falsePositivesPerRule {
		ruleIDs = append(ruleIDs, ruleID)
	}

	slices.Sort(ruleIDs)
	ruleIDs = slices.Compact(ruleIDs)
	for _, ruleID := range ruleIDs {
		currentRuleStats, hasCurrent := s.falsePositivesPerRule[ruleID]
		baselineRuleStats, hasBaseline := baseline.falsePositivesPerRule[ruleID]

		ruleDelta := RuleDelta{
			BaselineParanoiaLevel:  baselineRuleStats.ParanoiaLevel,
			CurrentParanoiaLevel:   currentRuleStats.ParanoiaLevel,
			BaselineFalsePositives: baselineRuleStats.FalsePositives,
			CurrentFalsePositives:  currentRuleStats.FalsePositives,
			Delta:                  currentRuleStats.FalsePositives - baselineRuleStats.FalsePositives,
		}
		perRuleDeltas[ruleID] = ruleDelta

		switch {
		case !hasBaseline && hasCurrent:
			newlyFiringRules[ruleID] = ruleDelta
		case hasBaseline && !hasCurrent:
			stoppedFiringRules[ruleID] = ruleDelta
		}
	}

	return ComparisonResult{
		Baseline: baseline,
		Current:  s,
		Regressions: RegressionSummary{
			Detected:            hasRegressions(perRuleDeltas),
			FalsePositivesDelta: s.falsePositives - baseline.falsePositives,
			PerRuleDeltas:       perRuleDeltas,
			NewlyFiringRules:    newlyFiringRules,
			StoppedFiringRules:  stoppedFiringRules,
		},
	}
}

// HasRegressions reports whether the comparison contains regressions.
func (r ComparisonResult) HasRegressions() bool {
	return r.Regressions.Detected
}

// PrintSummary prints the structured comparison.
func (r ComparisonResult) PrintSummary(out *output.Output) {
	if out.IsJson() {
		r.printJSON(out)
		return
	}
	r.printPretty(out)
}

func (r ComparisonResult) printJSON(out *output.Output) {
	b, err := json.Marshal(r)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal comparison to JSON")
		return
	}
	out.RawPrint(string(b))
}

func (r ComparisonResult) printPretty(out *output.Output) {
	out.Println("Current quantitative results:")
	r.Current.printSummary(out)
	out.Println("")
	out.Println("Baseline quantitative results:")
	r.Baseline.printSummary(out)
	out.Println("")
	out.Println("Comparison:")
	out.Println("Total false positive delta: %d", r.Regressions.FalsePositivesDelta)
	printRuleDeltaSection(out, "Per-rule deltas:", r.Regressions.PerRuleDeltas)
	printRuleDeltaSection(out, "Newly firing rules:", r.Regressions.NewlyFiringRules)
	printRuleDeltaSection(out, "Stopped firing rules:", r.Regressions.StoppedFiringRules)
	if r.Regressions.Detected {
		out.Println("Regressions detected")
		return
	}
	out.Println("No regressions detected")
}

// LoadQuantitativeRunStats loads previously emitted quantitative JSON results.
func LoadQuantitativeRunStats(path string) (*QuantitativeRunStats, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var serialized quantitativeRunStatsJSON
	if err := json.Unmarshal(b, &serialized); err != nil {
		return nil, fmt.Errorf("failed to decode baseline results %s: %w", path, err)
	}

	if serialized.FalsePositivesPerRule == nil {
		serialized.FalsePositivesPerRule = make(map[int]RuleStats)
	}
	if serialized.FalsePositivesPerParanoiaLevel == nil {
		serialized.FalsePositivesPerParanoiaLevel = make(map[int]int)
	}

	return &QuantitativeRunStats{
		count_:                         serialized.Count,
		skipped_:                       serialized.Skipped,
		totalTime:                      time.Duration(serialized.TotalTimeSeconds * float64(time.Second)),
		falsePositives:                 serialized.FalsePositives,
		falsePositivesPerRule:          serialized.FalsePositivesPerRule,
		falsePositivesPerParanoiaLevel: serialized.FalsePositivesPerParanoiaLevel,
		mu:                             sync.Mutex{},
	}, nil
}

func (s *QuantitativeRunStats) printEvaluatedParanoiaLevelTotals(out *output.Output) {
	out.Println("False positive totals by evaluated paranoia level:")
	for _, paranoiaLevel := range s.evaluatedOrderedParanoiaLevels {
		count := s.cumulativeFalsePositives(paranoiaLevel)
		out.Println("  PL%d: %d false positives. FP Ratio: %d/%d = %.4f", paranoiaLevel, count, count, s.count_, s.falsePositiveRatio(count))
	}
}

func (s *QuantitativeRunStats) cumulativeFalsePositives(paranoiaLevel int) int {
	total := 0
	for level := 1; level <= paranoiaLevel; level++ {
		total += s.falsePositivesPerParanoiaLevel[level]
	}
	return total
}

func (s *QuantitativeRunStats) falsePositiveRatio(count int) float64 {
	if s.count_ == 0 {
		return 0
	}
	return float64(count) / float64(s.count_)
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

// SetEvaluatedParanoiaLevels sets the ordered paranoia levels requested for reporting.
func (s *QuantitativeRunStats) SetEvaluatedParanoiaLevels(orderedLevels []int) {
	s.evaluatedOrderedParanoiaLevels = slices.Clone(orderedLevels)
}

// MarshalJSON marshals the stats to JSON.
func (s *QuantitativeRunStats) MarshalJSON() ([]byte, error) {
	serialized := quantitativeRunStatsJSON{
		Count:                          s.count_,
		Skipped:                        s.skipped_,
		TotalTimeSeconds:               s.totalTime.Seconds(),
		FalsePositives:                 s.falsePositives,
		FalsePositivesPerRule:          s.falsePositivesPerRule,
		FalsePositivesPerParanoiaLevel: s.falsePositivesPerParanoiaLevel,
	}
	if len(s.evaluatedOrderedParanoiaLevels) > 1 {
		totals := make(map[int]int, len(s.evaluatedOrderedParanoiaLevels))
		for _, paranoiaLevel := range s.evaluatedOrderedParanoiaLevels {
			totals[paranoiaLevel] = s.cumulativeFalsePositives(paranoiaLevel)
		}
		serialized.EvaluatedParanoiaLevels = s.evaluatedOrderedParanoiaLevels
		serialized.FalsePositiveTotalsPerParanoiaLevel = totals
	}
	return json.Marshal(serialized)
}

func hasRegressions(perRuleDeltas map[int]RuleDelta) bool {
	for _, delta := range perRuleDeltas {
		if delta.Delta > 0 {
			return true
		}
	}
	return false
}

func printRuleDeltaSection(out *output.Output, title string, deltas map[int]RuleDelta) {
	out.Println(title)
	if len(deltas) == 0 {
		out.Println("  none")
		return
	}

	ruleIDs := slices.Collect(maps.Keys(deltas))
	slices.SortFunc(ruleIDs, func(i, j int) int {
		plSort := deltas[i].paranoiaLevel() - deltas[j].paranoiaLevel()
		if plSort != 0 {
			return plSort
		}
		return i - j
	})

	for _, ruleID := range ruleIDs {
		delta := deltas[ruleID]
		out.Println("  %d (%s): baseline=%d current=%d delta=%+d", ruleID, delta.paranoiaLevelLabel(), delta.BaselineFalsePositives, delta.CurrentFalsePositives, delta.Delta)
	}
}

// paranoiaLevelLabel renders the paranoia level for display, showing both
// levels when the rule moved between paranoia levels across the two runs.
func (d RuleDelta) paranoiaLevelLabel() string {
	if d.BaselineParanoiaLevel != 0 && d.CurrentParanoiaLevel != 0 && d.BaselineParanoiaLevel != d.CurrentParanoiaLevel {
		return fmt.Sprintf("baseline PL%d, current PL%d", d.BaselineParanoiaLevel, d.CurrentParanoiaLevel)
	}
	return fmt.Sprintf("PL%d", d.paranoiaLevel())
}
