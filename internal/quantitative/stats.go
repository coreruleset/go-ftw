// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"slices"
	"strings"
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

type quantitativeRunStatsJSON struct {
	CorpusSize                          int               `json:"corpusSize"`
	Count                               int               `json:"count"`
	Skipped                             int               `json:"skipped"`
	TotalTimeSeconds                    float64           `json:"totalTimeSeconds"`
	FalsePositives                      int               `json:"falsePositives"`
	IgnoredFalsePositives               int               `json:"ignoredFalsePositives,omitempty"`
	FalsePositiveSentences              int               `json:"falsePositiveSentences"`
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
	// falsePositives is the total false positives detected (excludes ignored rules; rule-hit count, one
	// sentence can contribute multiple hits)
	falsePositives int
	// ignoredFalsePositives is the total false positives for ignored rules (not counted in aggregate)
	ignoredFalsePositives int
	// falsePositiveSentences is the number of distinct corpus sentences that triggered at least one rule
	falsePositiveSentences int
	// falsePositivesPerRule is the aggregated false positives per rule (key is rule ID)
	falsePositivesPerRule map[int]RuleStats
	// falsePositivesPerParanoiaLevel is the aggregated false positives per paranoia level (excludes ignored rules)
	falsePositivesPerParanoiaLevel map[int]int
	// ignoredRules is the set of rule IDs whose false positives are excluded from aggregate metrics
	ignoredRules map[int]struct{}
	// evaluatedParanoiaLevels are the paranoia levels requested for reporting cumulative totals.
	evaluatedParanoiaLevels ParanoiaLevels
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
		falsePositiveSentences:         0,
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
	if out.IsMarkdown() {
		out.RawPrint(s.markdownSummary())
		return
	}

	out.Println("Run %d payloads (%d skipped) in %s", s.count_, s.skipped_, s.totalTime)

	if s.falsePositives == 0 && s.ignoredFalsePositives == 0 {
		out.Println("No false positives detected with the passed corpus")
		return
	}

	regularRuleIDs, ignoredRuleIDs := s.sortedRuleIDsByStatus()

	s.printFalsePositiveRatio(out, len(ignoredRuleIDs))
	if s.evaluatedParanoiaLevels.Len() > 1 {
		s.printEvaluatedParanoiaLevelTotals(out)
	}

	sentenceRatio := s.falsePositiveRatio(s.falsePositiveSentences)
	out.Println("Total False positive sentences: %d/%d = %.4f", s.falsePositiveSentences, s.count_, sentenceRatio)

	if s.falsePositives > 0 {
		s.printFalsePositivesPerParanoiaLevel(out)
		s.printRuleStatsSection(out, "False positives per rule id:", regularRuleIDs)
	}
	if s.ignoredFalsePositives > 0 {
		s.printRuleStatsSection(out, "False positives for ignored rules (not counted in aggregate):", ignoredRuleIDs)
	}
}

// sortedRuleIDsByStatus splits the per-rule false positive IDs into regular and ignored
// buckets, each sorted by paranoia level and then rule ID.
func (s *QuantitativeRunStats) sortedRuleIDsByStatus() (regular, ignored []int) {
	for ruleID, ruleStats := range s.falsePositivesPerRule {
		if ruleStats.Ignored {
			ignored = append(ignored, ruleID)
		} else {
			regular = append(regular, ruleID)
		}
	}
	sortByPLThenID := func(ids []int) {
		slices.SortFunc(ids, func(i, j int) int {
			plSort := s.falsePositivesPerRule[i].ParanoiaLevel - s.falsePositivesPerRule[j].ParanoiaLevel
			if plSort != 0 {
				return plSort
			}
			return i - j
		})
	}
	sortByPLThenID(regular)
	sortByPLThenID(ignored)
	return regular, ignored
}

// printFalsePositiveRatio prints the total false positive ratio line, noting the highest
// evaluated paranoia level and/or the ignored-rule counts when applicable.
func (s *QuantitativeRunStats) printFalsePositiveRatio(out *output.Output, ignoredRuleCount int) {
	if s.falsePositives == 0 {
		if s.ignoredFalsePositives > 0 {
			out.Println("No false positives detected (excluding %d ignored rules)", ignoredRuleCount)
		}
		return
	}

	ratio := s.falsePositiveRatio(s.falsePositives)
	multiPL := s.evaluatedParanoiaLevels.Len() > 1
	switch {
	case multiPL && s.ignoredFalsePositives > 0:
		out.Println("Total False positive ratio at PL%d: %d/%d = %.4f (%d FPs from %d ignored rules not counted)",
			s.evaluatedParanoiaLevels.Highest(), s.falsePositives, s.count_, ratio, s.ignoredFalsePositives, ignoredRuleCount)
	case multiPL:
		out.Println("Total False positive ratio at PL%d: %d/%d = %.4f", s.evaluatedParanoiaLevels.Highest(), s.falsePositives, s.count_, ratio)
	case s.ignoredFalsePositives > 0:
		out.Println("Total False positive ratio: %d/%d = %.4f (%d FPs from %d ignored rules not counted)", s.falsePositives, s.count_, ratio, s.ignoredFalsePositives, ignoredRuleCount)
	default:
		out.Println("Total False positive ratio: %d/%d = %.4f", s.falsePositives, s.count_, ratio)
	}
}

// printFalsePositivesPerParanoiaLevel prints the per-paranoia-level false positive breakdown.
func (s *QuantitativeRunStats) printFalsePositivesPerParanoiaLevel(out *output.Output) {
	out.Println("False positives per paranoia level:")
	paranoiaLevels := slices.Sorted(maps.Keys(s.falsePositivesPerParanoiaLevel))
	for _, pl := range paranoiaLevels {
		count := s.falsePositivesPerParanoiaLevel[pl]
		perPLRatio := float64(count) / float64(s.count_)
		out.Println("  PL%d: %d false positives. FP Ratio: %d/%d = %.4f", pl, count, count, s.count_, perPLRatio)
	}
}

// printRuleStatsSection prints a titled per-rule false positive breakdown for the given rule IDs.
func (s *QuantitativeRunStats) printRuleStatsSection(out *output.Output, title string, ruleIDs []int) {
	out.Println(title)
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
		falsePositiveSentences:         serialized.FalsePositiveSentences,
		falsePositivesPerRule:          serialized.FalsePositivesPerRule,
		falsePositivesPerParanoiaLevel: serialized.FalsePositivesPerParanoiaLevel,
		mu:                             sync.Mutex{},
	}, nil
}

func (s *QuantitativeRunStats) printEvaluatedParanoiaLevelTotals(out *output.Output) {
	out.Println("False positive totals by evaluated paranoia level:")
	for _, paranoiaLevel := range s.evaluatedParanoiaLevels.All() {
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

func (s *QuantitativeRunStats) markdownSummary() string {
	var summary strings.Builder

	summary.WriteString("## Quantitative test results\n\n")
	if s.falsePositives == 0 {
		summary.WriteString("✅ Quantitative testing did not detect false positives.\n\n")
	} else {
		summary.WriteString("⚠️ Quantitative testing detected false positives.\n\n")
	}

	summary.WriteString("| Metric | Value |\n")
	summary.WriteString("|--------|-------|\n")
	fmt.Fprintf(&summary, "| Payloads run | %d |\n", s.count_)
	fmt.Fprintf(&summary, "| Skipped payloads | %d |\n", s.skipped_)
	fmt.Fprintf(&summary, "| False positives | %d |\n", s.falsePositives)
	fmt.Fprintf(&summary, "| Duration | %s |\n", s.totalTime)

	ratio := 0.0
	if s.count_ > 0 {
		ratio = float64(s.falsePositives) / float64(s.count_)
	}
	fmt.Fprintf(&summary, "| False positive ratio | %d/%d = %.4f |\n", s.falsePositives, s.count_, ratio)

	summary.WriteString("\n### False positives per rule\n\n")

	if len(s.falsePositivesPerRule) == 0 {
		summary.WriteString("_No false positives detected._\n")
		return summary.String()
	}

	ruleIDs := slices.Collect(maps.Keys(s.falsePositivesPerRule))
	slices.SortFunc(ruleIDs, func(i, j int) int {
		plSort := s.falsePositivesPerRule[i].ParanoiaLevel - s.falsePositivesPerRule[j].ParanoiaLevel
		if plSort != 0 {
			return plSort
		}
		return i - j
	})

	summary.WriteString("| Rule ID | PL | False positives | Ratio |\n")
	summary.WriteString("|---------|----|-----------------|-------|\n")
	for _, ruleID := range ruleIDs {
		ruleStats := s.falsePositivesPerRule[ruleID]
		perRuleRatio := 0.0
		if s.count_ > 0 {
			perRuleRatio = float64(ruleStats.FalsePositives) / float64(s.count_)
		}
		fmt.Fprintf(&summary, "| %d | %d | %d | %d/%d = %.4f |\n", ruleID, ruleStats.ParanoiaLevel, ruleStats.FalsePositives, ruleStats.FalsePositives, s.count_, perRuleRatio)
	}

	return summary.String()
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

// addFalsePositiveSentence increments the count of distinct sentences that triggered at least one rule.
func (s *QuantitativeRunStats) addFalsePositiveSentence() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.falsePositiveSentences++
}

// FalsePositives returns the total false positives detected (rule-hit count)
func (s *QuantitativeRunStats) FalsePositives() int {
	return s.falsePositives
}

// FalsePositiveSentences returns the number of distinct sentences that triggered at least one rule.
func (s *QuantitativeRunStats) FalsePositiveSentences() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.falsePositiveSentences
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

// SetEvaluatedParanoiaLevels sets the paranoia levels requested for reporting.
func (s *QuantitativeRunStats) SetEvaluatedParanoiaLevels(levels ParanoiaLevels) {
	s.evaluatedParanoiaLevels = levels
}

// MarshalJSON marshals the stats to JSON.
func (s *QuantitativeRunStats) MarshalJSON() ([]byte, error) {
	serialized := quantitativeRunStatsJSON{
		CorpusSize:                     s.count_ + s.skipped_,
		Count:                          s.count_,
		Skipped:                        s.skipped_,
		TotalTimeSeconds:               math.Round(s.totalTime.Seconds()*1e4) / 1e4,
		FalsePositives:                 s.falsePositives,
		IgnoredFalsePositives:          s.ignoredFalsePositives,
		FalsePositiveSentences:         s.falsePositiveSentences,
		FalsePositivesPerRule:          s.falsePositivesPerRule,
		FalsePositivesPerParanoiaLevel: s.falsePositivesPerParanoiaLevel,
	}
	if s.evaluatedParanoiaLevels.Len() > 1 {
		evaluatedLevels := s.evaluatedParanoiaLevels.All()
		totals := make(map[int]int, len(evaluatedLevels))
		for _, paranoiaLevel := range evaluatedLevels {
			totals[paranoiaLevel] = s.cumulativeFalsePositives(paranoiaLevel)
		}
		serialized.EvaluatedParanoiaLevels = evaluatedLevels
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
