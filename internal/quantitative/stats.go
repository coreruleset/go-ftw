package quantitative

import (
	"encoding/json"
	"github.com/coreruleset/go-ftw/output"
	"github.com/rs/zerolog/log"
	"time"
)

// RunStats accumulates test statistics.
type QuantitativeRunStats struct {
	// Run is the amount of tests executed in this run.
	Run int `json:"run"`
	// TotalTime is the duration over all runs, the sum of all individual run times.
	TotalTime time.Duration
	// FalsePositives is the total false positives detected
	FalsePositives int `json:"falsePositives"`
	// FalsePositivesPerRule is the aggregated false positives per rule
	FalsePositivesPerRule map[int]int `json:"falsePositivesPerRule"`
}

// NewQuantitativeStats returns a new empty stats
func NewQuantitativeStats() *QuantitativeRunStats {
	return &QuantitativeRunStats{
		Run:                   0,
		FalsePositives:        0,
		FalsePositivesPerRule: make(map[int]int),
		TotalTime:             0,
	}
}

// print final statistics
func (s *QuantitativeRunStats) printSummary(out *output.Output) {
	log.Debug().Msg("Printing Stats summary")
	if s.FalsePositives > 0 {
		if out.IsJson() {
			b, _ := json.Marshal(s)
			out.RawPrint(string(b))
		} else {
			ratio := float64(s.FalsePositives) / float64(s.Run)
			out.Println("Run %d payloads in %s", s.Run, s.TotalTime)
			out.Println("Total False positive ratio: %d/%d = %.4f", s.FalsePositives, s.Run, ratio)
			out.Println("False positives per rule: %+v", s.FalsePositivesPerRule)
			// echo "| Freq.  | ID #   | Paranoia Level |"
			// echo "| ------ | ------ | -------------- |"
		}
	}
}

func (s *QuantitativeRunStats) addFalsePositive(rule int) {
	s.FalsePositives++
	s.FalsePositivesPerRule[rule]++
}
