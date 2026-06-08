// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"cmp"
	"container/heap"
	"encoding/json"
	"math"
	"slices"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/output"
)

// Sample is the timing result for one subject.
type Sample struct {
	Subject string `json:"subject"`
	Ns      int64  `json:"ns"`
	Matched bool   `json:"matched"`
}

// slowestHeap is a min-heap of Samples by Ns, used to retain the top-N slowest.
type slowestHeap []Sample

func (h slowestHeap) Len() int           { return len(h) }
func (h slowestHeap) Less(i, j int) bool { return h[i].Ns < h[j].Ns }
func (h slowestHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *slowestHeap) Push(x any)        { *h = append(*h, x.(Sample)) }
func (h *slowestHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// Stats accumulates per-subject timing results.
type Stats struct {
	regexSource  string
	regexBytes   int
	repeat       int
	topN         int
	subjectCount int
	matchCount   int
	totalNs      int64
	maxNs        int64
	minsNs       []int64 // per-subject minimum ns, for percentiles
	slowest      slowestHeap
}

// NewStats returns an empty Stats. regexSource describes the regex origin,
// regexBytes is the length of the compiled regex string, repeat is the per-subject
// match repetition count, topN is how many slowest subjects to retain.
func NewStats(regexSource string, regexBytes int, repeat int, topN int) *Stats {
	return &Stats{
		regexSource: regexSource,
		regexBytes:  regexBytes,
		repeat:      repeat,
		topN:        topN,
		minsNs:      make([]int64, 0, 1024),
		slowest:     make(slowestHeap, 0, topN+1),
	}
}

// Add records one subject's timing result.
func (s *Stats) Add(subject string, ns int64, matched bool) {
	s.subjectCount++
	if matched {
		s.matchCount++
	}
	s.totalNs += ns
	s.maxNs = max(s.maxNs, ns)
	s.minsNs = append(s.minsNs, ns)
	if s.topN > 0 {
		heap.Push(&s.slowest, Sample{Subject: subject, Ns: ns, Matched: matched})
		if s.slowest.Len() > s.topN {
			heap.Pop(&s.slowest)
		}
	}
}

// report is the computed view of the accumulated stats, shared by the normal
// and JSON output paths.
type report struct {
	RegexSource      string   `json:"regexSource"`
	RegexBytes       int      `json:"regexBytes"`
	Repeat           int      `json:"repeat"`
	SubjectCount     int      `json:"subjectCount"`
	MatchCount       int      `json:"matchCount"`
	TotalNs          int64    `json:"totalNs"`
	MeanNs           int64    `json:"meanNs"`
	MedianNs         int64    `json:"medianNs"`
	P99Ns            int64    `json:"p99Ns"`
	MaxNs            int64    `json:"maxNs"`
	ThroughputPerSec float64  `json:"throughputPerSec"`
	Slowest          []Sample `json:"slowest"`
}

func (s *Stats) report() report {
	sorted := slices.Clone(s.minsNs)
	slices.Sort(sorted)

	var meanNs int64
	var throughput float64
	if s.subjectCount > 0 {
		meanNs = s.totalNs / int64(s.subjectCount)
	}
	if s.totalNs > 0 {
		throughput = float64(s.subjectCount) / (float64(s.totalNs) / 1e9)
	}

	return report{
		RegexSource:      s.regexSource,
		RegexBytes:       s.regexBytes,
		Repeat:           s.repeat,
		SubjectCount:     s.subjectCount,
		MatchCount:       s.matchCount,
		TotalNs:          s.totalNs,
		MeanNs:           meanNs,
		MedianNs:         percentile(sorted, 50),
		P99Ns:            percentile(sorted, 99),
		MaxNs:            s.maxNs,
		ThroughputPerSec: throughput,
		Slowest:          s.slowestSorted(),
	}
}

// slowestSorted returns the retained slowest samples in descending Ns order.
func (s *Stats) slowestSorted() []Sample {
	out := slices.Clone([]Sample(s.slowest))
	slices.SortFunc(out, func(a, b Sample) int {
		return cmp.Compare(b.Ns, a.Ns)
	})
	return out
}

// percentile returns the p-th percentile (0-100) of a sorted slice using
// nearest-rank rounding. Returns 0 for an empty slice.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := p / 100 * float64(len(sorted)-1)
	idx := min(max(int(math.Round(rank)), 0), len(sorted)-1)
	return sorted[idx]
}

// maxSubjectDisplayLen caps subject length in normal (human) output.
const maxSubjectDisplayLen = 80

// MarshalJSON renders the computed report.
func (s *Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.report())
}

// printSummary writes the report to out in JSON or human-readable form.
func (s *Stats) printSummary(out *output.Output) {
	if out.IsJson() {
		b, err := json.Marshal(s)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal regexperf stats to JSON")
			return
		}
		out.RawPrint(string(b))
		return
	}

	r := s.report()
	_ = out.Println("regex: %s (compiled, %d bytes)", r.RegexSource, r.RegexBytes)
	_ = out.Println("subjects: %d  matched: %d", r.SubjectCount, r.MatchCount)
	_ = out.Println("total: %s  mean: %s  median: %s",
		dur(r.TotalNs), dur(r.MeanNs), dur(r.MedianNs))
	_ = out.Println("p99: %s  max: %s", dur(r.P99Ns), dur(r.MaxNs))
	_ = out.Println("throughput: %.0f subj/s", r.ThroughputPerSec)

	if len(r.Slowest) == 0 {
		return
	}
	_ = out.Println("")
	_ = out.Println("slowest subjects:")
	for _, sample := range r.Slowest {
		_ = out.Println("  %s  %q", dur(sample.Ns), truncate(sample.Subject, maxSubjectDisplayLen))
	}
}

// dur formats a nanosecond count as a human-readable duration.
func dur(ns int64) string {
	return time.Duration(ns).String()
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
