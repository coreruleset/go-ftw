// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"cmp"
	"container/heap"
	"math"
	"slices"
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
	idx := int(math.Round(rank))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
