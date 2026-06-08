// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/output"
)

type statsTestSuite struct {
	suite.Suite
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(statsTestSuite))
}

func (s *statsTestSuite) TestAggregateBasics() {
	st := NewStats("pattern", 10, 1, 3)
	st.Add("a", 100, true)
	st.Add("b", 300, false)
	st.Add("c", 200, true)

	r := st.report()
	s.Equal(3, r.SubjectCount)
	s.Equal(2, r.MatchCount)
	s.Equal(int64(600), r.TotalNs)
	s.Equal(int64(200), r.MeanNs)   // 600/3
	s.Equal(int64(200), r.MedianNs) // middle of [100,200,300]
	s.Equal(int64(300), r.MaxNs)
}

func (s *statsTestSuite) TestTopNKeepsSlowest() {
	st := NewStats("pattern", 1, 1, 2) // keep top 2
	st.Add("slow1", 500, true)
	st.Add("fast", 10, false)
	st.Add("slow2", 400, true)
	st.Add("mid", 100, false)

	r := st.report()
	s.Len(r.Slowest, 2)
	s.Equal("slow1", r.Slowest[0].Subject) // descending by Ns
	s.Equal(int64(500), r.Slowest[0].Ns)
	s.Equal("slow2", r.Slowest[1].Subject)
	s.Equal(int64(400), r.Slowest[1].Ns)
}

func (s *statsTestSuite) TestEmptyStats() {
	st := NewStats("pattern", 0, 1, 3)
	r := st.report()
	s.Equal(0, r.SubjectCount)
	s.Equal(int64(0), r.MeanNs)
	s.Equal(float64(0), r.ThroughputPerSec)
	s.Empty(r.Slowest)
}

func (s *statsTestSuite) TestThroughput() {
	st := NewStats("pattern", 0, 1, 1)
	// 2 subjects taking 1ms total -> 2000 subj/s
	st.Add("a", 400_000, true)
	st.Add("b", 600_000, true)
	r := st.report()
	s.InDelta(2000.0, r.ThroughputPerSec, 0.001)
}

func (s *statsTestSuite) TestPrintSummaryNormal() {
	st := NewStats("file:foo.ra", 12, 5, 3)
	st.Add("' UNION SELECT 1", 1200, true)
	st.Add("hello", 300, false)

	var buf bytes.Buffer
	out := output.NewOutput("plain", &buf)
	st.printSummary(out)

	text := buf.String()
	s.Contains(text, "file:foo.ra")
	s.Contains(text, "subjects: 2")
	s.Contains(text, "matched: 1")
	s.Contains(text, "slowest subjects")
	s.Contains(text, "UNION SELECT")
}

func (s *statsTestSuite) TestPrintSummaryJSON() {
	st := NewStats("pattern", 8, 1, 2)
	st.Add("a", 100, true)
	st.Add("b", 200, false)

	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)
	st.printSummary(out)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal("pattern", r.RegexSource)
	s.Equal(2, r.SubjectCount)
	s.Equal(1, r.MatchCount)
	s.Len(r.Slowest, 2)
}
