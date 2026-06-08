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

type benchmarkTestSuite struct {
	suite.Suite
}

func TestBenchmarkTestSuite(t *testing.T) {
	suite.Run(t, new(benchmarkTestSuite))
}

func (s *benchmarkTestSuite) TestRunInlineSubjectMatch() {
	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	err := Run(Params{
		Pattern: `(?i)select`,
		Subject: "UNION SELECT 1",
		Repeat:  3,
		TopN:    5,
	}, out)
	s.Require().NoError(err)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal("pattern", r.RegexSource)
	s.Equal(1, r.SubjectCount)
	s.Equal(1, r.MatchCount)
	s.Len(r.Slowest, 1)
	s.True(r.Slowest[0].Matched)
}

func (s *benchmarkTestSuite) TestRunInlineSubjectNoMatch() {
	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	err := Run(Params{
		Pattern: `\d{5}`,
		Subject: "no digits here",
		Repeat:  1,
		TopN:    5,
	}, out)
	s.Require().NoError(err)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal(1, r.SubjectCount)
	s.Equal(0, r.MatchCount)
}

func (s *benchmarkTestSuite) TestRunInvalidPattern() {
	out := output.NewOutput("json", &bytes.Buffer{})
	err := Run(Params{Pattern: `(unclosed`, Subject: "x", Repeat: 1, TopN: 1}, out)
	s.Require().Error(err)
}
