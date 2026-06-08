// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
)

type perfCmdTestSuite struct {
	suite.Suite
}

func TestPerfCmdTestSuite(t *testing.T) {
	suite.Run(t, new(perfCmdTestSuite))
}

func (s *perfCmdTestSuite) TestRequiresFileOrPattern() {
	root := New(internal.NewCommandContext())
	root.SetArgs([]string{"perf", "--subject", "x"})
	err := root.Execute()
	s.Require().Error(err)
	s.Contains(err.Error(), "either")
}

func (s *perfCmdTestSuite) TestRejectsBothFileAndPattern() {
	root := New(internal.NewCommandContext())
	root.SetArgs([]string{"perf", "--file", "a.ra", "--pattern", "x", "--subject", "y"})
	err := root.Execute()
	s.Require().Error(err)
	s.Contains(err.Error(), "only one")
}

func (s *perfCmdTestSuite) TestPatternWithSubjectSmoke() {
	var buf bytes.Buffer
	root := New(internal.NewCommandContext())
	root.SetOut(&buf)
	root.SetArgs([]string{"perf",
		"--pattern", "(?i)select",
		"--subject", "UNION SELECT 1",
		"--output", "json",
	})
	err := root.Execute()
	s.Require().NoError(err)
	s.Contains(buf.String(), "\"subjectCount\":1")
}
