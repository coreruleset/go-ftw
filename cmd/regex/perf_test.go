// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regex

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/regexperf"
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

func (s *perfCmdTestSuite) TestValidateRawCorpusPathMissingFile() {
	err := validateRawCorpusPath(regexperf.Params{
		Corpus:          corpus.Raw,
		CorpusLocalPath: filepath.Join(s.T().TempDir(), "nope.txt"),
	})
	s.Require().Error(err)
}

func (s *perfCmdTestSuite) TestValidateRawCorpusPathIsDirectory() {
	dir := s.T().TempDir()
	err := validateRawCorpusPath(regexperf.Params{
		Corpus:          corpus.Raw,
		CorpusLocalPath: dir,
	})
	s.Require().Error(err)
	s.Contains(err.Error(), "directory")
}

func (s *perfCmdTestSuite) TestValidateRawCorpusPathEmptyPath() {
	err := validateRawCorpusPath(regexperf.Params{Corpus: corpus.Raw})
	s.Require().Error(err)
}

func (s *perfCmdTestSuite) TestValidateRawCorpusPathOkForFile() {
	f := filepath.Join(s.T().TempDir(), "subjects.txt")
	s.Require().NoError(os.WriteFile(f, []byte("a\nb\n"), 0o600))
	err := validateRawCorpusPath(regexperf.Params{Corpus: corpus.Raw, CorpusLocalPath: f})
	s.Require().NoError(err)
}

func (s *perfCmdTestSuite) TestValidateRawCorpusPathSkippedForSubject() {
	// With a subject set, raw-path validation is skipped entirely.
	err := validateRawCorpusPath(regexperf.Params{Subject: "x", Corpus: corpus.Raw})
	s.Require().NoError(err)
}
