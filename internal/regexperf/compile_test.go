// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
)

type compileTestSuite struct {
	suite.Suite
	tempDir string
}

func TestCompileTestSuite(t *testing.T) {
	suite.Run(t, new(compileTestSuite))
}

func (s *compileTestSuite) SetupTest() {
	s.tempDir = s.T().TempDir()
}

// writeRA writes content to a .ra file in tempDir and returns its path.
func (s *compileTestSuite) writeRA(name, content string) string {
	path := filepath.Join(s.tempDir, name)
	s.Require().NoError(os.WriteFile(path, []byte(content), 0o600))
	return path
}

func (s *compileTestSuite) TestAssembleFileProducesMatchingRegex() {
	// Two literal alternatives; the assembler emits an optimized alternation.
	raPath := s.writeRA("simple.ra", "homer\nmarge\n")

	regexStr, err := AssembleFile(raPath, s.tempDir)
	s.Require().NoError(err)
	s.Require().NotEmpty(regexStr)

	re, err := Compile(regexStr)
	s.Require().NoError(err)
	s.True(re.MatchString("homer"))
	s.True(re.MatchString("marge"))
	s.False(re.MatchString("bart"))
}

func (s *compileTestSuite) TestAssembleFileMissingFile() {
	_, err := AssembleFile(filepath.Join(s.tempDir, "nope.ra"), s.tempDir)
	s.Require().Error(err)
	s.Contains(err.Error(), "nope.ra")
}

func (s *compileTestSuite) TestCompilePassthroughValid() {
	re, err := Compile(`(?i)union\s+select`)
	s.Require().NoError(err)
	s.True(re.MatchString("UNION   SELECT"))
}

func (s *compileTestSuite) TestCompileInvalidRegex() {
	_, err := Compile(`(unclosed`)
	s.Require().Error(err)
}

func (s *compileTestSuite) TestAssembleFileIncludeMissingCrsRoot() {
	// .ra references an include, but crsRoot has no regex-assembly/ dir.
	// Must return an error instead of os.Exit-ing the process.
	raPath := s.writeRA("withinclude.ra", "include some-shared-fragment\nhomer\n")

	_, err := AssembleFile(raPath, s.tempDir)
	s.Require().Error(err)
	s.Contains(err.Error(), "regex-assembly")
}

func (s *compileTestSuite) TestPreflightNoIncludeIsOk() {
	s.Require().NoError(preflightAssembly("homer\nmarge\n", s.tempDir))
}

func (s *compileTestSuite) TestPreflightIncludeWithValidRoot() {
	// regex-assembly/ exists -> preflight passes (assembler may still fail later,
	// but preflight's job is only the crsRoot sanity check).
	s.Require().NoError(os.MkdirAll(filepath.Join(s.tempDir, "regex-assembly", "include"), 0o755))
	s.Require().NoError(preflightAssembly("include shared\nfoo\n", s.tempDir))
}
