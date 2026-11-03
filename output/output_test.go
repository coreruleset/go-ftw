// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

var testString = "test"

var format = `This is the %s`

// TODO:
// GitHub
// GitLab
// CodeBuild
// CircleCI
// Jenkins
var outputTest = []struct {
	oType    string
	expected string
}{
	{"quiet", ""},
	{"github", "This is the test"},
	{"normal", "⚠️ with emoji: This is the test"},
	{"json", `{"level":"notice","message":"This is the test"}`},
}

type outputTestSuite struct {
	suite.Suite
}

func (s *outputTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestOutputTestSuite(t *testing.T) {
	suite.Run(t, new(outputTestSuite))
}

func (s *outputTestSuite) TestOutput() {
	var b bytes.Buffer

	for i, test := range outputTest {
		o := NewOutput(test.oType, &b)

		err := o.Printf(format, testString)
		s.Require().NoError(err, "Error! in test %d", i)
	}
}

func (s *outputTestSuite) TestNormalCatalogOutput() {
	var b bytes.Buffer

	normal := NewOutput("normal", &b)
	for _, v := range normalCatalog {
		normal.RawPrint(v)
		s.Equal(b.String(), v, "output is not equal")
		// reset buffer
		b.Reset()
	}
}

func (s *outputTestSuite) TestPlainCatalogOutput() {
	var b bytes.Buffer

	normal := NewOutput("normal", &b)
	for _, v := range createPlainCatalog(normalCatalog) {
		normal.RawPrint(v)
		s.Equal(b.String(), v, "output is not equal")
		// reset buffer
		b.Reset()
	}
}

func (s *outputTestSuite) TestGitHubAnnotationError() {
	var b bytes.Buffer
	o := NewOutput("github", &b)
	o.SetSeverity(AnnotationError)

	err := o.Printf("- %s failed in %s", "920100-1", "5ms")
	s.Require().NoError(err)
	// file/line/endLine are deliberately omitted: go-ftw has no per-test
	// line info, and a file without a line renders as a misleading `#L0`.
	s.Equal("::error::- 920100-1 failed in 5ms\n", b.String())
}

func (s *outputTestSuite) TestGitHubAnnotationEscapesSpecialChars() {
	var b bytes.Buffer
	o := NewOutput("github", &b)

	err := o.Printf("100%% done\r\nwith: %s, ok", "newline")
	s.Require().NoError(err)
	// Only '%', CR and LF are escaped in the message body (per the actions
	// runner): ':' and ',' pass through untouched.
	s.Equal("::notice::100%25 done%0D%0Awith: newline, ok\n", b.String())
}

// Println's line break must remain a real newline: GitHub only parses one
// workflow command per line, so escaping it would glue every command into a
// single (rejected) annotation.
func (s *outputTestSuite) TestGitHubAnnotationPrintlnKeepsRealNewline() {
	var b bytes.Buffer
	o := NewOutput("github", &b)

	err := o.Println("+ passed in %s", "5ms")
	s.Require().NoError(err)
	err = o.Println("- failed")
	s.Require().NoError(err)
	s.Equal("::notice::+ passed in 5ms\n::notice::- failed\n", b.String())
}

// A Printf without a trailing newline (run.go's "\trunning %s: " progress
// prefix) must become a complete command on its own line instead of letting
// the next command be parsed as part of its message.
func (s *outputTestSuite) TestGitHubPartialPrintfDoesNotSwallowNextCommand() {
	var b bytes.Buffer
	o := NewOutput("github", &b)

	err := o.Printf("\trunning %s: ", "920100-1")
	s.Require().NoError(err)
	o.SetSeverity(AnnotationError)
	err = o.Println("- %s failed in %s (RTT %s)", "920100-1", "5ms", "2ms")
	s.Require().NoError(err)
	s.Equal("::notice::\trunning 920100-1: \n::error::- 920100-1 failed in 5ms (RTT 2ms)\n", b.String())
}
