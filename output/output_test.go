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

func (s *outputTestSuite) TestValidTypes() {
	types := ValidTypes()
	s.Require().Len(types, 5, "Expected 5 valid types")
	s.Contains(types, Normal)
	s.Contains(types, Quiet)
	s.Contains(types, GitHub)
	s.Contains(types, JSON)
	s.Contains(types, Plain)
}

func (s *outputTestSuite) TestPrintln() {
	var b bytes.Buffer

	tests := []struct {
		name     string
		oType    string
		format   string
		args     []any
		expected string
	}{
		{
			name:     "normal output with newline",
			oType:    "normal",
			format:   "test %s",
			args:     []any{"message"},
			expected: "test message\n",
		},
		{
			name:     "plain output with newline",
			oType:    "plain",
			format:   "test %s",
			args:     []any{"message"},
			expected: "test message\n",
		},
		{
			name:     "quiet output with newline",
			oType:    "quiet",
			format:   "test %s",
			args:     []any{"message"},
			expected: "",
		},
	}

	for _, test := range tests {
		b.Reset()
		o := NewOutput(test.oType, &b)
		err := o.Println(test.format, test.args...)
		s.Require().NoError(err, "Error in test: %s", test.name)
		s.Equal(test.expected, b.String(), "Output mismatch in test: %s", test.name)
	}
}

func (s *outputTestSuite) TestMessage() {
	var b bytes.Buffer

	o := NewOutput("normal", &b)

	// Test existing key
	msg := o.Message("** Starting tests!")
	s.Equal(":hammer_and_wrench:Starting tests!", msg, "Message should return value from catalog")

	// Test non-existing key
	msg = o.Message("non-existent-key")
	s.Equal("", msg, "Message should return empty string for non-existent key")

	// Test with plain catalog
	plain := NewOutput("plain", &b)
	msg = plain.Message("** Starting tests!")
	s.Equal("** Starting tests!", msg, "Plain message should return the key itself")
}

func (s *outputTestSuite) TestIsJson() {
	tests := []struct {
		oType    string
		expected bool
	}{
		{"json", true},
		{"normal", false},
		{"quiet", false},
		{"github", false},
		{"plain", false},
	}

	var b bytes.Buffer
	for _, test := range tests {
		o := NewOutput(test.oType, &b)
		s.Equal(test.expected, o.IsJson(), "IsJson() mismatch for type: %s", test.oType)
	}
}

func (s *outputTestSuite) TestNewOutputWithUnknownType() {
	var b bytes.Buffer

	// Test with unknown type - should default to Normal
	o := NewOutput("unknown-type", &b)
	s.Equal(Normal, o.OutputType, "Unknown type should default to Normal")
}

func (s *outputTestSuite) TestPrintfGitHub() {
	var b bytes.Buffer

	o := NewOutput("github", &b)
	err := o.Printf("test message %s", "here")
	s.Require().NoError(err)
	s.Contains(b.String(), "::notice")
	s.Contains(b.String(), "test message here")
}

func (s *outputTestSuite) TestPrintfAllTypes() {
	tests := []struct {
		name  string
		oType string
	}{
		{"normal", "normal"},
		{"quiet", "quiet"},
		{"github", "github"},
		{"json", "json"},
		{"plain", "plain"},
	}

	for _, test := range tests {
		var b bytes.Buffer
		o := NewOutput(test.oType, &b)
		err := o.Printf("test %s", "format")
		s.Require().NoError(err, "Printf failed for type: %s", test.name)
	}
}
