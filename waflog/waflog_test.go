// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"os"
	"regexp"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/config"
)

type waflogTestSuite struct {
	suite.Suite
}

func (s *waflogTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestWafLogTestSuite(t *testing.T) {
	suite.Run(t, new(waflogTestSuite))
}

func (s *waflogTestSuite) TestNewFTWLogLines() {
	cfg := config.NewDefaultConfig()
	s.NotNil(cfg)

	// Don't call NewFTWLogLines to avoid opening the file.
	ll := &FTWLogLines{}
	ll.WithStartMarker([]byte("#"))
	ll.WithEndMarker([]byte("#"))

	s.NotNil(ll.StartMarker, "Failed! StartMarker must be set")
	s.NotNil(ll.EndMarker, "Failed! EndMarker must be set")
	err := ll.Cleanup()
	s.Require().NoError(err)
}

func (s *waflogTestSuite) TestWithStartMarker() {
	cfg := config.NewDefaultConfig()
	s.NotNil(cfg)

	// Don't call NewFTWLogLines to avoid opening the file.
	ll := &FTWLogLines{}
	ll.WithStartMarker([]byte("#"))
	ll.WithEndMarker([]byte("#"))

	s.NotNil(ll.StartMarker())
	s.NotNil(ll.EndMarker())

	ll.WithStartMarker([]byte("new"))
	s.Nil(ll.endMarker, "WithStartMarker should reset end marker")

	ll.WithEndMarker([]byte("newer"))
	s.Equal("new", string(ll.startMarker))
	s.Equal("newer", string(ll.endMarker))
}

func (s *waflogTestSuite) TestLogLinesReset() {
	ll := FTWLogLines{
		logFile:             &os.File{},
		LogMarkerHeaderName: []byte("X-Tests"),
		startMarker:         []byte("startmarker"),
		endMarker:           []byte("endmarker"),
		triggeredRules:      []uint{1, 3, 3},
		markedLines:         [][]byte{[]byte("line1"), []byte("line2")},
		customLogIdRegex:    regexp.MustCompile(""),
	}

	ll.reset()
	s.IsType(&os.File{}, ll.logFile)
	s.Equal("X-Tests", string(ll.LogMarkerHeaderName))
	s.Nil(ll.startMarker)
	s.Nil(ll.endMarker)
	s.Empty(ll.triggeredRules)
	s.Empty(ll.markedLines)
	s.NotNil(ll.customLogIdRegex)
}

func (s *waflogTestSuite) TestCompileAndCheckRegex() {
	tests := []struct {
		name        string
		regex       string
		expectNil   bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty string returns nil without error",
			regex:       "",
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "valid regex with capture group",
			regex:       `(\d+)`,
			expectNil:   false,
			expectError: false,
		},
		{
			name:        "valid regex with named capture group",
			regex:       `(?P<id>\d+)`,
			expectNil:   false,
			expectError: false,
		},
		{
			name:        "valid regex with multiple capture groups",
			regex:       `(\d+)-([a-z]+)`,
			expectNil:   false,
			expectError: false,
		},
		{
			name:        "invalid regex syntax returns parse error",
			regex:       `[invalid`,
			expectNil:   true,
			expectError: true,
			errorMsg:    "could not parse regular expression",
		},
		{
			name:        "regex without capture group returns error",
			regex:       `\d+`,
			expectNil:   true,
			expectError: true,
			errorMsg:    "regex does not contain a capture group and cannot be used to find IDs",
		},
		{
			name:        "regex with only non-capturing group returns error",
			regex:       `(?:\d+)`,
			expectNil:   true,
			expectError: true,
			errorMsg:    "regex does not contain a capture group and cannot be used to find IDs",
		},
		{
			name:        "complex valid regex with capture group",
			regex:       `^prefix-([a-zA-Z0-9]+)-suffix$`,
			expectNil:   false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result, err := compileAndCheckRegex(tt.regex)

			if tt.expectError {
				s.Require().Error(err)
				s.Contains(err.Error(), tt.errorMsg)
				s.Nil(result)
			} else {
				s.Require().NoError(err)
			}

			if tt.expectNil {
				s.Nil(result)
			} else {
				s.NotNil(result)
			}
		})
	}
}
