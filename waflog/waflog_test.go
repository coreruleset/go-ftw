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
	"github.com/coreruleset/go-ftw/v2/utils"
)

type waflogTestSuite struct {
	suite.Suite
	tempDir string
}

func (s *waflogTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *waflogTestSuite) SetupTest() {
	s.tempDir = s.T().TempDir()
}

func TestWafLogTestSuite(t *testing.T) {
	suite.Run(t, new(waflogTestSuite))
}

func (s *waflogTestSuite) TestNewFTWLogLines() {
	var err error
	cfg := config.NewDefaultConfig()
	s.NotNil(cfg)

	cfg.LogFile, err = utils.CreateTempFile(s.tempDir, "logfile.log")
	s.Require().NoError(err)
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = ll.Cleanup() })

	ll.WithStartMarker([]byte("#"))
	ll.WithEndMarker([]byte("#"))

	s.NotNil(ll.StartMarker, "Failed! StartMarker must be set")
	s.NotNil(ll.EndMarker, "Failed! EndMarker must be set")
}

func (s *waflogTestSuite) TestWithStartMarker() {
	var err error
	cfg := config.NewDefaultConfig()
	s.NotNil(cfg)

	cfg.LogFile, err = utils.CreateTempFile(s.tempDir, "logfile.log")
	s.Require().NoError(err)
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = ll.Cleanup() })

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

func (s *waflogTestSuite) TestGetMarkedLinesWithoutMarkers() {
	ll := &FTWLogLines{}
	// Neither start nor end marker is set: GetMarkedLines should return nil safely
	_, err := ll.GetMarkedLines()
	s.Require().Error(err)
}
