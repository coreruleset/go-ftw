// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/utils"
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
	}

	ll.reset()
	s.IsType(&os.File{}, ll.logFile)
	s.Equal("X-Tests", string(ll.LogMarkerHeaderName))
	s.Nil(ll.startMarker)
	s.Nil(ll.endMarker)
	s.Empty(ll.triggeredRules)
	s.Empty(ll.markedLines)
}

func (s *waflogTestSuite) TestTruncateLogFile() {
	content := "line1\nline2\nline3\n"
	filename, err := utils.CreateTempFileWithContent("", content, "test-truncate-*.log")
	s.Require().NoError(err)
	defer os.Remove(filename)

	cfg := config.NewDefaultConfig()
	cfg.LogFile = filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	defer ll.Cleanup()

	// Verify file has content before truncation
	fi, err := os.Stat(filename)
	s.Require().NoError(err)
	s.Greater(fi.Size(), int64(0), "file should have content before truncation")

	// Truncate the file
	err = ll.TruncateLogFile()
	s.Require().NoError(err)

	// Verify file is empty after truncation
	fi, err = os.Stat(filename)
	s.Require().NoError(err)
	s.Equal(int64(0), fi.Size(), "file should be empty after truncation")
}

func (s *waflogTestSuite) TestGetMarkedLinesWithoutMarkers() {
	ll := &FTWLogLines{}
	// Neither start nor end marker is set: GetMarkedLines should return nil safely
	lines := ll.GetMarkedLines()
	s.Nil(lines, "GetMarkedLines should return nil when markers are not set")
}

func (s *waflogTestSuite) TestGetMarkedLinesWithOnlyStartMarker() {
	ll := &FTWLogLines{}
	ll.WithStartMarker([]byte("start"))
	// End marker not set: GetMarkedLines should return nil safely
	lines := ll.GetMarkedLines()
	s.Nil(lines, "GetMarkedLines should return nil when end marker is not set")
}
