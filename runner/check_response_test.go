// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/utils"
)

var expectedResponseOKTests = []struct {
	response string
	expected string
}{
	{`<html><title></title><body></body></html>`, "title"},
}

var expectedResponseFailTests = []struct {
	response string
	expected string
}{
	{`<html><title></title><body></body></html>`, "not found"},
	{``, `empty should return false`},
}

type checkResponseTestSuite struct {
	suite.Suite
	cfg          *config.FTWConfiguration
	runnerConfig *config.RunnerConfig
	context      *TestRunContext
}

func TestCheckResponseTestSuite(t *testing.T) {
	suite.Run(t, new(checkResponseTestSuite))
}

func (s *checkResponseTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *checkResponseTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()
	s.cfg.LogFile, err = utils.CreateTempFileWithContent("", logText, "test-*.log")
	s.Require().NoError(err)
	s.runnerConfig = config.NewRunnerConfiguration(s.cfg)
	s.context = &TestRunContext{
		RunnerConfig: s.runnerConfig,
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextErrorOK() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		s.Truef(c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextFailOK() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)
	for _, e := range expectedResponseFailTests {
		c.SetExpectResponse(e.expected)
		s.Falsef(c.AssertResponseContains(e.response), "response shouldn't contain text %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextChecksFullResponseOK() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		s.Truef(c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}
