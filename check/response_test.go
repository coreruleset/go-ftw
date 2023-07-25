// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
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
	cfg *config.FTWConfiguration
}

func TestCheckResponseTestSuite(t *testing.T) {
	suite.Run(t, new(checkResponseTestSuite))
}

func (s *checkResponseTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()
	logName, err := utils.CreateTempFileWithContent(logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(logName)
}

func (s *checkResponseTestSuite) TestAssertResponseTextErrorOK() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		s.Truef(c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextFailOK() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	for _, e := range expectedResponseFailTests {
		c.SetExpectResponse(e.expected)
		s.Falsef(c.AssertResponseContains(e.response), "response shouldn't contain text %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextChecksFullResponseOK() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		s.Truef(c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseContainsRequired() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	c.SetExpectResponse("")
	s.False(c.AssertResponseContains(""), "response shouldn't contain text")
	s.False(c.ResponseContainsRequired(), "response shouldn't contain text")
}
