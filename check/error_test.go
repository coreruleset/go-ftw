// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

var expectedOKTests = []struct {
	err      error
	expected bool
}{
	{nil, false},
	{errors.New("a"), true},
}

var expectedFailTests = []struct {
	err      error
	expected bool
}{
	{nil, true},
	{errors.New("a"), false},
}

type checkErrorTestSuite struct {
	suite.Suite
	cfg *config.FTWConfiguration
}

func TestCheckErrorTestSuite(t *testing.T) {
	suite.Run(t, new(checkErrorTestSuite))
}

func (s *checkErrorTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()

	logName, err := utils.CreateTempFileWithContent("", logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(logName)
}

func (s *checkErrorTestSuite) TestAssertResponseErrorOK() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	for _, e := range expectedOKTests {
		c.SetExpectError(e.expected)
		expected, succeeded := c.AssertExpectError(e.err)
		s.Equal(e.expected, expected)
		s.True(succeeded)
	}
}

func (s *checkErrorTestSuite) TestAssertResponseFail() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	for _, e := range expectedFailTests {
		c.SetExpectError(e.expected)
		expected, succeeded := c.AssertExpectError(e.err)
		s.Equal(e.expected, expected)
		s.False(succeeded)
	}
}
