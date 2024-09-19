// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"slices"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

type checkStatusTestSuite struct {
	suite.Suite
	cfg *config.FTWConfiguration
}

func (s *checkStatusTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()
	logName, err := utils.CreateTempFileWithContent(logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(logName)
}

func TestCheckStatusTestSuite(t *testing.T) {
	suite.Run(t, new(checkStatusTestSuite))
}

func (s *checkStatusTestSuite) TestStatusOK() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.SetExpectStatus(0)
	s.checkStatus(c, []int{})

	c.SetExpectStatus(200)
	s.checkStatus(c, []int{200})

	c.SetExpectStatus(303)
	s.checkStatus(c, []int{303})

	c.SetExpectStatus(400)
	s.checkStatus(c, []int{400})

	c.SetExpectStatus(403)
	s.checkStatus(c, []int{403})

	c.SetExpectStatus(500)
	s.checkStatus(c, []int{500})
}

// always match since no status expectation set
func (s *checkStatusTestSuite) TestCloudModePositiveMatch_AlwaysMatch() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	c.cfg.RunMode = config.CloudRunMode
	s.True(c.CloudMode(), "couldn't detect cloud mode")

	// negative regex match set
	c.SetLogContains("log contains")
	s.checkStatus(c, []int{})

	// negative regex match and ID negative ID match set
	c.expected.Log.ExpectIds = []uint{123456}
	s.checkStatus(c, []int{})

	// negative ID match set
	c.SetLogContains("")
	s.checkStatus(c, []int{})
}

func (s *checkStatusTestSuite) TestCloudModePositiveMatch() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	c.cfg.RunMode = config.CloudRunMode
	s.True(c.CloudMode(), "couldn't detect cloud mode")

	// nothing set
	c.SetExpectStatus(418) // I'm a teapot
	s.checkStatus(c, []int{418})

	// regex match set
	c.SetLogContains("this text")
	s.checkStatus(c, []int{403, 418})

	// regex match and ID match set
	c.expected.Log.ExpectIds = []uint{123456}
	s.checkStatus(c, []int{403, 418})

	// ID match set
	c.SetLogContains("")
	s.checkStatus(c, []int{403, 418})
}

// always match since no status expectation set
func (s *checkStatusTestSuite) TestCloudModeNegativeMatch_AlwaysMatch() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	c.cfg.RunMode = config.CloudRunMode
	s.True(c.CloudMode(), "couldn't detect cloud mode")

	// negative regex match set
	c.SetNoLogContains("no log contains")
	s.checkStatus(c, []int{})

	// negative regex match and ID negative ID match set
	c.expected.Log.NoExpectIds = []uint{123456}
	s.checkStatus(c, []int{})

	// negative ID match set
	c.SetNoLogContains("")
	s.checkStatus(c, []int{})
}

// status expectation set, only match specific statuses
func (s *checkStatusTestSuite) TestCloudModeNegativeMatch_SpecificMatch() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)
	c.cfg.RunMode = config.CloudRunMode
	s.True(c.CloudMode(), "couldn't detect cloud mode")

	// nothing set
	c.SetExpectStatus(418) // I'm a teapot
	s.checkStatus(c, []int{418})

	// negative regex match set
	c.SetNoLogContains("no log contains")
	s.checkStatus(c, []int{200, 404, 418, 405})

	// negative regex match and ID negative ID match set
	c.expected.Log.NoExpectIds = []uint{123456}
	s.checkStatus(c, []int{200, 404, 418, 405})

	// negative ID match set
	c.SetNoLogContains("")
	s.checkStatus(c, []int{200, 404, 418, 405})
}

func (s *checkStatusTestSuite) checkStatus(c *FTWCheck, expectedSuccesses []int) {
	if len(expectedSuccesses) == 0 {
		s.True(c.AssertStatus(-1), "Expected successful check because no expectation set")
		return
	}
	for status := 100; status < 600; status++ {
		if slices.Contains(expectedSuccesses, status) {
			s.True(c.AssertStatus(status), "Unexpected result for status %d", status)
		} else {
			s.False(c.AssertStatus(status), "Unexpected result for status %d", status)
		}
	}
}
