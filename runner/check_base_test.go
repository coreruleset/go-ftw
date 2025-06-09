// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"testing"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/test"
	"github.com/coreruleset/go-ftw/utils"
	"github.com/coreruleset/go-ftw/waflog"
)

var configMap = map[string]string{
	"TestNewCheck": `---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
`, "TestForced": `---
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
  forcepass:
    '1245': 'Forced Pass'
  forcefail:
    '6789': 'Forced Fail'
`, "TestCloudMode": `---
mode: "cloud"`,
}

type checkBaseTestSuite struct {
	suite.Suite
	cfg          *config.FTWConfiguration
	runnerConfig *config.RunnerConfig
	context      *TestRunContext
}

func (s *checkBaseTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *checkBaseTestSuite) BeforeTest(_, name string) {
	var err error
	s.cfg, err = config.NewConfigFromString(configMap[name])
	s.Require().NoError(err)
	s.cfg.LogFile, err = utils.CreateTempFileWithContent("", logText, "test-*.log")
	s.Require().NoError(err)
	s.runnerConfig = config.NewRunnerConfiguration(s.cfg)
	s.context = &TestRunContext{
		RunnerConfig: s.runnerConfig,
	}
	s.context.LogLines, err = waflog.NewFTWLogLines(s.runnerConfig)
	s.Require().NoError(err)
}

func TestCheckBaseTestSuite(t *testing.T) {
	suite.Run(t, new(checkBaseTestSuite))
}

func (s *checkBaseTestSuite) TestNewCheck() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)

	for _, text := range c.cfg.TestOverride.Ignore {
		s.Equal(text, "Ignore Me", "Well, didn't match Ignore Me")
	}

	to := test.Output{
		Status:           200,
		ResponseContains: "",
		LogContains:      "nothing",
		NoLogContains:    "",
		ExpectError:      func() *bool { b := true; return &b }(),
	}
	c.SetExpectTestOutput(&to)

	s.True(*c.expected.ExpectError, "Problem setting expected output")

	c.SetNoLogContains("nologcontains")

	//nolint:staticcheck
	s.Equal(c.expected.NoLogContains, "nologcontains", "Problem setting nologcontains")
}

func (s *checkBaseTestSuite) TestForced() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)

	s.True(c.ForcedIgnore(&schema.Test{RuleId: 942200, TestId: 1}), "Can't find ignored value")

	s.False(c.ForcedFail(&schema.Test{RuleId: 12345, TestId: 1}), "Value should not be found")

	s.False(c.ForcedPass(&schema.Test{RuleId: 12345, TestId: 1}), "Value should not be found")

	s.True(c.ForcedPass(&schema.Test{RuleId: 1245, TestId: 1}), "Value should be found")

	s.True(c.ForcedFail(&schema.Test{RuleId: 6789, TestId: 1}), "Value should be found")

	s.cfg.TestOverride.Ignore = make(map[*config.FTWRegexp]string)
	s.Falsef(c.ForcedIgnore(&schema.Test{RuleId: 1234, TestId: 1}), "Should not find ignored value in empty map")

}

func (s *checkBaseTestSuite) TestSetMarkers() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)

	c.SetStartMarker([]byte("TesTingStArtMarKer"))
	c.SetEndMarker([]byte("TestIngEnDMarkeR"))
	s.Equal("testingstartmarker", string(c.log.StartMarker()), "Couldn't set start marker")
	s.Equal("testingendmarker", string(c.log.EndMarker()), "Couldn't set end marker")
}
