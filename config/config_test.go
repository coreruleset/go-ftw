// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"regexp"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/utils"
)

var testData = map[string]string{
	"TestNewConfigFromFile": `---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
include: '^9.*'
include_tags: '^cookie$'
testoverride:
  input:
    dest_addr: 'httpbingo.org'
    port: '1234'
  ignore:
    '920400-1$': 'This test result must be ignored'
`,
	"TestNewConfigFromFileRunMode": `---
mode: 'cloud'
`,
	"bad": `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
doesNotExist: ""
`,
	"jsonConfig": `
{"test": "type"}
`,
}

type fileTestSuite struct {
	suite.Suite
	tempDir  string
	filename string
	cfg      *FTWConfiguration
}

type baseTestSuite struct {
	suite.Suite
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(baseTestSuite))
	suite.Run(t, new(fileTestSuite))
}

func (s *baseTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *fileTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *fileTestSuite) BeforeTest(_, name string) {
	var err error
	s.tempDir = s.T().TempDir()

	s.filename, err = utils.CreateTempFileWithContent(s.tempDir, testData[name], "test-*.yaml")
	s.Require().NoError(err)

	s.cfg, err = NewConfigFromFile(s.filename)
	s.Require().NoError(err)
	s.NotNil(s.cfg)
}

func (s *fileTestSuite) TearDownTest() {
	if s.filename != "" {
		err := os.Remove(s.filename)
		s.Require().NoError(err)
		s.filename = ""
	}
}

func (s *baseTestSuite) TestBaseUnmarshalText() {
	var ftwRegexp FTWRegexp
	err := ftwRegexp.UnmarshalText([]byte("test"))
	s.Require().NoError(err)
	s.NotNil(ftwRegexp)
	s.True(ftwRegexp.MatchString("This is a test for unmarshalling"), "looks like we could not match string")
}

func (s *baseTestSuite) TestBaseNewFTWRegexpText() {
	ftwRegexp, err := NewFTWRegexp("test")
	s.Require().NoError(err)
	s.NotNil(ftwRegexp)
	s.True(ftwRegexp.MatchString("This is a test"), "looks like we could not match string")
}

func (s *baseTestSuite) TestNewCloudConfig() {
	cfg := NewCloudConfig()
	s.Equal(CloudRunMode, cfg.RunMode)
	s.Equal("", cfg.LogFile)
}

func (s *baseTestSuite) TestNewDefaultConfig() {
	cfg := NewDefaultConfig()
	s.Equal(DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName)
	s.Equal(DefaultRunMode, cfg.RunMode)
	s.Equal("", cfg.LogFile)
}

func (s *fileTestSuite) TestNewConfigBadFileConfig() {
	filename, err := utils.CreateTempFileWithContent(s.tempDir, testData["jsonConfig"], "test-*.yaml")
	s.Require().NoError(err)

	cfg, err := NewConfigFromFile(filename)
	s.Require().NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromFile() {
	s.NotEmpty(s.cfg.IncludeTests, "Include regex must not be empty")
	s.NotEmpty(s.cfg.TestOverride.Overrides, "Ignore list must not be empty")

	s.Require().Contains((*regexp.Regexp)(s.cfg.IncludeTests).String(), "^9.*", "Looks like we could not find item to include")

	// deprecated `ignore` entries are treated as `forcepass`
	s.Empty(s.cfg.TestOverride.Ignore)
	s.Require().Len(s.cfg.TestOverride.ForcePass, 1)
	for id, text := range s.cfg.TestOverride.ForcePass {
		s.Contains((*regexp.Regexp)(id).String(), "920400-1$", "Looks like we could not find item to ignore")
		s.Equal("This test result must be ignored", text, "Text doesn't match")
	}

	overrides := s.cfg.TestOverride.Overrides
	s.NotNil(overrides.DestAddr, "Looks like we are not overriding destination address")
	s.Equal("httpbingo.org", *overrides.DestAddr, "Looks like we are not overriding destination address")
}

func (s *fileTestSuite) TestNewConfigBadConfig() {
	// contents come from `bad` YAML config
	s.NotNil(s.cfg)
}

func (s *fileTestSuite) TestNewConfigDefaultConfig() {
	// For this test we need a local .ftw.yaml file
	s.filename = ".ftw.yaml"
	_ = os.WriteFile(s.filename, []byte(testData["ok"]), 0644)

	cfg, err := NewConfigFromFile("")
	s.Require().NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromString() {
	cfg, err := NewConfigFromString(testData["ok"])
	s.Require().NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromNoneExistingFile() {
	cfg, err := NewConfigFromFile("nonsense")
	s.Error(err)
	s.Require().Nil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromEnv() {
	// Set some environment so it gets merged with conf
	err := os.Setenv("FTW_LOGFILE", "koanf")
	s.Require().NoError(err)

	cfg, err := NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)
	s.Equal("koanf", cfg.LogFile)
}

func (s *fileTestSuite) TestNewConfigFromEnvHasDefaults() {
	cfg, err := NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	s.Equalf(DefaultRunMode, cfg.RunMode,
		"unexpected default value '%s' for run mode", cfg.RunMode)
	s.Equalf(DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", cfg.LogMarkerHeaderName)

}

func (s *fileTestSuite) TestNewConfigFromFileHasDefaults() {
	s.Equalf(DefaultRunMode, s.cfg.RunMode,
		"unexpected default value '%s' for run mode", s.cfg.RunMode)
	s.Equalf(DefaultLogMarkerHeaderName, s.cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", s.cfg.LogMarkerHeaderName)
}

func (s *fileTestSuite) TestNewConfigFromStringHasDefaults() {
	cfg, err := NewConfigFromString("")
	s.Require().NoError(err)
	s.NotNil(cfg)
	s.Equalf(DefaultRunMode, cfg.RunMode,
		"unexpected default value '%s' for run mode", cfg.RunMode)
	s.Equalf(DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", s.cfg.LogMarkerHeaderName)
}

func (s *fileTestSuite) TestNewConfigFromFileRunMode() {
	s.Equalf(CloudRunMode, s.cfg.RunMode,
		"unexpected value '%s' for run mode, expected '%s;", s.cfg.RunMode, CloudRunMode)
}

func (s *fileTestSuite) TestNewDefaultConfigWithParams() {
	cfg := NewDefaultConfig()
	cfg.LogFile = "mylogfile.log"
	s.Equal("mylogfile.log", cfg.LogFile)
	overrides := FTWTestOverride{
		Overrides: Overrides{},
		ForcePass: nil,
		ForceFail: nil,
	}
	cfg.TestOverride = overrides
	s.Equal(overrides, cfg.TestOverride)
	cfg.LogMarkerHeaderName = "NEW-MARKER-TEST"
	s.Equal("NEW-MARKER-TEST", cfg.LogMarkerHeaderName)
	cfg.RunMode = CloudRunMode
	s.Equal(CloudRunMode, cfg.RunMode)
}

func (s *baseTestSuite) TestWithMaxMarker() {
	cfg := NewDefaultConfig()
	cfg.MaxMarkerRetries = 19
	s.Equal(uint(19), cfg.MaxMarkerRetries)
	cfg.MaxMarkerLogLines = 111
	s.Equal(uint(111), cfg.MaxMarkerLogLines)

}

func (s *baseTestSuite) TestExcludeIsNotSupported() {
	cfg, err := NewConfigFromString("exclude: '^920400-2$'")
	s.Require().Error(err)
	s.Nil(cfg)
	s.Contains(err.Error(), "platform overrides")
}

func (s *baseTestSuite) TestStaleOverridesDefaultsToFail() {
	cfg, err := NewConfigFromString("logfile: 'test.log'")
	s.Require().NoError(err)
	s.Equal(StaleOverridesFail, cfg.TestOverride.StaleOverrides)
	s.True(cfg.TestOverride.FailOnStaleOverrides())
}

func (s *baseTestSuite) TestStaleOverridesWarn() {
	cfg, err := NewConfigFromString("testoverride:\n  stale_overrides: warn")
	s.Require().NoError(err)
	s.Equal(StaleOverridesWarn, cfg.TestOverride.StaleOverrides)
	s.False(cfg.TestOverride.FailOnStaleOverrides())
}

func (s *baseTestSuite) TestStaleOverridesInvalid() {
	cfg, err := NewConfigFromString("testoverride:\n  stale_overrides: ignore")
	s.Require().Error(err)
	s.Nil(cfg)
	s.Contains(err.Error(), "stale_overrides")
}

func (s *baseTestSuite) TestIgnoreIsMergedIntoForcePass() {
	cfg, err := NewConfigFromString(`---
testoverride:
  ignore:
    '920400-1$': 'ignored'
  forcepass:
    '920400-2$': 'forced'
`)
	s.Require().NoError(err)
	s.Empty(cfg.TestOverride.Ignore)
	reasons := map[string]string{}
	for re, reason := range cfg.TestOverride.ForcePass {
		reasons[(*regexp.Regexp)(re).String()] = reason
	}
	s.Equal(map[string]string{"920400-1$": "ignored", "920400-2$": "forced"}, reasons)
}

func (s *baseTestSuite) TestRunnerConfigurationMergesIgnoreIntoForcePass() {
	ignore, err := NewFTWRegexp("920400-1$")
	s.Require().NoError(err)
	forcePass, err := NewFTWRegexp("920400-2$")
	s.Require().NoError(err)
	cfg := NewDefaultConfig()
	cfg.TestOverride.Ignore = map[*FTWRegexp]string{ignore: "ignored"}
	cfg.TestOverride.ForcePass = map[*FTWRegexp]string{forcePass: "forced"}

	runnerConfig := NewRunnerConfiguration(cfg)

	s.Empty(runnerConfig.TestOverride.Ignore)
	s.Equal(map[*FTWRegexp]string{ignore: "ignored", forcePass: "forced"}, runnerConfig.TestOverride.ForcePass)
	// the configuration is not modified
	s.Equal(map[*FTWRegexp]string{forcePass: "forced"}, cfg.TestOverride.ForcePass)
}
