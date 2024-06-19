// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/utils"
)

var testData = map[string]string{
	"TestNewConfigFromFile": `---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
include:
    '^9.*': 'Include all tests starting with 9'
exclude:
    '^920400-2$': 'Exclude this test'
include_tags:
    '^cookie$': 'Run test tagged with this label'
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
	filename string
	cfg      *FTWConfiguration
}

type envTestSuite struct {
	suite.Suite
}

type baseTestSuite struct {
	suite.Suite
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(baseTestSuite))
	suite.Run(t, new(fileTestSuite))
	suite.Run(t, new(envTestSuite))
}

func (s *fileTestSuite) SetupTest() {
}

func (s *envTestSuite) SetupTest() {
}

func (s *fileTestSuite) BeforeTest(_, name string) {
	var err error
	s.filename, _ = utils.CreateTempFileWithContent(testData[name], "test-*.yaml")
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
	filename, _ := utils.CreateTempFileWithContent(testData["jsonConfig"], "test-*.yaml")
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			s.T().Logf("Error removing file %s: %s", name, err.Error())
		}
	}(filename)
	cfg, err := NewConfigFromFile(filename)
	s.Require().NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromFile() {
	s.NotEmpty(s.cfg.IncludeTests, "Include list must not be empty")
	s.NotEmpty(s.cfg.TestOverride.Overrides, "Ignore list must not be empty")

	for id, text := range s.cfg.IncludeTests {
		s.Require().Contains((*regexp.Regexp)(id).String(), "^9.*", "Looks like we could not find item to include")
		s.Require().Equal("Include all tests starting with 9", text, "Text doesn't match")
	}
	for id, text := range s.cfg.TestOverride.Ignore {
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
	cfg.WithLogfile("mylogfile.log")
	s.Equal("mylogfile.log", cfg.LogFile)
	overrides := FTWTestOverride{
		Overrides: Overrides{},
		Ignore:    nil,
		ForcePass: nil,
		ForceFail: nil,
	}
	cfg.WithOverrides(overrides)
	s.Equal(overrides, cfg.TestOverride)
	cfg.WithLogMarkerHeaderName("NEW-MARKER-TEST")
	s.Equal("NEW-MARKER-TEST", cfg.LogMarkerHeaderName)
	cfg.WithRunMode(CloudRunMode)
	s.Equal(CloudRunMode, cfg.RunMode)
}

func (s *baseTestSuite) TestWithMaxMarker() {
	cfg := NewDefaultConfig()
	cfg.WithMaxMarkerRetries(19)
	s.Equal(uint(19), cfg.MaxMarkerRetries)
	cfg.WithMaxMarkerLogLines(111)
	s.Equal(uint(111), cfg.MaxMarkerLogLines)

}

func (s *baseTestSuite) TestPlatformOverridesDefaults() {
	overrides := NewDefaultConfig().PlatformOverrides
	meta := overrides.Meta
	s.Empty(meta.Annotations)
	s.Empty(meta.Engine)
	s.Empty(meta.Platform)
	s.Empty(overrides.Version)
	s.Empty(overrides.TestOverrides)
}

func (s *baseTestSuite) TestLoadPlatformOverrides() {
	tempDir := s.T().TempDir()
	overridesFile, err := os.CreateTemp(tempDir, "overrides.yaml")
	s.Require().NoError(err)
	_, err = overridesFile.WriteString(`---
version: "v0.0.0"
meta:
  engine: "coraza"
  platform: "go"
  annotations:
    - purpose: "Test loading overrides"
test_overrides:
  - rule_id: 920100
    test_ids: [4, 8]
    reason: 'Invalid uri, Coraza not reached - 404 page not found'
    output:
      status: 404
      log:
        match_regex: 'match.*me'
        no_expect_ids: [1234]
      response_contains: '404'`)

	s.Require().NoError(err)

	cfg := NewDefaultConfig()
	err = cfg.LoadPlatformOverrides(overridesFile.Name())
	s.Require().NoError(err)

	overrides := cfg.PlatformOverrides
	meta := overrides.Meta
	s.Equal("v0.0.0", overrides.Version)
	s.Equal("coraza", meta.Engine)
	s.Equal("go", meta.Platform)
	s.Len(meta.Annotations, 1)
	value, ok := meta.Annotations["purpose"]
	s.True(ok)
	s.Equal("Test loading overrides", value)

	s.Len(overrides.TestOverrides, 1)
	entry := overrides.TestOverrides[0]
	s.Equal(uint(920100), entry.RuleId)
	s.ElementsMatch([]uint{4, 8}, entry.TestIds)
	s.Equal("Invalid uri, Coraza not reached - 404 page not found", entry.Reason)
	s.Equal(404, entry.Output.Status)
	s.Equal("match.*me", entry.Output.Log.MatchRegex)
	s.Len(entry.Output.Log.NoExpectIds, 1)
	s.Equal(uint(1234), entry.Output.Log.NoExpectIds[0])
	s.Equal("404", entry.Output.ResponseContains)
}
