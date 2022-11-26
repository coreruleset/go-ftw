package config

import (
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"
	"os"
	"regexp"
	"testing"

	"github.com/coreruleset/go-ftw/test"
	"github.com/coreruleset/go-ftw/utils"
)

var testData = map[string]string{
	"TestNewConfigFromFile": `---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
testoverride:
  input:
    dest_addr: 'httpbingo.org'
    port: '1234'
  ignore:
    '920400-1$': 'This test must be ignored'
`,
	"cloud": `---
mode: 'cloud'
`,
	"bad": `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
doesNotExist: ""
`,
	"json": `
{"test": "type"}
`,
}

type fileTestSuite struct {
	suite.Suite
	filename string
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(fileTestSuite))
}

func (s *fileTestSuite) SetupTest() {
}

func (s *fileTestSuite) BeforeTest(_, name string) {
    s.filename, _ = utils.CreateTempFileWithContent(testData[name], "test-*.yaml")
    cfg, err := NewConfigFromFile(s.filename)
    s.NoError(err)
}

func (s *fileTestSuite) AfterTest(_ string, _ string) {
    if s.filename != "" {
        _ = os.Remove(s.filename)
        log.Info().Msgf("Deleting temporary file '%s'", s.filename)
    }
}

func (s *fileTestSuite)TestNewDefaultConfig() {
    cfg := NewDefaultConfig()
    s.Equal(DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName)
    s.Equal(DefaultRunMode, cfg.RunMode)
    s.Equal("", cfg.LogFile)
}

func (s *fileTestSuite)TestNewConfigBadFileConfig() {
	filename, _ := utils.CreateTempFileWithContent(jsonConfig, "test-*.yaml")
	defer os.Remove(filename)
	cfg, err := NewConfigFromFile(filename)
	s.NoError(err)
    s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromFile() {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")

	cfg, err := NewConfigFromFile(filename)

	s.NoError(err)
	s.NotNil(cfg)
	s.NotEmpty(cfg.TestOverride.Overrides, "Ignore list must not be empty")

	for id, text := range cfg.TestOverride.Ignore {
		s.Contains((*regexp.Regexp)(id).String(), "920400-1$", "Looks like we could not find item to ignore")
		s.Equal("This test must be ignored", text, "Text doesn't match")
	}

	overrides := cfg.TestOverride.Overrides
	s.NotNil(overrides.DestAddr, "Looks like we are not overriding destination address")
	s.Equal("httpbingo.org", *overrides.DestAddr, "Looks like we are not overriding destination address")
}

func (s *fileTestSuite) TestNewConfigBadConfig() {
	filename, _ := utils.CreateTempFileWithContent(yamlBadConfig, "test-*.yaml")
	defer os.Remove(filename)
	cfg, err := NewConfigFromFile(filename)

	s.NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigDefaultConfig() {
	// For this test we need a local .ftw.yaml file
	fileName := ".ftw.yaml"
	_ = os.WriteFile(fileName, []byte(testData["ok"]), 0644)
	t.Cleanup(func() {
		os.Remove(fileName)
	})

	cfg, err := NewConfigFromFile("")
	s.NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromString() {
    cfg, err := NewConfigFromString(testData["ok"])
	s.NoError(err)
	s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewEnvConfigFromString() {
    cfg, err := NewConfigFromString(testData["ok"])
    s.NoError(err)
    s.NotNil(cfg)
}

func (s *fileTestSuite) TestNewConfigFromEnv() {
	// Set some environment so it gets merged with conf
	os.Setenv("FTW_LOGFILE", "koanf")

	cfg, err := NewConfigFromEnv()
	s.NoError(err)
	s.NotNil(cfg)
	s.Equal("koanf", cfg.LogFile)
}

func (s *fileTestSuite) TestNewConfigFromEnvHasDefaults() {
	cfg, err := NewConfigFromEnv()
	s.NoError(err)
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
	s.NoError(err)
    s.NotNil(cfg)
	s.Equalf(DefaultRunMode, cfg.RunMode,
		"unexpected default value '%s' for run mode", cfg.RunMode)
	s.Equalf(DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)
}

func (s *fileTestSuite) TestNewConfigFromFileRunMode() {
	s.filename, err := utils.CreateTempFileWithContent(testData["cloud"], "test-*.yaml")

	cfg, err := NewConfigFromFile(s.filename)
	s.NoError(err)
	s.NotNil(cfg)
	s.Equalf(CloudRunMode, cfg.RunMode,
		"unexpected value '%s' for run mode, expected '%s;", cfg.RunMode, CloudRunMode)
}

func (s *fileTestSuite)  TestNewDefaultConfigWithParams() {
    cfg := NewDefaultConfig()
    cfg.WithLogfile("mylogfile.log")
    s.Equal("mylogfile.log", cfg.LogFile)
    overrides := FTWTestOverride{
        Overrides: test.Overrides{},
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