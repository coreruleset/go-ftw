package config

import (
	"os"
	"regexp"
	"testing"

	"github.com/coreruleset/go-ftw/test"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/utils"
)

var yamlConfig = `---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
testoverride:
  input:
    dest_addr: 'httpbin.org'
    port: '1234'
  ignore:
    '920400-1$': 'This test must be ignored'
`

var yamlCloudConfig = `---
mode: 'cloud'
`

var yamlBadConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
doesNotExist: ""
`

var jsonConfig = `
{"test": "type"}
`

func TestNewConfig(t *testing.T) {
	overrides := FTWTestOverride{
		Input:     test.Input{},
		Ignore:    nil,
		ForcePass: nil,
		ForceFail: nil,
	}
	cfg := NewConfig("mylogfile.log", overrides, "X-Test-Me", "cloud")
	assert.Equal(t, "mylogfile.log", cfg.LogFile)
	assert.Equal(t, "X-Test-Me", cfg.LogMarkerHeaderName)
	assert.Equal(t, CloudRunMode, cfg.RunMode)
}

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	assert.Equal(t, DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName)
	assert.Equal(t, DefaultRunMode, cfg.RunMode)
	assert.Equal(t, "", cfg.LogFile)
}

func TestNewConfigBadFileConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(jsonConfig, "test-*.yaml")
	defer os.Remove(filename)
	cfg, err := NewConfigFromFile(filename)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestNewConfigConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")

	cfg, err := NewConfigFromFile(filename)

	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.TestOverride.Input, "Ignore list must not be empty")

	for id, text := range cfg.TestOverride.Ignore {
		assert.Contains(t, (*regexp.Regexp)(id).String(), "920400-1$", "Looks like we could not find item to ignore")
		assert.Equal(t, "This test must be ignored", text, "Text doesn't match")
	}

	overrides := cfg.TestOverride.Input
	assert.NotNil(t, overrides.DestAddr, "Looks like we are not overriding destination address")
	assert.Equal(t, "httpbin.org", *overrides.DestAddr, "Looks like we are not overriding destination address")
}

func TestNewConfigBadConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlBadConfig, "test-*.yaml")
	defer os.Remove(filename)
	cfg, err := NewConfigFromFile(filename)

	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestNewConfigDefaultConfig(t *testing.T) {
	// For this test we need a local .ftw.yaml file
	fileName := ".ftw.yaml"
	_ = os.WriteFile(fileName, []byte(yamlConfig), 0644)
	t.Cleanup(func() {
		os.Remove(fileName)
	})

	cfg, err := NewConfigFromFile("")
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestNewConfigFromString(t *testing.T) {
	cfg, err := NewConfigFromString(yamlConfig)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestNewEnvConfigFromString(t *testing.T) {
	cfg, err := NewConfigFromString(yamlConfig)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestNewConfigFromEnv(t *testing.T) {
	// Set some environment so it gets merged with conf
	os.Setenv("FTW_LOGFILE", "koanf")

	cfg, err := NewConfigFromEnv()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "koanf", cfg.LogFile)
}

func TestNewConfigFromEnvHasDefaults(t *testing.T) {
	cfg, err := NewConfigFromEnv()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equalf(t, DefaultRunMode, cfg.RunMode,
		"unexpected default value '%s' for run mode", cfg.RunMode)
	assert.Equalf(t, DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", cfg.LogMarkerHeaderName)

}

func TestNewConfigFromFileHasDefaults(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")
	defer os.Remove(filename)

	cfg, err := NewConfigFromFile(filename)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equalf(t, DefaultRunMode, cfg.RunMode,
		"unexpected default value '%s' for run mode", cfg.RunMode)
	assert.Equalf(t, DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", cfg.LogMarkerHeaderName)
}

func TestNewConfigFromStringHasDefaults(t *testing.T) {
	cfg, err := NewConfigFromString("")
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equalf(t, DefaultRunMode, cfg.RunMode,
		"unexpected default value '%s' for run mode", cfg.RunMode)
	assert.Equalf(t, DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", cfg.LogMarkerHeaderName)
}

func TestNewConfigFromFileRunMode(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlCloudConfig, "test-*.yaml")
	defer os.Remove(filename)

	cfg, err := NewConfigFromFile(filename)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equalf(t, CloudRunMode, cfg.RunMode,
		"unexpected value '%s' for run mode, expected '%s;", cfg.RunMode, CloudRunMode)
}

func TestNewDefaultConfigWithParams(t *testing.T) {
	cfg := NewDefaultConfig()
	assert.Equal(t, DefaultLogMarkerHeaderName, cfg.LogMarkerHeaderName)
	assert.Equal(t, DefaultRunMode, cfg.RunMode)
	assert.Equal(t, "", cfg.LogFile)
	cfg.WithLogfile("mylogfile.log")
	assert.Equal(t, "mylogfile.log", cfg.LogFile)
	overrides := FTWTestOverride{
		Input:     test.Input{},
		Ignore:    nil,
		ForcePass: nil,
		ForceFail: nil,
	}
	cfg.WithOverrides(overrides)
	assert.Equal(t, overrides, cfg.TestOverride)
	cfg.WithLogMarkerHeaderName("NEW-MARKER-TEST")
	assert.Equal(t, "NEW-MARKER-TEST", cfg.LogMarkerHeaderName)
	cfg.WithRunMode(CloudRunMode)
	assert.Equal(t, CloudRunMode, cfg.RunMode)
}
