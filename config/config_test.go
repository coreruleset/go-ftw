package config

import (
	"os"
	"reflect"
	"strings"
	"testing"

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
    '920400-1': 'This test result must be ignored'
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

func TestNewConfigBadFileConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(jsonConfig, "test-*.yaml")
	defer os.Remove(filename)
	err := NewConfigFromFile(filename)
	assert.NoError(t, err)
}

func TestNewConfigConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")

	err := NewConfigFromFile(filename)
	assert.NoError(t, err)
	assert.Greater(t, len(FTWConfig.TestOverride.Ignore), 0, "Failed! Len must be > 0")
	assert.False(t, reflect.ValueOf(FTWConfig.TestOverride.Input).IsZero(), "Failed! Input must not be empty")

	for id, text := range FTWConfig.TestOverride.Ignore {
		assert.True(t, strings.Contains(id, "920400-1"), "Looks like we could not find item to ignore")
		assert.Equal(t, "This test result must be ignored", text, "Text doesn't match")
	}

	overrides := FTWConfig.TestOverride.Input
	assert.NotNil(t, overrides.DestAddr, "Looks like we are not overriding destination address")
	assert.Equal(t, "httpbin.org", *overrides.DestAddr, "Looks like we are not overriding destination address")
}

func TestNewConfigBadConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlBadConfig, "test-*.yaml")
	defer os.Remove(filename)
	_ = NewConfigFromFile(filename)

	assert.NotNil(t, FTWConfig)
}

func TestNewConfigDefaultConfig(t *testing.T) {
	// For this test we need a local .ftw.yaml file
	fileName := ".ftw.yaml"
	_ = os.WriteFile(fileName, []byte(yamlConfig), 0644)
	t.Cleanup(func() {
		os.Remove(fileName)
	})

	_ = NewConfigFromFile("")

	assert.NotNil(t, FTWConfig)
}

func TestNewConfigFromString(t *testing.T) {
	err := NewConfigFromString(yamlConfig)
	assert.NoError(t, err)
}

func TestNewEnvConfigFromString(t *testing.T) {
	err := NewConfigFromString(yamlConfig)
	assert.NoError(t, err)
}

func TestNewConfigFromEnv(t *testing.T) {
	// Set some environment so it gets merged with conf
	os.Setenv("FTW_LOGFILE", "kaonf")

	err := NewConfigFromEnv()
	assert.NoError(t, err)

	assert.Equal(t, "kaonf", FTWConfig.LogFile)
}

func TestNewConfigFromEnvHasDefaults(t *testing.T) {
	err := NewConfigFromEnv()
	assert.NoError(t, err)

	assert.Equalf(t, DefaultRunMode, FTWConfig.RunMode,
		"unexpected default value '%s' for run mode", FTWConfig.RunMode)
	assert.Equalf(t, DefaultLogMarkerHeaderName, FTWConfig.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)

}

func TestNewConfigFromFileHasDefaults(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")
	defer os.Remove(filename)

	err := NewConfigFromFile(filename)
	assert.NoError(t, err)

	assert.Equalf(t, DefaultRunMode, FTWConfig.RunMode,
		"unexpected default value '%s' for run mode", FTWConfig.RunMode)
	assert.Equalf(t, DefaultLogMarkerHeaderName, FTWConfig.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)
}

func TestNewConfigFromStringHasDefaults(t *testing.T) {
	err := NewConfigFromString("")
	assert.NoError(t, err)

	assert.Equalf(t, DefaultRunMode, FTWConfig.RunMode,
		"unexpected default value '%s' for run mode", FTWConfig.RunMode)
	assert.Equalf(t, DefaultLogMarkerHeaderName, FTWConfig.LogMarkerHeaderName,
		"unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)
}

func TestNewConfigFromFileRunMode(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlCloudConfig, "test-*.yaml")
	defer os.Remove(filename)

	err := NewConfigFromFile(filename)
	assert.NoError(t, err)

	assert.Equalf(t, CloudRunMode, FTWConfig.RunMode,
		"unexpected value '%s' for run mode, expected '%s;", FTWConfig.RunMode, CloudRunMode)
}
