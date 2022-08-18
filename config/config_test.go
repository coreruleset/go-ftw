package config

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/fzipi/go-ftw/utils"
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
	if err != nil {
		t.Errorf("Failed!")
	}
}

func TestNewConfigConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")

	err := NewConfigFromFile(filename)
	if err != nil {
		t.Errorf("Failed!")
	}

	if len(FTWConfig.TestOverride.Ignore) == 0 {
		t.Errorf("Failed! Len must be > 0")
	}

	if reflect.ValueOf(FTWConfig.TestOverride.Input).IsZero() {
		t.Errorf("Failed! Input must not be empty")
	}

	for id, text := range FTWConfig.TestOverride.Ignore {
		if !strings.Contains(id, "920400-1") {
			t.Errorf("Looks like we could not find item to ignore")
		}
		if text != "This test result must be ignored" {
			t.Errorf("Text doesn't match")
		}
	}

	overrides := FTWConfig.TestOverride.Input
	if overrides.DestAddr != nil && *overrides.DestAddr != "httpbin.org" {
		t.Errorf("Looks like we are not overriding destination!")
	}
}

func TestNewConfigBadConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlBadConfig, "test-*.yaml")
	defer os.Remove(filename)
	_ = NewConfigFromFile(filename)

	if FTWConfig == nil {
		t.Errorf("Failed !")
	}
}

func TestNewConfigDefaultConfig(t *testing.T) {
	// For this test we need a local .ftw.yaml file
	fileName := ".ftw.yaml"
	_ = os.WriteFile(fileName, []byte(yamlConfig), 0644)
	t.Cleanup(func() {
		os.Remove(fileName)
	})

	_ = NewConfigFromFile("")

	if FTWConfig == nil {
		t.Errorf("Failed !")
	}
}

func TestNewConfigFromString(t *testing.T) {
	err := NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
}

func TestNewEnvConfigFromString(t *testing.T) {
	err := NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
}

func TestNewConfigFromEnv(t *testing.T) {
	// Set some environment so it gets merged with conf
	os.Setenv("FTW_LOGFILE", "kaonf")

	err := NewConfigFromEnv()

	if err != nil {
		t.Error(err)
	}

	if FTWConfig.LogFile != "kaonf" {
		t.Errorf(FTWConfig.LogFile)
	}
}

func TestNewConfigFromEnvHasDefaults(t *testing.T) {
	if err := NewConfigFromEnv(); err != nil {
		t.Error(err)
	}

	if FTWConfig.RunMode != DefaultRunMode {
		t.Errorf("unexpected default value '%s' for run mode", FTWConfig.RunMode)
	}
	if FTWConfig.LogMarkerHeaderName != DefaultLogMarkerHeaderName {
		t.Errorf("unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)
	}
}

func TestNewConfigFromFileHasDefaults(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")
	defer os.Remove(filename)

	if err := NewConfigFromFile(filename); err != nil {
		t.Error(err)
	}

	if FTWConfig.RunMode != DefaultRunMode {
		t.Errorf("unexpected default value '%s' for run mode", FTWConfig.RunMode)
	}
	if FTWConfig.LogMarkerHeaderName != DefaultLogMarkerHeaderName {
		t.Errorf("unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)
	}
}

func TestNewConfigFromStringHasDefaults(t *testing.T) {
	if err := NewConfigFromString(""); err != nil {
		t.Error(err)
	}

	if FTWConfig.RunMode != DefaultRunMode {
		t.Errorf("unexpected default value '%s' for run mode", FTWConfig.RunMode)
	}
	if FTWConfig.LogMarkerHeaderName != DefaultLogMarkerHeaderName {
		t.Errorf("unexpected default value '%s' for logmarkerheadername", FTWConfig.LogMarkerHeaderName)
	}
}

func TestNewConfigFromFileRunMode(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlCloudConfig, "test-*.yaml")
	defer os.Remove(filename)

	if err := NewConfigFromFile(filename); err != nil {
		t.Error(err)
	}

	if FTWConfig.RunMode != CloudRunMode {
		t.Errorf("unexpected value '%s' for run mode, expected '%s;", FTWConfig.RunMode, CloudRunMode)
	}
}
