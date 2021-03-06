package config

import (
	"io/ioutil"
	"testing"

	"github.com/fzipi/go-ftw/utils"
)

var yamlConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
`

var yamlBadConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 1234
  nonexisting:  ""
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
`

var jsonConfig = `
{"test": "type"}
`

func TestInitConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlConfig, "test-*.yaml")

	Init(filename)

	if FTWConfig.LogType.Name != "apache" {
		t.Errorf("Failed !")
	}

	if FTWConfig.LogType.TimeFormat != "ddd MMM DD HH:mm:ss.S YYYY" {
		t.Errorf("Failed !")
	}
}

func TestInitBadFileConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(jsonConfig, "test-*.yaml")

	Init(filename)
}

func TestInitBadConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlBadConfig, "test-*.yaml")

	Init(filename)

	if FTWConfig == nil {
		t.Errorf("Failed !")
	}
}

func TestInitDefaultConfig(t *testing.T) {
	// For this test we need a local .ftw.yaml file
	_ = ioutil.WriteFile(".ftw.yaml", []byte(yamlConfig), 0644)

	Init("")

	if FTWConfig == nil {
		t.Errorf("Failed !")
	}
}

func TestImportConfig(t *testing.T) {
	ImportFromString(yamlConfig)

	if FTWConfig.LogType.Name != "apache" {
		t.Errorf("Failed !")
	}

	if FTWConfig.LogType.TimeFormat != "ddd MMM DD HH:mm:ss.S YYYY" {
		t.Errorf("Failed !")
	}
}
