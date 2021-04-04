package config

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fzipi/go-ftw/utils"
)

var yamlConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
testoverride:
  ignore:
    '920400-1': 'This test result must be ignored'
`

var yamlBadConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 1234
  nonexisting:  ""
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
`

var yamlTruncateConfig = `
---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
logtruncate: True
logtype:
  name: nginx
  timetruncate:  1s
  timeformat: 'ddd MMM DD HH:mm:ss'

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

	if len(FTWConfig.TestOverride.Ignore) == 0 {
		t.Errorf("Failed! Len must be > 0")
	}

	for id, text := range FTWConfig.TestOverride.Ignore {
		if !strings.Contains(id, "920400-1") {
			t.Errorf("Looks like we could not find item to ignore")
		}
		if text != "This test result must be ignored" {
			t.Errorf("Text doesn't match")
		}
	}
}

func TestInitBadFileConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(jsonConfig, "test-*.yaml")
	defer os.Remove(filename)
	Init(filename)
}

func TestInitBadConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlBadConfig, "test-*.yaml")
	defer os.Remove(filename)
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

func TestTimeTruncateConfig(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlTruncateConfig, "test-*.yaml")
	defer os.Remove(filename)
	Init(filename)

	if FTWConfig.LogType.Name != "nginx" {
		t.Errorf("Failed !")
	}

	if FTWConfig.LogType.TimeFormat != "ddd MMM DD HH:mm:ss" {
		t.Errorf("Failed !")
	}

	if FTWConfig.LogTruncate != true {
		t.Errorf("Trucate file is wrong !")
	}
	if FTWConfig.LogType.TimeTruncate != time.Second {
		t.Errorf("Failed !")
	}
}
