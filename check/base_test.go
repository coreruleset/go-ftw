package check

import (
	"sort"
	"testing"
	"time"

	"github.com/fzipi/go-ftw/config"
)

var yamlApacheConfig = `---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
`

var yamlNginxConfig = `---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
logtype:
  name: 'nginx'
  timeregex:  '(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})'
  timeformat: 'YYYY/MM/DD HH:mm:ss'
  timetruncate: 1s
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
`

var yamlCloudConfig = `---
testoverride:
  mode: "cloud"
`

func TestNewCheck(t *testing.T) {
	err := config.NewConfigFromString(yamlNginxConfig)
	if err != nil {
		t.Error(err)
	}

	c := NewCheck(config.FTWConfig)

	if c.log.TimeTruncate != time.Second {
		t.Errorf("Failed")
	}

	for _, text := range c.overrides.Ignore {
		if text != "Ignore Me" {
			t.Errorf("Well, didn't match Ignore Me")
		}
	}
}

func TestForced(t *testing.T) {
	err := config.NewConfigFromString(yamlNginxConfig)
	if err != nil {
		t.Error(err)
	}

	c := NewCheck(config.FTWConfig)

	if !c.ForcedIgnore("942200-1") {
		t.Errorf("Can't find ignored value")
	}

	if c.ForcedFail("1245") {
		t.Errorf("Value should not be found")
	}

	if c.ForcedPass("1245") {
		t.Errorf("Value should not be found")
	}
}

func TestCloudMode(t *testing.T) {
	err := config.NewConfigFromString(yamlCloudConfig)
	if err != nil {
		t.Error(err)
	}

	c := NewCheck(config.FTWConfig)

	if c.CloudMode() != true {
		t.Errorf("couldn't detect cloud mode")
	}

	status := []int{200, 301}
	c.SetExpectStatus(status)
	c.SetLogContains("this text")
	// this should override logcontains
	c.SetCloudMode()

	cloudStatus := c.expected.Status
	sort.Ints(cloudStatus)
	if res := sort.SearchInts(cloudStatus, 403); res == 0 {
		t.Errorf("couldn't find expected 403 status in %#v -> %d", cloudStatus, res)
	}
}
