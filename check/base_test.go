package check

import (
	"sort"
	"testing"

	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/test"
)

var yamlApacheConfig = `---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
`

var yamlNginxConfig = `---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
`

var yamlCloudConfig = `---
mode: "cloud"
`

func TestNewCheck(t *testing.T) {
	err := config.NewConfigFromString(yamlNginxConfig)
	if err != nil {
		t.Error(err)
	}

	c := NewCheck(config.FTWConfig)

	for _, text := range c.overrides.Ignore {
		if text != "Ignore Me" {
			t.Errorf("Well, didn't match Ignore Me")
		}
	}

	to := test.Output{
		Status:           []int{200},
		ResponseContains: "",
		LogContains:      "nothing",
		NoLogContains:    "",
		ExpectError:      true,
	}
	c.SetExpectTestOutput(&to)

	if c.expected.ExpectError != true {
		t.Error("Problem setting expected output")
	}

	c.SetNoLogContains("nologcontains")

	if c.expected.NoLogContains != "nologcontains" {
		t.Error("PRoblem setting nologcontains")
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

	c.SetLogContains("")
	c.SetNoLogContains("no log contains")
	// this should override logcontains
	c.SetCloudMode()

	cloudStatus = c.expected.Status
	sort.Ints(cloudStatus)
	found := false
	for _, n := range cloudStatus {
		if n == 200 {
			found = true
		}
	}
	if !found {
		t.Errorf("couldn't find expected 200 status\n")
	}

}
