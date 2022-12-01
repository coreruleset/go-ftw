package check

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/test"
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
	cfg, err := config.NewConfigFromString(yamlNginxConfig)
	assert.NoError(t, err)

	c := NewCheck(cfg)

	for _, text := range c.cfg.TestOverride.Ignore {
		assert.Equal(t, text, "Ignore Me", "Well, didn't match Ignore Me")
	}

	to := test.Output{
		Status:           []int{200},
		ResponseContains: "",
		LogContains:      "nothing",
		NoLogContains:    "",
		ExpectError:      true,
	}
	c.SetExpectTestOutput(&to)

	assert.True(t, c.expected.ExpectError, "Problem setting expected output")

	c.SetNoLogContains("nologcontains")

	assert.Equal(t, c.expected.NoLogContains, "nologcontains", "Problem setting nologcontains")
}

func TestForced(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlNginxConfig)
	assert.NoError(t, err)

	c := NewCheck(cfg)

	assert.True(t, c.ForcedIgnore("942200-1"), "Can't find ignored value")

	assert.False(t, c.ForcedFail("1245"), "Value should not be found")

	assert.False(t, c.ForcedPass("1245"), "Value should not be found")
}

func TestCloudMode(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlCloudConfig)
	assert.NoError(t, err)

	c := NewCheck(cfg)

	assert.True(t, c.CloudMode(), "couldn't detect cloud mode")

	status := []int{200, 301}
	c.SetExpectStatus(status)
	c.SetLogContains("this text")
	// this should override logcontains
	c.SetCloudMode()

	cloudStatus := c.expected.Status
	sort.Ints(cloudStatus)
	res := sort.SearchInts(cloudStatus, 403)
	assert.Equalf(t, 2, res, "couldn't find expected 403 status in %#v -> %d", cloudStatus, res)

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
	assert.True(t, found, "couldn't find expected 200 status")

}
