package check

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/suite"

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

type checkBaseTestSuite struct {
	suite.Suite
}

func TestCheckBaseTestSuite(t *testing.T) {
	suite.Run(t, new(checkBaseTestSuite))
}

func (s *checkBaseTestSuite) TestNewCheck() {
	cfg, err := config.NewConfigFromString(yamlNginxConfig)
	s.NoError(err)

	c := NewCheck(cfg)

	for _, text := range c.cfg.TestOverride.Ignore {
		s.Equal(text, "Ignore Me", "Well, didn't match Ignore Me")
	}

	to := test.Output{
		Status:           []int{200},
		ResponseContains: "",
		LogContains:      "nothing",
		NoLogContains:    "",
		ExpectError:      true,
	}
	c.SetExpectTestOutput(&to)

	s.True(c.expected.ExpectError, "Problem setting expected output")

	c.SetNoLogContains("nologcontains")

	s.Equal(c.expected.NoLogContains, "nologcontains", "Problem setting nologcontains")
}

func (s *checkBaseTestSuite) TestForced() {
	cfg, err := config.NewConfigFromString(yamlNginxConfig)
	s.NoError(err)

	c := NewCheck(cfg)

	s.True(c.ForcedIgnore("942200-1"), "Can't find ignored value")

	s.False(c.ForcedFail("1245"), "Value should not be found")

	s.False(c.ForcedPass("1245"), "Value should not be found")
}

func (s *checkBaseTestSuite) TestCloudMode() {
	cfg, err := config.NewConfigFromString(yamlCloudConfig)
	s.NoError(err)

	c := NewCheck(cfg)

	s.True(c.CloudMode(), "couldn't detect cloud mode")

	status := []int{200, 301}
	c.SetExpectStatus(status)
	c.SetLogContains("this text")
	// this should override logcontains
	c.SetCloudMode()

	cloudStatus := c.expected.Status
	sort.Ints(cloudStatus)
	res := sort.SearchInts(cloudStatus, 403)
	s.Equalf(2, res, "couldn't find expected 403 status in %#v -> %d", cloudStatus, res)

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
	s.True(found, "couldn't find expected 200 status")

}
