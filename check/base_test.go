package check

import (
	"sort"
	"testing"

	"github.com/coreruleset/go-ftw/utils"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/test"
)

var configMap = map[string]string{
	"TestNewCheck": `---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
`, "TestForced": `---
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
  forcepass:
    '1245': 'Forced Pass'
  forcefail:
    '6789': 'Forced Fail'
`, "TestCloudMode": `---
mode: "cloud"`,
}

type checkBaseTestSuite struct {
	suite.Suite
	cfg *config.FTWConfiguration
}

func (s *checkBaseTestSuite) BeforeTest(_, name string) {
	var err error
	var logName string
	s.cfg, err = config.NewConfigFromString(configMap[name])
	s.Require().NoError(err)
	logName, err = utils.CreateTempFileWithContent(logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(logName)
}

func TestCheckBaseTestSuite(t *testing.T) {
	suite.Run(t, new(checkBaseTestSuite))
}

func (s *checkBaseTestSuite) TestNewCheck() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

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
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	s.True(c.ForcedIgnore("942200-1"), "Can't find ignored value")

	s.False(c.ForcedFail("1245"), "Value should not be found")

	s.False(c.ForcedPass("1234"), "Value should not be found")

	s.True(c.ForcedPass("1245"), "Value should be found")

	s.True(c.ForcedFail("6789"), "Value should be found")

	s.cfg.TestOverride.Ignore = make(map[*config.FTWRegexp]string)
	s.Falsef(c.ForcedIgnore("anything"), "Should not find ignored value in empty map")

}

func (s *checkBaseTestSuite) TestCloudMode() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

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

func (s *checkBaseTestSuite) TestSetMarkers() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.SetStartMarker([]byte("TesTingStArtMarKer"))
	c.SetEndMarker([]byte("TestIngEnDMarkeR"))
	s.Equal([]byte("testingstartmarker"), c.log.StartMarker, "Couldn't set start marker")
	s.Equal([]byte("testingendmarker"), c.log.EndMarker, "Couldn't set end marker")
}
