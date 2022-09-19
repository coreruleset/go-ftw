package check

import (
	"regexp"

	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/test"
	"github.com/fzipi/go-ftw/waflog"
)

// FTWCheck is the base struct for checking test results
type FTWCheck struct {
	log         *waflog.FTWLogLines
	expected    *test.Output
	overrides   *config.FTWTestOverride
	overridesRE *config.FTWTestOverrideRE
}

// NewCheck creates a new FTWCheck, allowing to inject the configuration
func NewCheck(c *config.FTWConfiguration) *FTWCheck {
	check := &FTWCheck{
		log: &waflog.FTWLogLines{
			FileName:    c.LogFile,
			StartMarker: nil,
			EndMarker:   nil,
		},
		expected:    &test.Output{},
		overrides:   &c.TestOverride,
		overridesRE: overridesIntoRegexes(&c.TestOverride),
	}

	return check
}

func overridesIntoRegexes(c *config.FTWTestOverride) *config.FTWTestOverrideRE {
	overridesRE := new(config.FTWTestOverrideRE)

	overridesRE.Ignore = make(map[string]*regexp.Regexp)
	for id := range c.Ignore {
		var idRE *regexp.Regexp
		idRE = regexp.MustCompile(id)
		overridesRE.Ignore[id] = idRE
	}

	overridesRE.ForceFail = make(map[string]*regexp.Regexp)
	for id := range c.ForceFail {
		var idRE *regexp.Regexp
		idRE = regexp.MustCompile(id)
		overridesRE.ForceFail[id] = idRE
	}

	overridesRE.ForcePass = make(map[string]*regexp.Regexp)
	for id := range c.ForcePass {
		var idRE *regexp.Regexp
		idRE = regexp.MustCompile(id)
		overridesRE.ForcePass[id] = idRE
	}
	return overridesRE
}

// SetExpectTestOutput sets the combined expected output from this test
func (c *FTWCheck) SetExpectTestOutput(t *test.Output) {
	c.expected = t
}

// SetExpectStatus sets to expect the HTTP status from the test to be in the integer range passed
func (c *FTWCheck) SetExpectStatus(s []int) {
	c.expected.Status = s
}

// SetExpectResponse sets the response we expect in the text from the server
func (c *FTWCheck) SetExpectResponse(response string) {
	c.expected.ResponseContains = response
}

// SetExpectError sets the boolean if we are expecting an error from the server
func (c *FTWCheck) SetExpectError(expect bool) {
	c.expected.ExpectError = expect
}

// SetLogContains sets the string to look for in logs
func (c *FTWCheck) SetLogContains(contains string) {
	c.expected.LogContains = contains
}

// SetNoLogContains sets the string to look that should not present in logs
func (c *FTWCheck) SetNoLogContains(contains string) {
	c.expected.NoLogContains = contains
}

// ForcedIgnore check if this id need to be ignored from results
func (c *FTWCheck) ForcedIgnore(id string) bool {
	for _, re := range c.overridesRE.Ignore {
		if re.MatchString(id) {
			return true
		}
	}
	return false
}

// ForcedPass check if this id need to be ignored from results
func (c *FTWCheck) ForcedPass(id string) bool {
	// TODO regex match
	_, ok := c.overrides.ForcePass[id]
	return ok
}

// ForcedFail check if this id need to be ignored from results
func (c *FTWCheck) ForcedFail(id string) bool {
	// TODO regex match
	_, ok := c.overrides.ForceFail[id]
	return ok
}

// CloudMode returns true if we are running in cloud mode
func (c *FTWCheck) CloudMode() bool {
	return config.FTWConfig.RunMode == config.CloudRunMode
}

// SetCloudMode alters the values for expected logs and status code
func (c *FTWCheck) SetCloudMode() {
	var status = c.expected.Status

	if c.expected.LogContains != "" {
		status = append(status, 403)
		c.expected.LogContains = ""
	} else if c.expected.NoLogContains != "" {
		status = append(status, 200, 404, 405)
		c.expected.NoLogContains = ""
	}
	c.expected.Status = status
}

// SetStartMarker sets the log line that marks the start of the logs to analyze
func (c *FTWCheck) SetStartMarker(marker []byte) {
	c.log.StartMarker = marker
}

// SetEndMarker sets the log line that marks the end of the logs to analyze
func (c *FTWCheck) SetEndMarker(marker []byte) {
	c.log.EndMarker = marker
}
