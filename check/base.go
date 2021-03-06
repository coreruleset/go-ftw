package check

import (
	"time"

	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/test"
	"github.com/fzipi/go-ftw/waflog"
)

// FTWCheck is the base struct for checks
type FTWCheck struct {
	log      *waflog.FTWLogLines
	expected *test.Output
}

// NewCheck creates a new FTWCheck, allowing to inject the configuration
func NewCheck(c *config.FTWConfiguration) *FTWCheck {
	check := &FTWCheck{
		log: &waflog.FTWLogLines{
			FileName:   c.LogFile,
			TimeRegex:  c.LogType.TimeRegex,
			TimeFormat: c.LogType.TimeFormat,
			Since:      time.Now(),
			Until:      time.Now(),
		},
		expected: &test.Output{},
	}

	return check
}

// SetRoundTripTime sets the time the roundtrip took so we can check logs with it
func (c *FTWCheck) SetRoundTripTime(since time.Time, until time.Time) {
	c.log.Since = since
	c.log.Until = until
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
