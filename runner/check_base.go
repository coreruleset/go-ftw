// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	schema "github.com/coreruleset/ftw-tests-schema/v2/types"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/test"
	"github.com/coreruleset/go-ftw/waflog"
)

// FTWCheck is the base struct for checking test results
type FTWCheck struct {
	log      *waflog.FTWLogLines
	expected *test.Output
	cfg      *config.RunnerConfig
}

// NewCheck creates a new FTWCheck, allowing to inject the configuration
func NewCheck(context *TestRunContext) (*FTWCheck, error) {
	check := &FTWCheck{
		log:      context.LogLines,
		cfg:      context.RunnerConfig,
		expected: &test.Output{},
	}

	return check, nil
}

// SetExpectTestOutput sets the combined expected output from this test
func (c *FTWCheck) SetExpectTestOutput(t *test.Output) {
	c.expected = t
}

// SetExpectStatus sets to expect the HTTP status from the test to be in the integer range passed
func (c *FTWCheck) SetExpectStatus(status int) {
	c.expected.Status = status
}

// SetExpectResponse sets the response we expect in the text from the server
func (c *FTWCheck) SetExpectResponse(response string) {
	c.expected.ResponseContains = response
}

// SetExpectError sets the boolean if we are expecting an error from the server
func (c *FTWCheck) SetExpectError(expect bool) {
	c.expected.ExpectError = &expect
}

// SetLogContains sets the string to look for in logs
func (c *FTWCheck) SetLogContains(regex string) {
	//nolint:staticcheck
	c.expected.LogContains = regex
	c.expected.Log.MatchRegex = regex
}

// SetNoLogContains sets the string to look that should not present in logs
func (c *FTWCheck) SetNoLogContains(regex string) {
	//nolint:staticcheck
	c.expected.NoLogContains = regex
	c.expected.Log.NoMatchRegex = regex
}

// ForcedIgnore check if this ID need to be ignored from results
func (c *FTWCheck) ForcedIgnore(testCase *schema.Test) bool {
	for re := range c.cfg.TestOverride.Ignore {
		if re.MatchString(testCase.IdString()) {
			return true
		}
	}
	return false
}

// ForcedPass check if this ID need to be ignored from results
func (c *FTWCheck) ForcedPass(testCase *schema.Test) bool {
	for re := range c.cfg.TestOverride.ForcePass {
		if re.MatchString(testCase.IdString()) {
			return true
		}
	}
	return false
}

// ForcedFail check if this ID need to be ignored from results
func (c *FTWCheck) ForcedFail(testCase *schema.Test) bool {
	for re := range c.cfg.TestOverride.ForceFail {
		if re.MatchString(testCase.IdString()) {
			return true
		}
	}
	return false
}

// CloudMode returns true if we are running in cloud mode
func (c *FTWCheck) CloudMode() bool {
	return c.cfg.RunMode == config.CloudRunMode
}

// SetStartMarker sets the log line that marks the start of the logs to analyze
func (c *FTWCheck) SetStartMarker(marker []byte) {
	c.log.WithStartMarker(marker)
}

// SetEndMarker sets the log line that marks the end of the logs to analyze
func (c *FTWCheck) SetEndMarker(marker []byte) {
	c.log.WithEndMarker(marker)
}

func (c *FTWCheck) GetTriggeredRules() []uint {
	if c.CloudMode() {
		return nil
	}
	// When a test is expecting to trigger an error and it effectively does, markers are not set.
	if len(c.log.StartMarker()) == 0 || len(c.log.EndMarker()) == 0 {
		return nil
	}
	return c.log.TriggeredRules()
}

func (c *FTWCheck) Close() error {
	return c.log.Cleanup()
}
