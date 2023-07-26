// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

// AssertNoLogContains returns true is the string is not found in the logs
func (c *FTWCheck) AssertNoLogContains() bool {
	if c.expected.NoLogContains != "" {
		return !c.log.Contains(c.expected.NoLogContains)
	}
	return false
}

// NoLogContainsRequired checks that the test requires no_log_contains
func (c *FTWCheck) NoLogContainsRequired() bool {
	return c.expected.NoLogContains != ""
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) AssertLogContains() bool {
	if c.expected.LogContains != "" {
		return c.log.Contains(c.expected.LogContains)
	}
	return false
}

// LogContainsRequired checks that the test requires log_contains
func (c *FTWCheck) LogContainsRequired() bool {
	return c.expected.LogContains != ""
}
