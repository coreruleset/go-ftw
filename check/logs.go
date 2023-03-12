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
	if c.expected.NoLogContains == "" {
		return false
	}
	return true
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
	if c.expected.LogContains == "" {
		return false
	}
	return true
}
