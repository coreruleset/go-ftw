package check

// AssertNoLogContains returns true is the string is not found in the logs
func (c *FTWCheck) AssertNoLogContains() bool {
	if c.expected.NoLogContains != "" {
		return !c.log.Contains(c.expected.NoLogContains)
	}
	return false
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) AssertLogContains() bool {
	if c.expected.LogContains != "" {
		return c.log.Contains(c.expected.LogContains)
	}
	return false
}
