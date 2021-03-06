package check

// AssertNoLogContains returns true is the string is not found in the logs
func (c *FTWCheck) AssertNoLogContains() bool {
	return !c.log.Contains(c.expected.NoLogContains)
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) AssertLogContains() bool {
	return c.log.Contains(c.expected.LogContains)
}
