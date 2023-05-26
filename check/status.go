package check

// AssertStatus will match the expected status list with the one received in the response
func (c *FTWCheck) AssertStatus(status int) bool {
	for _, i := range c.expected.Status {
		if i == status {
			return true
		}
	}
	return false
}

// StatusCodeRequired checks that the test requires to check the returned status code
func (c *FTWCheck) StatusCodeRequired() bool {
	return c.expected.Status != nil
}
