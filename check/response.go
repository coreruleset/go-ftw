package check

import (
	"strings"
)

// AssertResponseContains checks that the http response contains the needle
func (c *FTWCheck) AssertResponseContains(response string) bool {
	if c.expected.ResponseContains != "" {
		return strings.Contains(response, c.expected.ResponseContains)
	}
	return false
}

// ResponseContainsRequired checks that the test requires to check the response
func (c *FTWCheck) ResponseContainsRequired() bool {
	if c.expected.ResponseContains == "" {
		return false
	}
	return true
}
