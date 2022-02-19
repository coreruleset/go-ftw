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
