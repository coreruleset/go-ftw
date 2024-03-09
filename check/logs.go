// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"fmt"
)

func (c *FTWCheck) AssertLogs() bool {
	if c.CloudMode() {
		// No logs to check in cloud mode
		return true
	}

	return c.assertLogContains() && c.assertNoLogContains()
}

// AssertNoLogContains returns true is the string is not found in the logs
func (c *FTWCheck) assertNoLogContains() bool {
	logExpectations := c.expected.Log
	result := true
	if logExpectations.NoMatchRegex != "" {
		result = !c.log.Contains(logExpectations.NoMatchRegex)
	}
	if result && logExpectations.NoExpectId != 0 {
		result = !c.log.Contains(generateIdRegex(logExpectations.NoExpectId))
	}
	return result
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) assertLogContains() bool {
	logExpectations := c.expected.Log
	result := true
	if logExpectations.MatchRegex != "" {
		result = c.log.Contains(logExpectations.MatchRegex)
	}
	if result && logExpectations.ExpectId != 0 {
		result = c.log.Contains(generateIdRegex(logExpectations.ExpectId))
	}
	return result
}

// Search for both standard ModSecurity, and JSON output
func generateIdRegex(id int) string {
	return fmt.Sprintf(`\[id "%d"\]|"id":\s*"?%d"?`, id, id)
}
