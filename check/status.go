// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import "slices"

var negativeExpectedStatuses = []int{200, 404, 405}

// AssertStatus will match the expected status list with the one received in the response
func (c *FTWCheck) AssertStatus(status int) bool {
	// No status code expectation defined
	if c.expected.Status == 0 {
		return true
	}

	if c.CloudMode() {
		return c.assertCloudStatus(status)
	}

	return c.expected.Status == status

}

func (c *FTWCheck) assertCloudStatus(status int) bool {
	logExpectations := c.expected.Log
	if (logExpectations.MatchRegex != "" || len(logExpectations.ExpectIds) > 0) && status == 403 {
		return true
	}
	if (logExpectations.NoMatchRegex != "" || len(logExpectations.NoExpectIds) > 0) && slices.Contains(negativeExpectedStatuses, status) {
		return true
	}
	return c.expected.Status == status
}
