// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"strings"
)

// AssertResponseContains checks that the http response contains the needle
func (c *FTWCheck) AssertResponseContains(response string) bool {
	if c.expected.ResponseContains != "" {
		return strings.Contains(response, c.expected.ResponseContains)
	}
	return true
}
