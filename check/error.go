// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import "github.com/rs/zerolog/log"

// AssertExpectError helper to check if this error was expected or not
func (c *FTWCheck) AssertExpectError(err error) (bool, bool) {
	errorExpected := c.expected.ExpectError != nil && *c.expected.ExpectError
	var errorString string
	if err == nil {
		errorString = "-"
	} else {
		errorString = err.Error()
	}
	log.Debug().Caller().Msgf("Error expected: %t. Found: %s", errorExpected, errorString)

	return errorExpected, (errorExpected && err != nil) || (!errorExpected && err == nil)
}
