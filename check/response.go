// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"regexp"

	"github.com/rs/zerolog/log"
)

// AssertResponseContains checks that the http response contains the needle
func (c *FTWCheck) AssertResponseContains(response string) bool {
	if c.expected.ResponseContains != "" {
		found, err := regexp.MatchString(c.expected.ResponseContains, response)
		if err != nil {
			log.Fatal().Msgf("Invalid regular expression for matching response contents: '%s'", c.expected.ResponseContains)
		}
		if !found {
			log.Debug().Msgf("Failed to match response contents. Expected to find '%s'", c.expected.ResponseContains)
		}
		return found
	}
	return true
}
