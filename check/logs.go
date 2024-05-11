// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"github.com/rs/zerolog/log"
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
		result = !c.log.MatchesRegex(logExpectations.NoMatchRegex)
		if !result {
			log.Debug().Msgf("Unexpectedly found match for '%s'", logExpectations.NoMatchRegex)
		}
	}
	if result && len(logExpectations.NoExpectIds) > 0 {
		found, foundRules := c.log.ContainsAnyId(logExpectations.NoExpectIds)
		if found {
			log.Debug().Msgf("Unexpectedly found the following IDs in the log: %v", foundRules)
			result = false
		}
	}
	return result
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) assertLogContains() bool {
	logExpectations := c.expected.Log
	result := true
	if logExpectations.MatchRegex != "" {
		result = c.log.MatchesRegex(logExpectations.MatchRegex)
		if !result {
			log.Debug().Msgf("Failed to find match for match_regex. Expected to find '%s'", logExpectations.MatchRegex)
		}
	}
	if result && len(logExpectations.ExpectIds) > 0 {
		found, missedRules := c.log.ContainsAllIds(logExpectations.ExpectIds)
		if !found {
			log.Debug().Msgf("Failed to find the following IDs in the log: %v", missedRules)
			result = false
		}
	}

	if c.expected.Isolated {
		ruleIds := c.log.TriggeredRules()
		result = len(ruleIds) == 1
		if !result {
			log.Debug().Msgf("Found more than one triggered rule for isolated test: %v", ruleIds)
		}
	}

	return result
}
