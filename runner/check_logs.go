// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"github.com/rs/zerolog/log"
)

func (c *FTWCheck) AssertLogs() (bool, error) {
	if c.CloudMode() {
		// No logs to check in cloud mode
		return true, nil
	}

	contains, err := c.assertLogContains()
	if err != nil {
		return false, err
	}
	notContains, err := c.assertNoLogContains()
	if err != nil {
		return false, err
	}

	return contains && notContains, nil
}

// AssertNoLogContains returns true is the string is not found in the logs
func (c *FTWCheck) assertNoLogContains() (bool, error) {
	logExpectations := c.expected.Log
	if logExpectations.NoMatchRegex != "" {
		found, err := c.log.MatchesRegex(logExpectations.NoMatchRegex)
		if err != nil {
			return false, err
		}
		if found {
			log.Debug().Msgf("Unexpectedly found match for '%s'", logExpectations.NoMatchRegex)
			return false, nil
		}
	}
	if len(logExpectations.NoExpectIds) > 0 {
		found, foundRules, err := c.log.ContainsAnyId(logExpectations.NoExpectIds)
		if err != nil {
			return false, err
		}
		if found {
			log.Debug().Msgf("Unexpectedly found the following IDs in the log: %v", foundRules)
			return false, nil
		}
	}
	return true, nil
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) assertLogContains() (bool, error) {
	logExpectations := c.expected.Log
	if logExpectations.MatchRegex != "" {
		found, err := c.log.MatchesRegex(logExpectations.MatchRegex)
		if err != nil {
			return false, err
		}
		if !found {
			log.Debug().Msgf("Failed to find match for match_regex. Expected to find '%s'", logExpectations.MatchRegex)
			return false, nil
		}
	}
	if len(logExpectations.ExpectIds) > 0 {
		found, missedRules, err := c.log.ContainsAllIds(logExpectations.ExpectIds)
		if err != nil {
			return false, err
		}
		if !found {
			log.Debug().Msgf("Failed to find the following IDs in the log: %v", missedRules)
			return false, nil
		}
	}

	if c.expected.Isolated {
		ruleIds, err := c.log.TriggeredRules()
		if err != nil {
			return false, err
		}
		if len(ruleIds) != 1 {
			log.Debug().Msgf("Found more than one triggered rule for isolated test: %v", ruleIds)
			return false, nil
		}
	}

	return true, nil
}
