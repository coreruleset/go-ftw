// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"fmt"
	"strings"

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
		result = !c.log.Contains(logExpectations.NoMatchRegex)
		if !result {
			log.Debug().Msgf("Unexpectedly found match for '%s'", logExpectations.NoMatchRegex)
		}
	}
	if result && len(logExpectations.NoExpectIds) > 0 {
		result = !c.log.Contains(generateIdRegex(logExpectations.NoExpectIds))
		if !result {
			log.Debug().Msg("Unexpectedly found IDs")
		}
	}
	return result
}

// AssertLogContains returns true when the logs contain the string
func (c *FTWCheck) assertLogContains() bool {
	logExpectations := c.expected.Log
	result := true
	if logExpectations.MatchRegex != "" {
		result = c.log.Contains(logExpectations.MatchRegex)
		if !result {
			log.Debug().Msgf("Failed to find match for match_regex. Expected to find '%s'", logExpectations.MatchRegex)
		}
	}
	if result && len(logExpectations.ExpectIds) > 0 {
		result = c.log.Contains(generateIdRegex(logExpectations.ExpectIds))
		if !result {
			log.Debug().Msg("Failed to find expected IDs")
		}
	}
	return result
}

// Search for both standard ModSecurity, and JSON output
func generateIdRegex(ids []uint) string {
	modSecLogSyntax := strings.Builder{}
	jsonLogSyntax := strings.Builder{}
	modSecLogSyntax.WriteString(`\[id "(?:`)
	jsonLogSyntax.WriteString(`"id":\s*"?(?:`)
	for index, id := range ids {
		if index > 0 {
			modSecLogSyntax.WriteRune('|')
			jsonLogSyntax.WriteRune('|')
		}
		modSecLogSyntax.WriteString(fmt.Sprint(id))
		jsonLogSyntax.WriteString(fmt.Sprint(id))
	}
	modSecLogSyntax.WriteString(`)"\]`)
	jsonLogSyntax.WriteString(`)"?`)

	return modSecLogSyntax.String() + "|" + jsonLogSyntax.String()
}
