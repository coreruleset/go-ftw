package check

import (
	"strings"

	"github.com/rs/zerolog/log"
)

// AssertResponseContains checks that the http response contains the needle
func (c *FTWCheck) AssertResponseContains(response string) bool {
	if c.expected.ResponseContains != "" {
		log.Debug().Msgf("ftw/check: is %s contained in response %s", c.expected.ResponseContains, response)
		return strings.Contains(response, c.expected.ResponseContains)
	}
	return false
}
