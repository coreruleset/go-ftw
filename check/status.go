package check

import "github.com/rs/zerolog/log"

// AssertStatus will match the expected status list with the one received in the response
func (c *FTWCheck) AssertStatus(status int) bool {
	log.Trace().Msgf("ftw/check: status %d, expected %v", status, c.expected.Status)
	for _, i := range c.expected.Status {
		if i == status {
			return true
		}
	}
	return false
}
