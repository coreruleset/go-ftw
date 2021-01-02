package check

import "github.com/rs/zerolog/log"

// Status will match the expected status list with the one received in the response
func Status(status int, expectedStatus []int) bool {
	log.Debug().Msgf("ftw/check: status %d, expected %v", status, expectedStatus)
	for _, i := range expectedStatus {
		if i == status {
			return true
		}
	}
	return false
}
