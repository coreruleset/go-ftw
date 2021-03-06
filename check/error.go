package check

import "github.com/rs/zerolog/log"

// AssertExpectError helper to check if this error was expected or not
func (c *FTWCheck) AssertExpectError(err error) bool {
	if err != nil {
		log.Debug().Msgf("ftw/check: expected error? -> %t, and error is %s", c.expected.ExpectError, err.Error())
	} else {
		log.Debug().Msgf("ftw/check: expected error? -> %t, and error is nil", c.expected.ExpectError)
	}
	if c.expected.ExpectError && err != nil || !c.expected.ExpectError && err == nil {
		return true
	}
	return false
}
