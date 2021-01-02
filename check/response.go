package check

import (
	"io"
)

// ResponseContains checks that the http response contains the needle
func ResponseContains(response io.ReadCloser, contains string) bool {
	return false
}

// ExpectedError is called when there is an error in communication to check if we expected it or not
func ExpectedError(err error, expectError bool) bool {
	if expectError && err != nil {
		return true
	}
	return false
}
