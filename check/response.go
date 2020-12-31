package check

import (
	"ftw/ftwtest"
	"io"
)

// ResponseContains checks that the http response contains the needle
func ResponseContains(response io.ReadCloser, contains string) bool {
	return false
}

// ExpectError is called when there is an error in communication to check if we expected it or not
func ExpectError(err error, output ftwtest.Output) bool {
	if output.ExpectError && err != nil {
		return true
	}
	return false
}
