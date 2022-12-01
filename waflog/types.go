// Package waflog encapsulates getting logs from a WAF to compare with expected results
package waflog

import (
	"os"
)

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	logFile             *os.File
	LogMarkerHeaderName []byte
	StartMarker         []byte
	EndMarker           []byte
}
