// Package waflog encapsulates getting logs from a WAF to compare with expected results
package waflog

import "os"

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	logFile     *os.File
	FileName    string
	StartMarker []byte
	EndMarker   []byte
}

// FTWLogOption follows the option pattern for FTWLogLines
type FTWLogOption func(*FTWLogLines)
