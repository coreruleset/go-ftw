// Package waflog encapsulates getting logs from a WAF to compare with expected results
package waflog

import (
	"github.com/coreruleset/go-ftw/config"
	"os"
)

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	cfg         *config.FTWConfiguration
	logFile     *os.File
	StartMarker []byte
	EndMarker   []byte
}

// FTWLogOption follows the option pattern for FTWLogLines
type FTWLogOption func(*FTWLogLines)
