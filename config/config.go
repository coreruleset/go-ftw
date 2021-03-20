package config

import (
	"time"
)

// FTWConfig is being exported to be used across the app
var FTWConfig *FTWConfiguration

// FTWConfiguration FTW global Configuration
type FTWConfiguration struct {
	LogFile string
	LogType FTWLogType
}

// FTWLogType log readers must implement this one
// TimeTruncate is a string that represents a golang time, e.g. 'time.Microsecond', 'time.Second', etc.
// It will be used when comparing times to match logs
type FTWLogType struct {
	Name         string
	TimeRegex    string
	TimeFormat   string
	TimeTruncate time.Duration
}
