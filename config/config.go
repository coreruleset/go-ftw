package config

import (
	"time"
)

// FTWConfig is being exported to be used across the app
var FTWConfig *FTWConfiguration

// FTWConfiguration FTW global Configuration
type FTWConfiguration struct {
	LogFile      string
	LogType      FTWLogType
	LogTruncate  bool
	TestOverride FTWTestOverride
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

// FTWTestOverride holds three lists:
//   Ignore is for tests you want to ignore. It will still execute the test, but ignore the results. You should add a comment on why you ignore the test
//   ForcePass is for tests you want to pass unconditionally. Test will be executed, and pass even when the test fails. You should add a comment on why you force pass the test
//   ForceFail is for tests you want to fail unconditionally. Test will be executed, and fail even when the test passes. You should add a comment on why you force fail the test
type FTWTestOverride struct {
	Ignore    map[string]string
	ForcePass map[string]string
	ForceFail map[string]string
}
