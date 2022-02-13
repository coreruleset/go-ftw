package config

import (
	"time"
)

// FTWConfig is being exported to be used across the app
var FTWConfig *FTWConfiguration

// FTWConfiguration FTW global Configuration
type FTWConfiguration struct {
	LogFile      string          `koanf:"logfile"`
	LogType      FTWLogType      `koanf:"logtype"`
	LogTruncate  bool            `koanf:"logtruncate"`
	TestOverride FTWTestOverride `koanf:"testoverride"`
}

// FTWLogType log readers must implement this one
// TimeTruncate is a string that represents a golang time, e.g. 'time.Microsecond', 'time.Second', etc.
// It will be used when comparing times to match logs
type FTWLogType struct {
	Name         string        `koanf:"name"`
	TimeRegex    string        `koanf:"timeregex"`
	TimeFormat   string        `koanf:"timeformat"`
	TimeTruncate time.Duration `koanf:"timetruncate"`
}

// FTWTestOverride holds four lists:
//   Global allows you to override global parameters in tests. An example usage is if you want to change the `dest_addr` of all tests to point to an external IP or host.
//   Ignore is for tests you want to ignore. It will still execute the test, but ignore the results. You should add a comment on why you ignore the test
//   ForcePass is for tests you want to pass unconditionally. Test will be executed, and pass even when the test fails. You should add a comment on why you force pass the test
//   ForceFail is for tests you want to fail unconditionally. Test will be executed, and fail even when the test passes. You should add a comment on why you force fail the test
type FTWTestOverride struct {
	Input     map[string]string `koanf:"input"`
	Ignore    map[string]string `koanf:"ignore"`
	ForcePass map[string]string `koanf:"forcepass"`
	ForceFail map[string]string `koanf:"forcefail"`
}
