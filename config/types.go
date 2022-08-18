package config

import "github.com/fzipi/go-ftw/test"

// RunMode represents the mode of the test run
type RunMode string

const (
	// CloudRunMode is the string that will be used to override the run mode of execution to cloud
	CloudRunMode RunMode = "cloud"
	// DefaultRunMode is the default execution run mode
	DefaultRunMode RunMode = "default"
	// DefaultLogMarkerHeaderName is the default log marker header name
	DefaultLogMarkerHeaderName string = "X-CRS-Test"
)

// FTWConfig is being exported to be used across the app
var FTWConfig *FTWConfiguration

// FTWConfiguration FTW global Configuration
type FTWConfiguration struct {
	LogFile             string          `koanf:"logfile"`
	TestOverride        FTWTestOverride `koanf:"testoverride"`
	LogMarkerHeaderName string          `koanf:"logmarkerheadername"`
	RunMode             RunMode         `koanf:"mode"`
}

// FTWTestOverride holds four lists:
//
//	Input allows you to override input parameters in tests. An example usage is if you want to change the `dest_addr` of all tests to point to an external IP or host.
//	Ignore is for tests you want to ignore. It will still execute the test, but ignore the results. You should add a comment on why you ignore the test
//	ForcePass is for tests you want to pass unconditionally. Test will be executed, and pass even when the test fails. You should add a comment on why you force pass the test
//	ForceFail is for tests you want to fail unconditionally. Test will be executed, and fail even when the test passes. You should add a comment on why you force fail the test
type FTWTestOverride struct {
	Input     test.Input        `koanf:"input"`
	Ignore    map[string]string `koanf:"ignore"`
	ForcePass map[string]string `koanf:"forcepass"`
	ForceFail map[string]string `koanf:"forcefail"`
}
