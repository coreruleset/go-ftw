package config

import (
	"fmt"
	"regexp"

	"github.com/coreruleset/go-ftw/test"
)

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
//	Ignore is for tests you want to ignore. You should add a comment on why you ignore the test
//	ForcePass is for tests you want to pass unconditionally. You should add a comment on why you force to pass the test
//	ForceFail is for tests you want to fail unconditionally. You should add a comment on why you force to fail the test
type FTWTestOverride struct {
	Input     test.Input            `koanf:"input"`
	Ignore    map[*FTWRegexp]string `koanf:"ignore"`
	ForcePass map[*FTWRegexp]string `koanf:"forcepass"`
	ForceFail map[*FTWRegexp]string `koanf:"forcefail"`
}

type FTWRegexp regexp.Regexp

func (r *FTWRegexp) UnmarshalText(b []byte) error {
	re, err := regexp.Compile(string(b))
	if err != nil {
		return fmt.Errorf("invalid regexp: %w", err)
	}
	*r = FTWRegexp(*re)
	return nil
}

func (r *FTWRegexp) MatchString(s string) bool {
	return (*regexp.Regexp)(r).MatchString(s)
}
