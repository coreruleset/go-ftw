// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types/overrides"
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
	// DefaultMaxMarkerRetries is the default amount of retries that will be attempted to find the log markers
	DefaultMaxMarkerRetries uint = 20
	// DefaultMaxMarkerLogLines is the default lines we are going read back in a logfile to find the markers
	DefaultMaxMarkerLogLines uint = 500
)

// FTWConfiguration FTW global Configuration
type FTWConfiguration struct {
	// Logfile is the path to the file that contains the WAF logs to check. The path may be absolute or relative, in which case it will be interpreted as relative to the current working directory.
	LogFile string `koanf:"logfile"`
	// PlatformOverrides holds platform specific overrides for tests in the test suite
	PlatformOverrides PlatformOverrides `koanf:"platformoverrides"`
	// TestOverride holds the test overrides that will apply globally
	TestOverride FTWTestOverride `koanf:"testoverride"`
	// LogMarkerHeaderName is the name of the header that will be used by the test framework to mark positions in the log file
	LogMarkerHeaderName string `koanf:"logmarkerheadername"`
	// RunMode stores the mode used to interpret test results. See https://github.com/coreruleset/go-ftw#%EF%B8%8F-cloud-mode.
	RunMode RunMode `koanf:"mode"`
	// MaxMarkerRetries is the maximum number of times the search for log markers will be repeated; each time an additional request is sent to the web server, eventually forcing the log to be flushed
	MaxMarkerRetries uint `koanf:"maxmarkerretries"`
	// MaxMarkerLogLines is the maximum number of lines to search for a marker before aborting
	MaxMarkerLogLines uint `koanf:"maxmarkerloglines"`
	// IncludeTests is a regular expression for tests to include, matched against the rule ID (same as --include)
	IncludeTests *FTWRegexp `koanf:"include"`
	// ExcludeTests is a regular expression for tests to exclude, matched against the rule ID (same as --exclude)
	ExcludeTests *FTWRegexp `koanf:"exclude"`
	// IncludeTags is a regular expression for tests to include, matched aginst the tags of tests (same as --tag)
	IncludeTags *FTWRegexp `koanf:"include_tags"`
}

type PlatformOverrides struct {
	schema.FTWOverrides
	OverridesMap map[uint][]*schema.TestOverride
}

// FTWTestOverride holds four lists:
//
//	Overrides allows you to override input parameters in tests. An example usage is if you want to change the `dest_addr` of all tests to point to an external IP or host.
//	Ignore is for tests you want to ignore. You should add a comment on why you ignore the test
//	ForcePass is for tests you want to pass unconditionally. You should add a comment on why you force to pass the test
//	ForceFail is for tests you want to fail unconditionally. You should add a comment on why you force to fail the test
type FTWTestOverride struct {
	Overrides Overrides             `koanf:"input"`
	Ignore    map[*FTWRegexp]string `koanf:"ignore"`
	ForcePass map[*FTWRegexp]string `koanf:"forcepass"`
	ForceFail map[*FTWRegexp]string `koanf:"forcefail"`
}

// Overrides represents the overridden inputs that have to be applied to tests
type Overrides struct {
	DestAddr   *string           `yaml:"dest_addr,omitempty" koanf:"dest_addr,omitempty"`
	Port       *int              `yaml:"port,omitempty" koanf:"port,omitempty"`
	Protocol   *string           `yaml:"protocol,omitempty" koanf:"protocol,omitempty"`
	URI        *string           `yaml:"uri,omitempty" koanf:"uri,omitempty"`
	Version    *string           `yaml:"version,omitempty" koanf:"version,omitempty"`
	Headers    map[string]string `yaml:"headers,omitempty" koanf:"headers,omitempty"`
	Method     *string           `yaml:"method,omitempty" koanf:"method,omitempty"`
	Data       *string           `yaml:"data,omitempty" koanf:"data,omitempty"`
	SaveCookie *bool             `yaml:"save_cookie,omitempty" koanf:"save_cookie,omitempty"`
	// Deprecated: replaced with AutocompleteHeaders
	StopMagic               *bool   `yaml:"stop_magic" koanf:"stop_magic,omitempty"`
	AutocompleteHeaders     *bool   `yaml:"autocomplete_headers" koanf:"autocomplete_headers,omitempty"`
	EncodedRequest          *string `yaml:"encoded_request,omitempty" koanf:"encoded_request,omitempty"`
	OverrideEmptyHostHeader *bool   `yaml:"override_empty_host_header,omitempty" koanf:"override_empty_host_header,omitempty"`
}

// FTWRegexp is a wrapper around regexp.Regexp that implements the Unmarshaler interface
type FTWRegexp regexp.Regexp

// UnmarshalText implements the Unmarshaler interface
func (r *FTWRegexp) UnmarshalText(b []byte) error {
	re, err := regexp.Compile(string(b))
	if err != nil {
		return fmt.Errorf("invalid regexp: %w", err)
	}
	*r = FTWRegexp(*re)
	return nil
}

// MatchString implements the MatchString method of the regexp.Regexp struct
func (r *FTWRegexp) MatchString(s string) bool {
	return (*regexp.Regexp)(r).MatchString(s)
}

// NewFTWRegexp creates a new FTWRegexp from a string
func NewFTWRegexp(s string) (*FTWRegexp, error) {
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp: %w", err)
	}
	return (*FTWRegexp)(re), nil
}
