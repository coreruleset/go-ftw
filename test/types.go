package test

import (
	"github.com/coreruleset/go-ftw/ftwhttp"
)

// Input represents the input request in a stage
// The fields `Version`, `Method` and `URI` we want to explicitly know when they are set to ""

type Input struct {
	DestAddr   *string        `yaml:"dest_addr,omitempty"`
	Port       *int           `yaml:"port,omitempty"`
	Protocol   *string        `yaml:"protocol,omitempty"`
	URI        *string        `yaml:"uri,omitempty"`
	Version    *string        `yaml:"version,omitempty"`
	Headers    ftwhttp.Header `yaml:"headers,omitempty"`
	Method     *string        `yaml:"method,omitempty"`
	Data       *string        `yaml:"data,omitempty"`
	SaveCookie *bool          `yaml:"save_cookie,omitempty"`
	// Deprecated: replaced with NoAutocompleteHeaders
	StopMagic             *bool  `yaml:"stop_magic"`
	NoAutocompleteHeaders *bool  `yaml:"no_autocomplete_headers"`
	EncodedRequest        string `yaml:"encoded_request,omitempty"`
	RAWRequest            string `yaml:"raw_request,omitempty"`
}

// Overrides represents the overridden inputs that have to be applied to tests
type Overrides struct {
	DestAddr   *string        `yaml:"dest_addr,omitempty" koanf:"dest_addr,omitempty"`
	Port       *int           `yaml:"port,omitempty" koanf:"port,omitempty"`
	Protocol   *string        `yaml:"protocol,omitempty" koanf:"protocol,omitempty"`
	URI        *string        `yaml:"uri,omitempty" koanf:"uri,omitempty"`
	Version    *string        `yaml:"version,omitempty" koanf:"version,omitempty"`
	Headers    ftwhttp.Header `yaml:"headers,omitempty" koanf:"headers,omitempty"`
	Method     *string        `yaml:"method,omitempty" koanf:"method,omitempty"`
	Data       *string        `yaml:"data,omitempty" koanf:"data,omitempty"`
	SaveCookie *bool          `yaml:"save_cookie,omitempty" koanf:"save_cookie,omitempty"`
	// Deprecated: replaced with NoAutocompleteHeaders
	StopMagic               *bool   `yaml:"stop_magic" koanf:"stop_magic,omitempty"`
	NoAutocompleteHeaders   *bool   `yaml:"no_autocomplete_headers" koanf:"no_autocomplete_headers,omitempty"`
	EncodedRequest          *string `yaml:"encoded_request,omitempty" koanf:"encoded_request,omitempty"`
	RAWRequest              *string `yaml:"raw_request,omitempty" koanf:"raw_request,omitempty"`
	OverrideEmptyHostHeader *bool   `yaml:"override_empty_host_header,omitempty" koanf:"override_empty_host_header,omitempty"`
}

// Output is the response expected from the test
type Output struct {
	Status           []int  `yaml:"status,flow,omitempty"`
	ResponseContains string `yaml:"response_contains,omitempty"`
	LogContains      string `yaml:"log_contains,omitempty"`
	NoLogContains    string `yaml:"no_log_contains,omitempty"`
	ExpectError      *bool  `yaml:"expect_error,omitempty"`
}

// Stage is an individual test stage
type Stage struct {
	Input  Input  `yaml:"input"`
	Output Output `yaml:"output"`
}

// Test is an individual test
type Test struct {
	TestTitle       string `yaml:"test_title"`
	TestDescription string `yaml:"desc,omitempty"`
	Stages          []struct {
		Stage Stage `yaml:"stage"`
	} `yaml:"stages"`
}

// FTWTest is the base type used when unmarshaling
type FTWTest struct {
	FileName string
	Meta     struct {
		Author      string `yaml:"author,omitempty"`
		Enabled     *bool  `yaml:"enabled,omitempty"`
		Name        string `yaml:"name,omitempty"`
		Description string `yaml:"description,omitempty"`
	} `yaml:"meta"`
	Tests []Test `yaml:"tests"`
}

// ApplyInputOverride will check if config had global overrides and write that into the test.
func ApplyInputOverrides(overrides *Overrides, input *Input) {
	applySimpleOverrides(overrides, input)
	applyDestAddrOverride(overrides, input)
	applyHeadersOverride(overrides, input)
	postProcessNoAutocompleteHeaders(overrides.NoAutocompleteHeaders, overrides.StopMagic, input)
}

func applyDestAddrOverride(overrides *Overrides, input *Input) {
	if overrides.DestAddr != nil {
		input.DestAddr = overrides.DestAddr
		if input.Headers == nil {
			input.Headers = ftwhttp.Header{}
		}
		if overrides.OverrideEmptyHostHeader != nil && *overrides.OverrideEmptyHostHeader && input.Headers.Get("Host") == "" {
			input.Headers.Set("Host", *overrides.DestAddr)
		}
	}
}

func applySimpleOverrides(overrides *Overrides, input *Input) {
	if overrides.Port != nil {
		input.Port = overrides.Port
	}

	if overrides.Protocol != nil {
		input.Protocol = overrides.Protocol
	}

	if overrides.URI != nil {
		input.URI = overrides.URI
	}

	if overrides.Version != nil {
		input.Version = overrides.Version
	}

	if overrides.Method != nil {
		input.Method = overrides.Method
	}

	if overrides.Data != nil {
		input.Data = overrides.Data
	}

	if overrides.SaveCookie != nil {
		input.SaveCookie = overrides.SaveCookie
	}

	if overrides.EncodedRequest != nil {
		input.EncodedRequest = *overrides.EncodedRequest
	}

	if overrides.RAWRequest != nil {
		input.RAWRequest = *overrides.RAWRequest
	}
}

func applyHeadersOverride(overrides *Overrides, input *Input) {
	if overrides.Headers != nil {
		if input.Headers == nil {
			input.Headers = ftwhttp.Header{}
		}
		for k, v := range overrides.Headers {
			input.Headers.Set(k, v)
		}
	}
}

func postLoadTestFTWTest(ftwTest *FTWTest) {
	for _, test := range ftwTest.Tests {
		postLoadTest(&test)
	}
}

func postLoadTest(test *Test) {
	for index := range test.Stages {
		postLoadStage(&test.Stages[index].Stage)
	}
}

func postLoadStage(stage *Stage) {
	postLoadInput(&stage.Input)
}

func postLoadInput(input *Input) {
	postProcessNoAutocompleteHeaders(input.NoAutocompleteHeaders, input.StopMagic, input)
}

func postProcessNoAutocompleteHeaders(noAutocompleteHeaders *bool, stopMagic *bool, input *Input) {
	noAutocompleteHeadersMissing := noAutocompleteHeaders == nil
	stopMagicMissing := stopMagic == nil
	finalValue := false

	if noAutocompleteHeadersMissing && !stopMagicMissing {
		finalValue = *stopMagic
	} else if !noAutocompleteHeadersMissing {
		finalValue = *noAutocompleteHeaders
	}
	input.NoAutocompleteHeaders = &finalValue
	input.StopMagic = &finalValue
}
