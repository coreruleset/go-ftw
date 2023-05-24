package test

import "github.com/coreruleset/go-ftw/ftwhttp"

// Input represents the input request in a stage
// The fields `Version`, `Method` and `URI` we want to explicitly now when they are set to ""

type Input struct {
	DestAddr       *string        `yaml:"dest_addr,omitempty" koanf:"dest_addr,omitempty"`
	Port           *int           `yaml:"port,omitempty" koanf:"port,omitempty"`
	Protocol       *string        `yaml:"protocol,omitempty" koanf:"protocol,omitempty"`
	URI            *string        `yaml:"uri,omitempty" koanf:"uri,omitempty"`
	Version        *string        `yaml:"version,omitempty" koanf:"version,omitempty"`
	Headers        ftwhttp.Header `yaml:"headers,omitempty" koanf:"headers,omitempty"`
	Method         *string        `yaml:"method,omitempty" koanf:"method,omitempty"`
	Data           *string        `yaml:"data,omitempty" koanf:"data,omitempty"`
	SaveCookie     bool           `yaml:"save_cookie,omitempty" koanf:"save_cookie,omitempty"`
	StopMagic      bool           `yaml:"stop_magic" koanf:"stop_magic,omitempty"`
	EncodedRequest string         `yaml:"encoded_request,omitempty" koanf:"encoded_request,omitempty"`
	RAWRequest     string         `yaml:"raw_request,omitempty" koanf:"raw_request,omitempty"`
}

// Overrides represents the overridden inputs that have to be applied to tests
type Overrides struct {
	DestAddr *string        `yaml:"dest_addr,omitempty" koanf:"dest_addr,omitempty"`
	Port     *int           `yaml:"port,omitempty" koanf:"port,omitempty"`
	Protocol *string        `yaml:"protocol,omitempty" koanf:"protocol,omitempty"`
	URI      *string        `yaml:"uri,omitempty" koanf:"uri,omitempty"`
	Version  *string        `yaml:"version,omitempty" koanf:"version,omitempty"`
	Headers  ftwhttp.Header `yaml:"headers,omitempty" koanf:"headers,omitempty"`
	Method   *string        `yaml:"method,omitempty" koanf:"method,omitempty"`
	Data     *string        `yaml:"data,omitempty" koanf:"data,omitempty"`
	//SaveCookie              bool           `yaml:"save_cookie,omitempty" koanf:"save_cookie,omitempty"`
	StopMagic               *bool   `yaml:"stop_magic" koanf:"stop_magic,omitempty"`
	EncodedRequest          *string `yaml:"encoded_request,omitempty" koanf:"encoded_request,omitempty"`
	RAWRequest              *string `yaml:"raw_request,omitempty" koanf:"raw_request,omitempty"`
	OverrideEmptyHostHeader bool    `yaml:"override_empty_host_header,omitempty" koanf:"override_empty_host_header,omitempty"`
}

// Output is the response expected from the test
type Output struct {
	Status           []int  `yaml:"status,flow,omitempty"`
	ResponseContains string `yaml:"response_contains,omitempty"`
	LogContains      string `yaml:"log_contains,omitempty"`
	NoLogContains    string `yaml:"no_log_contains,omitempty"`
	ExpectError      bool   `yaml:"expect_error,omitempty"`
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
		Enabled     bool   `yaml:"enabled,omitempty"`
		Name        string `yaml:"name,omitempty"`
		Description string `yaml:"description,omitempty"`
	} `yaml:"meta"`
	Tests []Test `yaml:"tests"`
}
