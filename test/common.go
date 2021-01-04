package test

import "github.com/fzipi/go-ftw/http"

// Input represents the input request in a stage
// The fields `Version`, `Method` and `URI` we want to explicitly now when they are set to ""
type Input struct {
	DestAddr       *string     `yaml:"dest_addr,omitempty"`
	Port           *int        `yaml:"port,omitempty"`
	Protocol       *string     `yaml:"protocol,omitempty"`
	URI            *string     `yaml:"uri,omitempty"`
	Version        *string     `yaml:"version,omitempty"`
	Headers        http.Header `yaml:"headers,omitempty"`
	Method         *string     `yaml:"method,omitempty"`
	Data           string      `yaml:"data,omitempty"`
	SaveCookie     bool        `yaml:"save_cookie,omitempty"`
	StopMagic      bool        `yaml:"stop_magic"`
	EncodedRequest string      `yaml:"encoded_request,omitempty"`
	RAWRequest     string      `yaml:"raw_request,omitempty"`
}

// Output is the response expected from the test
type Output struct {
	Status           []int  `yaml:"status,flow,omitempty"`
	ResponseContains string `yaml:"response_contains,omitempty"`
	LogContains      string `yaml:"log_contains,omitempty"`
	NoLogContains    string `yaml:"no_log_contains,omitempty"`
	ExpectError      bool   `yaml:"expect_error,omitempty"`
}

// FTWTest is the base type used when unmarshaling
type FTWTest struct {
	Meta struct {
		Author      string `yaml:"author,omitempty"`
		Enabled     bool   `yaml:"enabled,omitempty"`
		Name        string `yaml:"name,omitempty"`
		Description string `yaml:"description,omitempty"`
	} `yaml:"meta"`
	Tests []struct {
		TestTitle       string `yaml:"test_title"`
		TestDescription string `yaml:"desc,omitempty"`
		Stages          []struct {
			Stage struct {
				Input  Input  `yaml:"input"`
				Output Output `yaml:"output"`
			} `yaml:"stage"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}
