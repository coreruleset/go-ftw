// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"github.com/coreruleset/ftw-tests-schema/types"
	"github.com/coreruleset/go-ftw/ftwhttp"
)

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
	// Deprecated: replaced with AutocompleteHeaders
	StopMagic               *bool   `yaml:"stop_magic" koanf:"stop_magic,omitempty"`
	AutocompleteHeaders     *bool   `yaml:"autocomplete_headers" koanf:"autocomplete_headers,omitempty"`
	EncodedRequest          *string `yaml:"encoded_request,omitempty" koanf:"encoded_request,omitempty"`
	RAWRequest              *string `yaml:"raw_request,omitempty" koanf:"raw_request,omitempty"`
	OverrideEmptyHostHeader *bool   `yaml:"override_empty_host_header,omitempty" koanf:"override_empty_host_header,omitempty"`
}

// ApplyInputOverride will check if config had global overrides and write that into the test.
func ApplyInputOverrides(overrides *Overrides, input *types.Input) {
	applySimpleOverrides(overrides, input)
	applyDestAddrOverride(overrides, input)
	applyHeadersOverride(overrides, input)
	if overrides.AutocompleteHeaders != nil || overrides.StopMagic != nil {
		postProcessAutocompleteHeaders(overrides.AutocompleteHeaders, overrides.StopMagic, input)
	}
}

func applyDestAddrOverride(overrides *Overrides, input *types.Input) {
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

func applySimpleOverrides(overrides *Overrides, input *types.Input) {
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

func applyHeadersOverride(overrides *Overrides, input *types.Input) {
	if overrides.Headers != nil {
		if input.Headers == nil {
			input.Headers = ftwhttp.Header{}
		}
		for k, v := range overrides.Headers {
			input.Headers.Set(k, v)
		}
	}
}

func postLoadTestFTWTest(ftwTest *types.FTWTest) {
	for _, test := range ftwTest.Tests {
		postLoadTest(&test)
	}
}

func postLoadTest(test *types.Test) {
	for index := range test.Stages {
		postLoadStage(&test.Stages[index].Stage)
	}
}

func postLoadStage(stage *types.Stage) {
	postLoadInput(&stage.Input)
}

func postLoadInput(input *types.Input) {
	postProcessAutocompleteHeaders(input.AutocompleteHeaders, input.StopMagic, input)
}

func postProcessAutocompleteHeaders(autocompleteHeaders *bool, stopMagic *bool, input *types.Input) {
	autocompleteHeadersMissing := autocompleteHeaders == nil
	stopMagicMissing := stopMagic == nil
	// default value
	finalValue := true

	if autocompleteHeadersMissing && !stopMagicMissing {
		// StopMagic has the inverse boolean logic
		finalValue = !*stopMagic
	} else if !autocompleteHeadersMissing {
		finalValue = *autocompleteHeaders
	}
	input.AutocompleteHeaders = &finalValue
	// StopMagic has the inverse boolean logic
	input.StopMagic = func() *bool { b := !finalValue; return &b }()
}
