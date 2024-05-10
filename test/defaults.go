// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"encoding/base64"

	schema "github.com/coreruleset/ftw-tests-schema/types"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/utils"
)

type Input schema.Input
type Output schema.Output
type FTWTest struct {
	schema.FTWTest `yaml:",inline"`
	FileName       string
}

// GetMethod returns the proper semantic when the field is empty
func (i *Input) GetMethod() string {
	if i.Method == nil {
		return "GET"
	}
	return *i.Method
}

// GetURI returns the proper semantic when the field is empty
func (i *Input) GetURI() string {
	if i.URI == nil {
		return "/"
	}
	return *i.URI
}

// GetVersion returns the proper semantic when the field is empty
func (i *Input) GetVersion() string {
	if i.Version == nil {
		return "HTTP/1.1"
	}
	return *i.Version
}

// GetProtocol returns the proper semantic when the field is empty
func (i *Input) GetProtocol() string {
	if i.Protocol == nil {
		return "http"
	}
	return *i.Protocol
}

// GetDestAddr returns the proper semantic when the field is empty
func (i *Input) GetDestAddr() string {
	if i.DestAddr == nil {
		return "localhost"
	}
	return *i.DestAddr
}

// GetPort returns the proper semantic when the field is empty
func (i *Input) GetPort() int {
	if i.Port == nil {
		return 80
	}
	return *i.Port
}

// GetHeaders returns the headers wrapped in a ftwhttp.Header
func (i *Input) GetHeaders() ftwhttp.Header {
	if i.Headers == nil {
		return ftwhttp.Header{}
	}
	return ftwhttp.Header(i.Headers)
}

// GetRawRequest returns the proper raw data, and error if there was none
func (i *Input) GetRawRequest() ([]byte, error) {
	if utils.IsNotEmpty(i.EncodedRequest) {
		// if Encoded, first base64 decode, then dump
		return base64.StdEncoding.DecodeString(i.EncodedRequest)
	}
	//nolint:staticcheck
	if utils.IsNotEmpty(i.RAWRequest) {
		//nolint:staticcheck
		return []byte(i.RAWRequest), nil
	}
	return nil, nil
}

// GetAutocompleteHeaders returns the autocompleteHeaders value, defaults to true
func (i *Input) GetAutocompleteHeaders() bool {
	if i.AutocompleteHeaders == nil {
		return true
	}
	return *i.AutocompleteHeaders
}
