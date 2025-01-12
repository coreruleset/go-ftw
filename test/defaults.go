// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	schema "github.com/coreruleset/ftw-tests-schema/v2/types"

	"github.com/coreruleset/go-ftw/ftwhttp"
)

type Input struct {
	*schema.Input
	effectiveHeaders *ftwhttp.Header
}
type Output schema.Output
type FTWTest struct {
	schema.FTWTest `yaml:",inline"`
	FileName       string
}

func NewInput(input *schema.Input) *Input {
	return &Input{
		input,
		nil,
	}
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
func (i *Input) GetHeaders() *ftwhttp.Header {
	if i.effectiveHeaders != nil {
		return i.effectiveHeaders
	}

	if i.Headers == nil {
		i.effectiveHeaders = ftwhttp.NewHeader()
	} else {
		i.effectiveHeaders = ftwhttp.NewHeaderFromMap(i.Headers)
	}
	return i.effectiveHeaders
}
