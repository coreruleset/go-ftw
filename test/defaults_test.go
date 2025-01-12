// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
)

type defaultsTestSuite struct {
	suite.Suite
}

func (s *defaultsTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestDefaultsTestSuite(t *testing.T) {
	suite.Run(t, new(defaultsTestSuite))
}

func getTestInputDefaults() *Input {
	data := "My Data"

	return NewInput(&schema.Input{
		Headers:             map[string]string{},
		Data:                &data,
		SaveCookie:          func() *bool { b := false; return &b }(),
		AutocompleteHeaders: func() *bool { b := false; return &b }(),
	})
}

func getTestExampleInput() *Input {
	destaddr := "192.168.0.1"
	port := 8080
	protocol := "http"
	uri := "/test"
	method := "REPORT"
	version := "HTTP/1.1"

	return NewInput(&schema.Input{
		DestAddr:            &destaddr,
		Port:                &port,
		Protocol:            &protocol,
		URI:                 &uri,
		Version:             &version,
		Headers:             map[string]string{},
		Method:              &method,
		Data:                nil,
		EncodedRequest:      "TXkgRGF0YQo=",
		SaveCookie:          func() *bool { b := false; return &b }(),
		AutocompleteHeaders: func() *bool { b := false; return &b }(),
	})
}

func (s *defaultsTestSuite) TestBasicGetters() {
	input := getTestExampleInput()

	dest := input.GetDestAddr()
	s.Equal("192.168.0.1", dest)
	method := input.GetMethod()
	s.Equal("REPORT", method)
	version := input.GetVersion()
	s.Equal("HTTP/1.1", version)
	port := input.GetPort()
	s.Equal(8080, port)
	proto := input.GetProtocol()
	s.Equal("http", proto)
	uri := input.GetURI()
	s.Equal("/test", uri)
}

func (s *defaultsTestSuite) TestDefaultGetters() {
	inputDefaults := getTestInputDefaults()

	val := inputDefaults.GetDestAddr()
	s.Equal("localhost", val)

	val = inputDefaults.GetMethod()
	s.Equal("GET", val)

	val = inputDefaults.GetVersion()
	s.Equal("HTTP/1.1", val)

	port := inputDefaults.GetPort()
	s.Equal(80, port)

	val = inputDefaults.GetProtocol()
	s.Equal("http", val)

	val = inputDefaults.GetURI()
	s.Equal("/", val)

	s.Equal([]byte("My Data"), []byte(*inputDefaults.Data))
}
