// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type connectionTestSuite struct {
	suite.Suite
}

func TestConnectionTestSuite(t *testing.T) {
	suite.Run(t, new(connectionTestSuite))
}

func (s *connectionTestSuite) TestDestinationFromString() {
	d, err := DestinationFromString("http://example.com:80")
	s.Require().NoError(err, "This should not error")
	s.Equal("example.com", d.DestAddr, "Error parsing destination")
	s.Equal(80, d.Port, "Error parsing destination")
	s.Equal("http", d.Protocol, "Error parsing destination")
}

func (s *connectionTestSuite) TestMultipleRequestTypes() {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/path",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two`)
	req = NewRequest(rl, h, data, true)

	s.True(req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
}
