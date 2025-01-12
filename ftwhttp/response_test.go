// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	header_names "github.com/coreruleset/go-ftw/ftwhttp/header_names"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type responseTestSuite struct {
	suite.Suite
	client *Client
	ts     *httptest.Server
}

func (s *responseTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestHResponseTestSuite(t *testing.T) {
	suite.Run(t, new(responseTestSuite))
}

func generateRequestForTesting(keepalive bool) *Request {
	var req *Request
	var connection string

	rl := &RequestLine{
		Method:  "GET",
		URI:     "/",
		Version: "HTTP/1.1",
	}

	if keepalive {
		connection = "keep-alive"
	} else {
		connection = "close"
	}
	h := NewHeader()
	h.Add("Host", "localhost")
	h.Add("User-Agent", "Go Tests")
	h.Add(header_names.Connection, connection)

	req = NewRequest(rl, h, nil, true)

	return req
}

func (s *responseTestSuite) helloClient(w http.ResponseWriter, r *http.Request) {
	n, err := fmt.Fprintln(w, "Hello, client")
	s.Require().NoError(err)
	s.Equal(14, n)
}

func (s *responseTestSuite) testEchoServer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Powered-By", "go-ftw")
	w.WriteHeader(http.StatusOK)
	resp := new(bytes.Buffer)
	for key, value := range r.Header {
		_, err := fmt.Fprintf(resp, "%s=%s,", key, value)
		s.Require().NoError(err)
	}
	_, err := w.Write(resp.Bytes())
	s.Require().NoError(err)
}

func (s *responseTestSuite) responseWithCookies(w http.ResponseWriter, r *http.Request) {
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{Name: "username", Value: "go-ftw", Expires: expiration}
	http.SetCookie(w, &cookie)
	n, err := fmt.Fprintln(w, "Setting Cookies!")
	s.Require().NoError(err)
	s.Equal(17, n)
}

func (s *responseTestSuite) SetupTest() {
	var err error
	s.client, err = NewClient(NewClientConfig())
	s.Require().NoError(err)
}

func (s *responseTestSuite) TearDownTest() {
	s.ts.Close()
}

func (s *responseTestSuite) BeforeTest(_, testName string) {
	var f http.HandlerFunc
	switch testName {
	case "TestResponse":
		f = s.helloClient
	case "TestResponseWithCookies":
		f = s.responseWithCookies
	case "TestResponseChecksFullResponse":
		f = s.testEchoServer
	default:
		f = s.testEchoServer
	}
	s.ts = httptest.NewServer(f)
}

func (s *responseTestSuite) TestResponse() {
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err)

	req := generateRequestForTesting(true)

	err = s.client.NewConnection(*d)
	s.Require().NoError(err)

	response, err := s.client.Do(*req)
	s.Require().NoError(err)

	s.Contains(response.GetFullResponse(), "Hello, client\n")
}

func (s *responseTestSuite) TestResponseChecksFullResponse() {
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err)
	req := generateRequestForTesting(true)

	err = s.client.NewConnection(*d)
	s.Require().NoError(err)

	response, err := s.client.Do(*req)
	s.Require().NoError(err)

	s.Contains(response.GetFullResponse(), "X-Powered-By: go-ftw")
	s.Contains(response.GetFullResponse(), "User-Agent=[Go Tests]")
}
