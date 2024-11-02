// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

var testFileContentsTemplate = `---
meta:
  author: "go-ftw"
  description: "Test file for go-ftw"
tests:
  - # Standard GET request
    test_id: 1234
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: {{ .Port }}
          headers:
            User-Agent: "OWASP CRS test agent"
            Host: "localhost"
            Accept: "*/*"
          protocol: "http"
          uri: "/"
          version: "HTTP/1.1"
        output:
          status: 200
`

type runCmdTestSuite struct {
	suite.Suite
	tempDir        string
	rootCmd        *cobra.Command
	testHTTPServer *httptest.Server
}

func (s *runCmdTestSuite) setupMockHTTPServer() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := new(bytes.Buffer)
		for key, value := range r.Header {
			_, err := fmt.Fprintf(resp, "%s=%s,", key, value)
			s.Require().NoError(err)
		}

		_, err := w.Write(resp.Bytes())
		s.Require().NoError(err)
	}))
	return server
}

func (s *runCmdTestSuite) SetupTest() {
	s.tempDir = s.T().TempDir()

	s.testHTTPServer = s.setupMockHTTPServer()
	err := os.MkdirAll(s.tempDir, fs.ModePerm)
	s.Require().NoError(err)
	testUrl, err := url.Parse(s.testHTTPServer.URL)
	s.Require().NoError(err)
	port, err := strconv.Atoi(testUrl.Port())
	s.Require().NoError(err)
	vars := map[string]int{
		"Port": port,
	}
	testFileContents, err := os.CreateTemp(s.tempDir, "mock-test-*.yaml")
	s.Require().NoError(err)
	tmpl, err := template.New("mock-test").Parse(testFileContentsTemplate)
	s.Require().NoError(err)
	err = tmpl.Execute(testFileContents, vars)
	s.Require().NoError(err)
	err = testFileContents.Close()
	s.Require().NoError(err)

	s.rootCmd = NewRootCommand()
	s.rootCmd.AddCommand(NewRunCommand())
}

func (s *runCmdTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
	s.testHTTPServer.Close()
}

func TestRunChoreTestSuite(t *testing.T) {
	suite.Run(t, new(runCmdTestSuite))
}

func (s *runCmdTestSuite) TestHTTPCommandInvalidAddress() {
	s.rootCmd.SetArgs([]string{"run", "-d", s.tempDir, "--wait-for-host", "http://local host"})
	cmd, err := s.rootCmd.ExecuteContextC(context.Background())

	s.Equal("run", cmd.Name())
	s.Error(err)
	s.ErrorContains(err, "invalid character \" \" in host name")
}

func (s *runCmdTestSuite) TestHTTPConnectionSuccess() {
	s.rootCmd.SetArgs([]string{"run", "--cloud", "-d", s.tempDir, "--wait-for-host", s.testHTTPServer.URL})
	_, err := s.rootCmd.ExecuteContextC(context.Background())

	s.Require().NoError(err)
}

func (s *runCmdTestSuite) TestHTTPConnectionFail() {
	s.rootCmd.SetArgs([]string{"run", "--cloud", "-d", s.tempDir, "--wait-for-timeout", "2s", "--wait-for-host", "http://not-exists-doomain.tld"})
	_, err := s.rootCmd.ExecuteContextC(context.Background())

	s.Equal(context.DeadlineExceeded, err)
}

// func TestHTTPRequestHeaderSuccess(t *testing.T) {
func (s *runCmdTestSuite) TestHTTPRequestHeaderSuccess() {
	s.rootCmd.SetArgs([]string{
		"run", "--cloud", "-d", s.tempDir,
		"--wait-for-host", s.testHTTPServer.URL,
		"--wait-for-expect-body-regex", "(.*User-Agent=\\[Go-http-client/1.1\\].*)",
	})
	_, err := s.rootCmd.ExecuteContextC(context.Background())

	s.Require().NoError(err)
}
