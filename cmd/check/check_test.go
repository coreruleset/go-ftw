// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/coreruleset/go-ftw/cmd/internal"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

var checkFileContents = `---
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
          port: 1234
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

type checkCmdTestSuite struct {
	suite.Suite
	tempDir string
	cmd     *cobra.Command
}

func (s *checkCmdTestSuite) SetupTest() {
	s.tempDir = s.T().TempDir()

	s.cmd = New(internal.NewCommandContext())
	err := os.MkdirAll(s.tempDir, fs.ModePerm)
	s.Require().NoError(err)
	testFileContents, err := os.CreateTemp(s.tempDir, "mock-test-*.yaml")
	s.Require().NoError(err)
	n, err := testFileContents.WriteString(checkFileContents)
	s.Require().NoError(err)
	err = testFileContents.Close()
	s.Require().NoError(err)
	s.Equal(len(checkFileContents), n)

}

func (s *checkCmdTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestCheckChoreTestSuite(t *testing.T) {
	suite.Run(t, new(checkCmdTestSuite))
}

func (s *checkCmdTestSuite) TestCheckCommand() {
	s.cmd.SetArgs([]string{"check", "-d", s.tempDir})
	cmd, err := s.cmd.ExecuteContextC(context.Background())
	s.Require().NoError(err, "check command should not return an error")
	s.Equal("check", cmd.Name(), "check command should have the name 'check'")
}
