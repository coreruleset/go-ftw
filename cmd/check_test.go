// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

var checkFileContents = `---
meta:
  author: "go-ftw"
  enabled: true
  name: "mock-TestRunTests_Run.yaml"
  description: "Test file for go-ftw"
tests:
  - # Standard GET request
    test_title: 1234
    stages:
      - stage:
          input:
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
	rootCmd *cobra.Command
}

func (s *checkCmdTestSuite) SetupTest() {
	tempDir, err := os.MkdirTemp("", "go-ftw-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	err = os.MkdirAll(s.tempDir, fs.ModePerm)
	s.Require().NoError(err)
	testFileContents, err := os.CreateTemp(s.tempDir, "mock-test-*.yaml")
	s.Require().NoError(err)
	n, err := testFileContents.WriteString(checkFileContents)
	s.Require().NoError(err)
	s.Equal(len(checkFileContents), n)

	s.rootCmd = NewRootCommand()
	s.rootCmd.AddCommand(NewCheckCommand())
}

func (s *checkCmdTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestCheckChoreTestSuite(t *testing.T) {
	suite.Run(t, new(checkCmdTestSuite))
}

func (s *checkCmdTestSuite) TestCheckCommand() {
	s.rootCmd.SetArgs([]string{"check", "-d", s.tempDir})
	cmd, err := s.rootCmd.ExecuteContextC(context.Background())
	s.Require().NoError(err, "check command should not return an error")
	s.Equal("check", cmd.Name(), "check command should have the name 'check'")
}
