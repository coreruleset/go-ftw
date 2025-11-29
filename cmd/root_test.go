// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/coreruleset/go-ftw/v2/utils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

type rootCmdTestSuite struct {
	suite.Suite
	rootCmd *cobra.Command
}

func TestRootTestSuite(t *testing.T) {
	suite.Run(t, new(rootCmdTestSuite))
}

func (s *rootCmdTestSuite) SetupTest() {
	s.rootCmd = NewRootCommand()
	s.rootCmd.AddCommand(NewRunCommand())
}
func (s *rootCmdTestSuite) TestRootCommand() {
	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"help"})
	err := Execute("v1.0.0")
	s.Require().NoError(err)
}

func (s *rootCmdTestSuite) TestFlags() {
	configFile, err := utils.CreateTempFile(s.T().TempDir(), "config")
	s.Require().NoError(err)
	overridesFile, err := utils.CreateTempFile(s.T().TempDir(), "overrides")
	s.Require().NoError(err)
	s.rootCmd.SetArgs([]string{
		"run",
		"--" + configFlag, configFile,
		"--" + debugFlag,
		"--" + overridesFlag, overridesFile,
		"--" + traceFlag,
	})
	cmd, _ := s.rootCmd.ExecuteC()

	config, err := cmd.Flags().GetString(configFlag)
	s.NoError(err)
	debug, err := cmd.Flags().GetBool(debugFlag)
	s.NoError(err)
	overrides, err := cmd.Flags().GetString(overridesFlag)
	s.NoError(err)
	trace, err := cmd.Flags().GetBool(traceFlag)
	s.NoError(err)

	s.Equal(configFile, config)
	s.Equal(true, debug)
	s.Equal(overridesFile, overrides)
	s.Equal(true, trace)
}
