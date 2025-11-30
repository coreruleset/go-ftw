// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/coreruleset/go-ftw/cmd/internal"
	run "github.com/coreruleset/go-ftw/cmd/run"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
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
		"--" + configFlagName, configFile,
		"--" + debugFlagName,
		"--" + overridesFlagName, overridesFile,
		"--" + traceFlagName,
	})
	cmdContext := internal.NewCommandContext()
	cmdContext.Configuration = config.NewDefaultConfig()
	s.rootCmd.AddCommand(run.New(cmdContext))
	cmd, _ := s.rootCmd.ExecuteC()

	config, err := cmd.Flags().GetString(configFlagName)
	s.NoError(err)
	debug, err := cmd.Flags().GetBool(debugFlagName)
	s.NoError(err)
	overrides, err := cmd.Flags().GetString(overridesFlagName)
	s.NoError(err)
	trace, err := cmd.Flags().GetBool(traceFlagName)
	s.NoError(err)

	s.Equal(configFile, config)
	s.True(debug)
	s.Equal(overridesFile, overrides)
	s.True(trace)
}
