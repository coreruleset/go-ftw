// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
	run "github.com/coreruleset/go-ftw/v2/cmd/run"
	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/utils"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

type rootCmdTestSuite struct {
	suite.Suite
	rootCmd    *cobra.Command
	cmdContext *internal.CommandContext
}

func TestRootTestSuite(t *testing.T) {
	suite.Run(t, new(rootCmdTestSuite))
}

func (s *rootCmdTestSuite) SetupTest() {
	s.cmdContext = internal.NewCommandContext()
	s.rootCmd = NewRootCommand(s.cmdContext)
}
func (s *rootCmdTestSuite) TestRootCommand() {
	rootCmd := NewRootCommand(internal.NewCommandContext())
	rootCmd.SetArgs([]string{"help"})
	err := Execute("v1.0.0")
	s.Require().NoError(err)
}

func (s *rootCmdTestSuite) TestFlags() {
	configFile, err := utils.CreateTempFile(s.T().TempDir(), "config")
	s.Require().NoError(err)
	overridesFile, err := utils.CreateTempFile(s.T().TempDir(), "overrides")
	s.Require().NoError(err)

	s.cmdContext.Configuration = config.NewDefaultConfig()
	s.rootCmd.AddCommand(run.New(s.cmdContext))
	s.rootCmd.SetArgs([]string{
		"run",
		"--" + configFlagName, configFile,
		"--" + debugFlagName,
		"--" + overridesFlagName, overridesFile,
		"--" + traceFlagName,
		"--" + cloudFlagName,
	})

	// Reset log level to info before test
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

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

	// Validate that flags populate command context
	s.Equal(configFile, s.cmdContext.ConfigurationFileName)
	s.Equal(overridesFile, s.cmdContext.OverridesFileName)
	s.True(s.cmdContext.Debug)
	s.True(s.cmdContext.Trace)
	s.True(s.cmdContext.CloudMode)
	// Validate that log level is set correctly (trace takes precedence over debug)
	s.Equal(zerolog.TraceLevel, zerolog.GlobalLevel())
}
