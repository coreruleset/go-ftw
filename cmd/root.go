// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"log"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	check "github.com/coreruleset/go-ftw/cmd/check"
	internal "github.com/coreruleset/go-ftw/cmd/internal"
	quantitative "github.com/coreruleset/go-ftw/cmd/quantitative"
	run "github.com/coreruleset/go-ftw/cmd/run"
	selfUpdate "github.com/coreruleset/go-ftw/cmd/self_update"
	"github.com/coreruleset/go-ftw/config"
)

const (
	cloudFlagName     = "cloud"
	configFlagName    = "config"
	debugFlagName     = "debug"
	overridesFlagName = "overrides"
	traceFlagName     = "trace"
)

var (
	configurationFileNameFlag *internal.ConfigurationFileNameFlag
	overridesFileNameFlag     *internal.OverridesFileNameFlag
	debugFlag                 *internal.DebugFlag
	traceFlag                 *internal.TraceFlag
	cloudFlag                 *internal.CloudFlag
)

// NewRootCommand represents the base command when called without any subcommands
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "go-ftw",
		Short: "Framework for Testing WAFs - Go Version",
	}

	cmdContext := internal.NewCommandContext()
	buildFlags(rootCmd, cmdContext)

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) error {
	rootCmd := NewRootCommand()
	cmdContext := internal.NewCommandContext()
	rootCmd.AddCommand(
		check.New(cmdContext),
		run.New(cmdContext),
		quantitative.New(cmdContext),
		selfUpdate.New(cmdContext))
	// Setting Version creates a `--version` flag
	rootCmd.Version = version
	initConfig(cmdContext)

	return rootCmd.ExecuteContext(context.Background())
}

func initConfig(cmdContext *internal.CommandContext) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if cmdContext.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if cmdContext.Trace {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
	var err error
	cfg, err := config.NewConfigFromFile(cmdContext.ConfigurationFileName)
	if err != nil {
		cfgenv, errEnv := config.NewConfigFromEnv()
		if errEnv != nil {
			log.Fatalf("cannot read config from file (%s) nor environment (%s).", err.Error(), errEnv.Error())
		}
		cfg = cfgenv
	}
	cmdContext.Configuration = cfg
	if cmdContext.CloudMode {
		cfg.RunMode = config.CloudRunMode
	}
}

func buildFlags(cmd *cobra.Command, cmdContext *internal.CommandContext) {
	configurationFileNameFlag = &internal.ConfigurationFileNameFlag{Context: cmdContext}
	overridesFileNameFlag = &internal.OverridesFileNameFlag{Context: cmdContext}
	debugFlag = &internal.DebugFlag{Context: cmdContext}
	traceFlag = &internal.TraceFlag{Context: cmdContext}
	cloudFlag = &internal.CloudFlag{Context: cmdContext}
	cmd.PersistentFlags().VarP(configurationFileNameFlag, configFlagName, "", "specify config file (default is $PWD/.ftw.yaml)")
	cmd.PersistentFlags().VarP(overridesFileNameFlag, overridesFlagName, "", "specify file with platform specific overrides")
	cmd.PersistentFlags().VarPF(debugFlag, debugFlagName, "", "debug output").NoOptDefVal = "true"
	cmd.PersistentFlags().VarPF(traceFlag, traceFlagName, "", "trace output: really, really verbose").NoOptDefVal = "true"
	cmd.PersistentFlags().VarPF(cloudFlag, cloudFlagName, "", "cloud mode: rely only on HTTP status codes for determining test success or failure (will not process any logs)").NoOptDefVal = "true"
}
