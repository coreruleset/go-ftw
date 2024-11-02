// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"log"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/config"
)

var (
	cfgFile       string
	overridesFile string
	debug         bool
	trace         bool
	cloud         bool
)

var cfg = config.NewDefaultConfig()

// NewRootCommand represents the base command when called without any subcommands
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ftw run",
		Short: "Framework for Testing WAFs - Go Version",
	}
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "specify config file (default is $PWD/.ftw.yaml)")
	rootCmd.PersistentFlags().StringVar(&overridesFile, "overrides", "", "specify file with platform specific overrides")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "", false, "trace output: really, really verbose")
	rootCmd.PersistentFlags().BoolVarP(&cloud, "cloud", "", false, "cloud mode: rely only on HTTP status codes for determining test success or failure (will not process any logs)")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) error {
	rootCmd := NewRootCommand()
	rootCmd.AddCommand(NewCheckCommand())
	rootCmd.AddCommand(NewRunCommand())
	rootCmd.AddCommand(NewQuantitativeCmd())
	rootCmd.AddCommand(NewSelfUpdateCommand(version))
	rootCmd.AddCommand(NewVersionCommand(version))
	rootCmd.Version = version

	return rootCmd.ExecuteContext(context.Background())
}

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if trace {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
	var err error
	cfg, err = config.NewConfigFromFile(cfgFile)
	if err != nil {
		cfgenv, errEnv := config.NewConfigFromEnv()
		if errEnv != nil {
			log.Fatalf("cannot read config from file (%s) nor environment (%s).", err.Error(), errEnv.Error())
		}
		cfg = cfgenv
	}
	if cloud {
		cfg.RunMode = config.CloudRunMode
	}
	err = cfg.LoadPlatformOverrides(overridesFile)
	if err != nil {
		log.Fatal("failed to load platform overrides")
	}
}
