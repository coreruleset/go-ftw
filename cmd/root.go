package cmd

import (
	config "github.com/fzipi/go-ftw/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	debug   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ftw run",
	Short: "Framework for Testing WAFs - Go Version",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Msgf("Problem executing: %s", err.Error())
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "cfg", "", "override config file (default is $PWD/.ftw.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "debug output")
}

func initConfig() {
	config.Init(cfgFile)
	if debug {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
}
