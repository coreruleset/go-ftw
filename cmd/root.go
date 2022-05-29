package cmd

import (
	"log"
	"os"

	"github.com/fzipi/go-ftw/config"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	debug   bool
	trace   bool
	cloud   bool
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
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "override config file (default is $PWD/.ftw.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "", false, "trace output: really, really verbose")
	rootCmd.PersistentFlags().BoolVarP(&cloud, "cloud", "", false, "cloud mode: rely only in http status code for determining test succes or failure (assumes no logs access)")
}

func initConfig() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if trace {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
	errFile := config.NewConfigFromFile(cfgFile)
	if errFile != nil {
		errEnv := config.NewConfigFromEnv()
		if errEnv != nil {
			log.Fatalf("cannot read config from file (%s) nor environment (%s).", errFile.Error(), errEnv.Error())
		}
	}
	if cloud {
		config.FTWConfig.RunMode = config.CloudRunMode
	}
}
