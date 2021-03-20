package config

import (
	"bytes"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Init reads data from the config file and/or env vars
func Init(cfgFile string) {
	log.Debug().Msgf("ftw/config: executing init")
	viper.SetConfigType("yaml")
	if cfgFile != "" {
		// Use config file from the flag. Assumes the config file is the only one used
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".ftw" (without extension).
		// Search also in current directory
		viper.AddConfigPath(".")
		viper.SetConfigName(".ftw")
	}
	viper.SetEnvPrefix("FTW")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		log.Info().Msgf("Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		log.Fatal().Msgf("ftw/config: fatal error reading config: %s", err.Error())
	}
	err := viper.Unmarshal(&FTWConfig)
	if err != nil {
		log.Fatal().Msgf("ftw/config: fatal error decoding config: %s", err.Error())
	}
	if duration := viper.GetDuration("logtype.timetruncate"); duration != 0 {
		log.Info().Msgf("ftw/config: will truncate logs to %s", duration)
	} else {
		log.Info().Msgf("ftw/config: no duration found")
	}
}

// ImportFromString initializes the configuration from a yaml formatted string. Useful for testing.
func ImportFromString(conf string) {
	viper.SetConfigType("yaml")

	if err := viper.ReadConfig(bytes.NewBuffer([]byte(conf))); err != nil {
		log.Fatal().Msgf("ftw/config: fatal error reading config: %s", err.Error())
	}
	err := viper.Unmarshal(&FTWConfig)
	if err != nil {
		log.Fatal().Msgf("ftw/config: fatal error decoding config: %s", err.Error())
	}
}
