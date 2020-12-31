package config

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

//Init we use two config files, defaults and local customizations
func Init(cfgFile string) {
	log.Debug().Msgf("ftw/config: executing init")
	if cfgFile != "" {
		// Use config file from the flag. Assumes the config file is the only one used
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".cobra" (without extension).
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
}
