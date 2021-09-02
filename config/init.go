package config

import (
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/rs/zerolog/log"
)

// Init reads data from the config file and/or env vars
func Init(cfgFile string) {
	log.Trace().Msgf("ftw/config: executing init")
	// Global koanf instance. Use "." as the key path delimiter. This can be "/" or any character.
	var k = koanf.New(".")
	// first check if we had an explicit call with config file
	if cfgFile == "" {
		cfgFile = ".ftw.yaml"
	}

	if err := k.Load(file.Provider(cfgFile), yaml.Parser()); err != nil {
		log.Debug().Msgf("ftw/config: error reading config: %s", err.Error())
	}

	err := k.Load(env.Provider("FTW_", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(
			strings.TrimPrefix(s, "FTW_")), "_", ".")
	}), nil)

	if err != nil {
		log.Trace().Msgf("ftw/config: error while reading env vars: %s", err.Error())
	}

	// Unmarshal the whole root module
	if err := k.UnmarshalWithConf("", &FTWConfig, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		log.Fatal().Msgf("ftw/config: error while unmarshaling config: %s", err.Error())
	}

	if duration := k.Duration("logtype.timetruncate"); duration != 0 {
		log.Info().Msgf("ftw/config: will truncate logs to %s", duration)
	} else {
		log.Info().Msgf("ftw/config: no duration found")
	}
}

// ImportFromString initializes the configuration from a yaml formatted string. Useful for testing.
func ImportFromString(conf string) {
	var k = koanf.New(".")
	if err := k.Load(rawbytes.Provider([]byte(conf)), yaml.Parser()); err != nil {
		log.Debug().Msgf("ftw/config: error reading config: %s", err.Error())
	}

	// Unmarshal the whole root module
	if err := k.UnmarshalWithConf("", &FTWConfig, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		log.Fatal().Msgf("ftw/config: error while unmarshaling config: %s", err.Error())
	}
}
