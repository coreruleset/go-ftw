// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	koanfenvv2 "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	koanfv2 "github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
)

// NewDefaultConfig initializes the configuration with default values
func NewDefaultConfig() *FTWConfiguration {
	return &FTWConfiguration{
		LogFile:             "",
		LogMarkerHeaderName: DefaultLogMarkerHeaderName,
		RunMode:             DefaultRunMode,
		MaxMarkerRetries:    DefaultMaxMarkerRetries,
		MaxMarkerLogLines:   DefaultMaxMarkerLogLines,
		CustomLogIdRegex:    "",
		TestOverride: FTWTestOverride{
			StaleOverrides: StaleOverridesFail,
		},
	}
}

// NewCloudConfig initializes the configuration with cloud values
func NewCloudConfig() *FTWConfiguration {
	cfg := NewDefaultConfig()
	cfg.RunMode = CloudRunMode

	return cfg
}

// NewConfigFromFile reads configuration information from the config file if it exists,
// or uses `.ftw.yaml` as default file
func NewConfigFromFile(cfgFile string) (*FTWConfiguration, error) {
	// first check if we had an explicit call with config file
	if cfgFile == "" {
		cfgFile = ".ftw.yaml"
	}

	_, err := os.Stat(cfgFile)
	if err != nil { // file does not exist, so we try the home folder

		var home string

		home, err = os.UserHomeDir()
		if err != nil { // home folder could not be retrieved
			return nil, err
		}

		cfgFile = home + "/.ftw.yaml"

	}

	_, err = os.Stat(cfgFile)
	if err != nil { // file exists, so we read it looking for config values
		return nil, err
	}

	k := getKoanfInstance()
	err = k.Load(file.Provider(cfgFile), yaml.Parser())
	if err != nil {
		return nil, err
	}

	return unmarshalConfig(k)
}

// NewConfigFromEnv reads configuration information from environment variables that start with `FTW_`
func NewConfigFromEnv() (*FTWConfiguration, error) {
	k := getKoanfInstance()
	options := koanfenvv2.Opt{
		Prefix: "FTW_",
		TransformFunc: func(key string, value string) (string, any) {
			cleanKey := strings.ReplaceAll(strings.ToLower(
				strings.TrimPrefix(key, "FTW_")), "_", ".")
			return cleanKey, value
		},
	}
	err := k.Load(koanfenvv2.Provider(".", options), nil)

	if err != nil {
		return nil, err
	}

	return unmarshalConfig(k)
}

// NewConfigFromString initializes the configuration from a yaml formatted string. Useful for testing.
func NewConfigFromString(conf string) (*FTWConfiguration, error) {
	k := getKoanfInstance()
	err := k.Load(rawbytes.Provider([]byte(conf)), yaml.Parser())
	if err != nil {
		return nil, err
	}

	return unmarshalConfig(k)
}

// Unmarshal the loaded koanf instance into a configuration object
func unmarshalConfig(k *koanfv2.Koanf) (*FTWConfiguration, error) {
	if k.Exists("exclude") {
		return nil, errors.New("the 'exclude' option is no longer supported, use platform overrides (--overrides) to describe platform specific behavior and the --exclude command line flag to filter tests for a run")
	}

	config := NewDefaultConfig()
	err := k.UnmarshalWithConf("", config, koanfv2.UnmarshalConf{Tag: "koanf"})
	if err != nil {
		return nil, err
	}

	if err = normalizeTestOverride(&config.TestOverride); err != nil {
		return nil, err
	}

	return config, nil
}

// normalizeTestOverride validates the test overrides and merges deprecated entries into their replacements
func normalizeTestOverride(override *FTWTestOverride) error {
	switch override.StaleOverrides {
	case StaleOverridesFail, StaleOverridesWarn:
	default:
		return fmt.Errorf("invalid value '%s' for 'stale_overrides', must be '%s' or '%s'", override.StaleOverrides, StaleOverridesFail, StaleOverridesWarn)
	}

	if len(override.Ignore) > 0 {
		log.Warn().Msg("the 'ignore' test override is deprecated, use 'forcepass' instead; 'ignore' entries are treated as 'forcepass'")
	}
	mergeIgnoreIntoForcePass(override)
	return nil
}

// mergeIgnoreIntoForcePass merges the entries of the deprecated `ignore` override into `forcepass`.
// Does not modify the existing maps.
func mergeIgnoreIntoForcePass(override *FTWTestOverride) {
	if len(override.Ignore) == 0 {
		override.Ignore = nil
		return
	}
	forcePass := make(map[*FTWRegexp]string, len(override.ForcePass)+len(override.Ignore))
	maps.Copy(forcePass, override.ForcePass)
	maps.Copy(forcePass, override.Ignore)
	override.ForcePass = forcePass
	override.Ignore = nil
}

// Get the global koanf instance
func getKoanfInstance() *koanfv2.Koanf {
	// Use "." as the key path delimiter. This can be "/" or any character.
	return koanfv2.New(".")
}
