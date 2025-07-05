// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	koanfv2 "github.com/knadh/koanf/v2"
)

// NewDefaultConfig initializes the configuration with default values
func NewDefaultConfig() *FTWConfiguration {
	return &FTWConfiguration{
		LogFile:             "",
		LogMarkerHeaderName: DefaultLogMarkerHeaderName,
		RunMode:             DefaultRunMode,
		MaxMarkerRetries:    DefaultMaxMarkerRetries,
		MaxMarkerLogLines:   DefaultMaxMarkerLogLines,
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
	err := k.Load(env.Provider("FTW_", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(
			strings.TrimPrefix(s, "FTW_")), "_", ".")
	}), nil)

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
	config := NewDefaultConfig()
	err := k.UnmarshalWithConf("", config, koanfv2.UnmarshalConf{Tag: "koanf"})
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Get the global koanf instance
func getKoanfInstance() *koanfv2.Koanf {
	// Use "." as the key path delimiter. This can be "/" or any character.
	return koanfv2.New(".")
}
