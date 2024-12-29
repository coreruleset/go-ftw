// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types/overrides"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	koanfv2 "github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
)

// NewDefaultConfig initializes the configuration with default values
func NewDefaultConfig() *FTWConfiguration {
	cfg := &FTWConfiguration{
		LogFile:             "",
		PlatformOverrides:   PlatformOverrides{},
		LogMarkerHeaderName: DefaultLogMarkerHeaderName,
		RunMode:             DefaultRunMode,
		MaxMarkerRetries:    DefaultMaxMarkerRetries,
		MaxMarkerLogLines:   DefaultMaxMarkerLogLines,
	}
	return cfg
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

// LoadPlatformOverrides loads platform overrides from the specified file path
func (c *FTWConfiguration) LoadPlatformOverrides(overridesFile string) error {
	if overridesFile == "" {
		log.Trace().Msg("No overrides file specified, skipping.")
		return nil
	}
	if _, err := os.Stat(overridesFile); err != nil {
		return fmt.Errorf("could not find overrides file '%s'", overridesFile)
	}

	log.Debug().Msgf("Loading platform overrides from '%s'", overridesFile)

	k := getKoanfInstance()
	err := k.Load(file.Provider(overridesFile), yaml.Parser())
	if err != nil {
		return err
	}

	overrides, err := unmarshalPlatformOverrides(k)
	if err != nil {
		return err
	}

	c.PlatformOverrides.FTWOverrides = *overrides
	c.populatePlatformOverridesMap()

	return nil
}

func (c *FTWConfiguration) populatePlatformOverridesMap() {
	rulesMap := map[uint][]*schema.TestOverride{}
	for i := 0; i < len(c.PlatformOverrides.TestOverrides); i++ {
		testOverride := &c.PlatformOverrides.TestOverrides[i]
		var list []*schema.TestOverride
		list, ok := rulesMap[testOverride.RuleId]
		if !ok {
			list = []*schema.TestOverride{}
		}
		list = append(list, testOverride)
		rulesMap[testOverride.RuleId] = list

	}
	c.PlatformOverrides.OverridesMap = rulesMap
}

// WithLogfile changes the logfile in the configuration.
func (c *FTWConfiguration) WithLogfile(logfile string) {
	c.LogFile = logfile
}

// WithOverrides sets the overrides in the configuration.
func (c *FTWConfiguration) WithOverrides(overrides FTWTestOverride) {
	c.TestOverride = overrides
}

// WithRunMode sets the RunMode.
func (c *FTWConfiguration) WithRunMode(runMode RunMode) {
	c.RunMode = runMode
}

// WithLogMarkerHeaderName sets the new LogMarker header name.
func (c *FTWConfiguration) WithLogMarkerHeaderName(name string) {
	c.LogMarkerHeaderName = name
}

// WithMaxMarkerRetries sets the new amount of retries we are doing to find markers in the logfile.
func (c *FTWConfiguration) WithMaxMarkerRetries(retries uint) {
	c.MaxMarkerRetries = retries
}

// WithMaxMarkerLogLines sets the new amount of lines we go back in the logfile attempting to find markers.
func (c *FTWConfiguration) WithMaxMarkerLogLines(amount uint) {
	c.MaxMarkerLogLines = amount
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

// Unmarshal the loaded koanf instance into an FTWOverrides object
func unmarshalPlatformOverrides(k *koanfv2.Koanf) (*schema.FTWOverrides, error) {
	overrides := &schema.FTWOverrides{}
	err := k.UnmarshalWithConf("", overrides, koanfv2.UnmarshalConf{Tag: "yaml"})
	if err != nil {
		return nil, err
	}

	return overrides, nil
}

// Get the global koanf instance
func getKoanfInstance() *koanfv2.Koanf {
	// Use "." as the key path delimiter. This can be "/" or any character.
	return koanfv2.New(".")
}
