package config

import (
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
)

// NewConfig creates a new configuration with the passed parameters
func NewConfig(logFile string, overrides FTWTestOverride, logMarkerHeaderName string, runMode RunMode) *FTWConfiguration {
	cfg := &FTWConfiguration{
		LogFile:             logFile,
		TestOverride:        overrides,
		LogMarkerHeaderName: logMarkerHeaderName,
		RunMode:             runMode,
	}
	return cfg
}

// NewDefaultConfig initializes the configuration with default values
func NewDefaultConfig() *FTWConfiguration {
	cfg := &FTWConfiguration{
		LogFile:             "",
		TestOverride:        FTWTestOverride{},
		LogMarkerHeaderName: DefaultLogMarkerHeaderName,
		RunMode:             DefaultRunMode,
	}
	return cfg
}

// NewConfigFromFile reads configuration information from the config file if it exists,
// or uses `.ftw.yaml` as default file
func NewConfigFromFile(cfgFile string) (*FTWConfiguration, error) {
	// Global koanf instance. Use "." as the key path delimiter. This can be "/" or any character.
	var k = koanf.New(".")
	var err error
	cfg := NewDefaultConfig()

	// first check if we had an explicit call with config file
	if cfgFile == "" {
		cfgFile = ".ftw.yaml"
	}

	_, err = os.Stat(cfgFile)
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

	err = k.Load(file.Provider(cfgFile), yaml.Parser())
	if err != nil {
		return nil, err
	}

	// At this point we have loaded our config, now we need to
	// unmarshal the whole root module
	err = k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"})
	if err != nil {
		return nil, err
	}

	return cfg, err
}

// NewConfigFromEnv reads configuration information from environment variables that start with `FTW_`
func NewConfigFromEnv() (*FTWConfiguration, error) {
	var err error
	var k = koanf.New(".")
	cfg := NewDefaultConfig()

	err = k.Load(env.Provider("FTW_", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(
			strings.TrimPrefix(s, "FTW_")), "_", ".")
	}), nil)

	if err != nil {
		return nil, err
	}
	// Unmarshal the whole root module
	err = k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"})

	return cfg, err
}

// NewConfigFromString initializes the configuration from a yaml formatted string. Useful for testing.
func NewConfigFromString(conf string) (*FTWConfiguration, error) {
	var k = koanf.New(".")
	var err error
	cfg := NewDefaultConfig()

	err = k.Load(rawbytes.Provider([]byte(conf)), yaml.Parser())
	if err != nil {
		return nil, err
	}

	// Unmarshal the whole root module
	err = k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"})

	return cfg, err
}

// WithLogfile changes the logfile in the configuration.
func (c *FTWConfiguration) WithLogfile(logfile string) {
	c.LogFile = logfile
}

func (c *FTWConfiguration) WithOverrides(overrides FTWTestOverride) {
	c.TestOverride = overrides
}

func (c *FTWConfiguration) WithRunMode(runmode RunMode) {
	c.RunMode = runmode
}

func (c *FTWConfiguration) WithLogMarkerHeaderName(name string) {
	c.LogMarkerHeaderName = name
}
