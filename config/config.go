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

// NewConfigFromFile reads configuration information from the config file if it exists,
// or uses `.ftw.yaml` as default file
func NewConfigFromFile(cfgFile string) error {
	// koanf merges by default, but we never want to merge in this case
	Reset()

	// Global koanf instance. Use "." as the key path delimiter. This can be "/" or any character.
	var k = koanf.New(".")
	var err error

	// first check if we had an explicit call with config file
	if cfgFile == "" {
		cfgFile = ".ftw.yaml"
	}

	_, err = os.Stat(cfgFile)
	if err != nil { // file does not exist, so we try the home folder

		var home string

		home, err = os.UserHomeDir()
		if err != nil { // home folder could not be retrieved
			return err
		}

		cfgFile = home + "/.ftw.yaml"

	}

	_, err = os.Stat(cfgFile)
	if err != nil { // file exists, so we read it looking for config values
		return err
	}

	err = k.Load(file.Provider(cfgFile), yaml.Parser())
	if err != nil {
		return err
	}

	// At this point we have loaded our config, now we need to
	// unmarshal the whole root module
	err = k.UnmarshalWithConf("", &FTWConfig, koanf.UnmarshalConf{Tag: "koanf"})
	if err != nil {
		return err
	}
	loadDefaults()

	return err
}

// NewConfigFromEnv reads configuration information from environment variables that start with `FTW_`
func NewConfigFromEnv() error {
	// koanf merges by default, but we never want to merge in this case
	Reset()

	var err error
	var k = koanf.New(".")

	err = k.Load(env.Provider("FTW_", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(
			strings.TrimPrefix(s, "FTW_")), "_", ".")
	}), nil)

	if err != nil {
		return err
	}
	// Unmarshal the whole root module
	err = k.UnmarshalWithConf("", &FTWConfig, koanf.UnmarshalConf{Tag: "koanf"})
	loadDefaults()

	return err
}

// NewConfigFromString initializes the configuration from a yaml formatted string. Useful for testing.
func NewConfigFromString(conf string) error {
	// koanf merges by default, but we never want to merge in this case
	Reset()

	var k = koanf.New(".")
	var err error

	err = k.Load(rawbytes.Provider([]byte(conf)), yaml.Parser())
	if err != nil {
		return err
	}

	// Unmarshal the whole root module
	err = k.UnmarshalWithConf("", &FTWConfig, koanf.UnmarshalConf{Tag: "koanf"})
	loadDefaults()

	return err
}

// Reset configuration to uninitialized state
func Reset() {
	FTWConfig = nil
}

func loadDefaults() {
	// Note: koanf has a way to set defaults. However, koanf's merge behavior
	// will overwrite defaults when the associated field is empty in nested
	// structures (top level would work). That's why we set defaults here
	// explicitly.
	if FTWConfig.LogMarkerHeaderName == "" {
		FTWConfig.LogMarkerHeaderName = DefaultLogMarkerHeaderName
	}
	if FTWConfig.RunMode == "" {
		FTWConfig.RunMode = DefaultRunMode
	}

}
