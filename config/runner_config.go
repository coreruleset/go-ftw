package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types/overrides"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	koanfv2 "github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
)

// RunnerConfig provides configuration for the test runner.
type RunnerConfig struct {
	// Include is a regular expression to filter tests to include. If nil, all tests are included.
	Include *regexp.Regexp
	// Exclude is a regular expression to filter tests to exclude. If nil, no tests are excluded.
	Exclude *regexp.Regexp
	// IncludeTags is a regular expression to filter tests to count the ones tagged with the mathing label. If nil, no impact on test runner.
	IncludeTags *regexp.Regexp
	// ShowTime determines whether to show the time taken to run each test.
	ShowTime bool
	// ShowOnlyFailed will only output information related to failed tests
	ShowOnlyFailed bool
	// Output determines the type of output the user wants.
	Output output.Type
	// ConnectTimeout is the timeout for connecting to endpoints during test execution.
	ConnectTimeout time.Duration
	// ReadTimeout is the timeout for receiving responses during test execution.
	ReadTimeout time.Duration
	// RateLimit is the rate limit for requests to the server. 0 is unlimited.
	RateLimit time.Duration
	// FailFast determines whether to stop running tests when the first failure is encountered.
	FailFast            bool
	RunMode             RunMode
	LogMarkerHeaderName string
	LogFilePath         string
	PlatformOverrides   PlatformOverrides
	TestOverride        FTWTestOverride
	MaxMarkerRetries    uint
	MaxMarkerLogLines   uint
	// SkipTlsVerification skips certificate validation. Useful for connecting
	// to domains with a self-signed certificate.
	SkipTlsVerification bool
	// WriteSummary determines whether to write a summary to GITHUB_STEP_SUMMARY when using GitHub output mode.
	WriteSummary bool
}

type PlatformOverrides struct {
	schema.FTWOverrides
	OverridesMap map[uint][]*schema.TestOverride
}

func NewRunnerConfiguration(cfg *FTWConfiguration) *RunnerConfig {
	runnerConfig := &RunnerConfig{
		LogMarkerHeaderName: cfg.LogMarkerHeaderName,
		LogFilePath:         cfg.LogFile,
		TestOverride:        cfg.TestOverride,
		MaxMarkerLogLines:   cfg.MaxMarkerLogLines,
		MaxMarkerRetries:    cfg.MaxMarkerRetries,
		RunMode:             cfg.RunMode,
		SkipTlsVerification: cfg.SkipTlsVerification,
	}

	if cfg.IncludeTests != nil {
		runnerConfig.Include = (*regexp.Regexp)(cfg.IncludeTests)
	}
	if cfg.ExcludeTests != nil {
		runnerConfig.Exclude = (*regexp.Regexp)(cfg.ExcludeTests)
	}
	if cfg.IncludeTags != nil {
		runnerConfig.IncludeTags = (*regexp.Regexp)(cfg.IncludeTags)
	}
	return runnerConfig
}

// LoadPlatformOverrides reads platform overrides from the specified file path
func (c *RunnerConfig) LoadPlatformOverrides(overridesFile string) error {
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
	c.PlatformOverrides = PlatformOverrides{
		FTWOverrides: *overrides,
		OverridesMap: buildPlatformOverridesMap(overrides.TestOverrides),
	}

	return nil
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

func buildPlatformOverridesMap(overrides []schema.TestOverride) map[uint][]*schema.TestOverride {
	rulesMap := map[uint][]*schema.TestOverride{}
	for i := 0; i < len(overrides); i++ {
		testOverride := &overrides[i]
		var list []*schema.TestOverride
		list, ok := rulesMap[testOverride.RuleId]
		if !ok {
			list = []*schema.TestOverride{}
		}
		list = append(list, testOverride)
		rulesMap[testOverride.RuleId] = list

	}
	return rulesMap
}
