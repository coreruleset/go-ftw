// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"regexp"
	"strconv"

	"slices"

	schema "github.com/coreruleset/ftw-tests-schema/types"
	overridesSchema "github.com/coreruleset/ftw-tests-schema/types/overrides"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
)

// ApplyInputOverride will check if config had global overrides and write that into the test.
func ApplyInputOverrides(conf *config.FTWConfiguration, input *Input) {
	overrides := &conf.TestOverride.Overrides
	applySimpleOverrides(overrides, input)
	applyDestAddrOverride(overrides, input)
	applyHeadersOverride(overrides, input)
	//nolint:staticcheck
	if overrides.AutocompleteHeaders != nil || overrides.StopMagic != nil {
		//nolint:staticcheck
		postProcessAutocompleteHeaders(overrides.AutocompleteHeaders, overrides.StopMagic, input)
	}
}

func ApplyPlatformOverrides(conf *config.FTWConfiguration, testCase *schema.Test) {
	platformOverrides := conf.PlatformOverrides
	log.Debug().Msgf("Applying overrides for engine '%s', platform '%s", platformOverrides.Meta.Engine, platformOverrides.Meta.Platform)
	overrides, ok := platformOverrides.OverridesMap[testCase.RuleId]
	if !ok {
		log.Trace().Msgf("no override found for rule %d", testCase.RuleId)
		return
	}

	applyToAll := len(overrides) == 0
	for _, override := range overrides {
		for _, testId := range override.TestIds {
			if applyToAll || testId == testCase.TestId {
				basicApplyPlatformOverrides(override, testCase)
			}
		}
	}
}

func basicApplyPlatformOverrides(override *overridesSchema.TestOverride, testCase *schema.Test) {
	// Apply to all stages of the given test if the list of stage IDs is empty
	applyToAll := len(override.StageIds) == 0

	for index := 0; index < len(testCase.Stages); index++ {
		stage := &testCase.Stages[index]
		if applyToAll || slices.Contains(override.StageIds, uint(index)) {
			stage.Output = override.Output
		}
	}
}

func applyDestAddrOverride(overrides *config.Overrides, input *Input) {
	if overrides.DestAddr != nil {
		input.DestAddr = overrides.DestAddr
		if input.Headers == nil {
			input.Headers = ftwhttp.Header{}
		}
		if overrides.OverrideEmptyHostHeader != nil &&
			*overrides.OverrideEmptyHostHeader &&
			input.GetHeaders().Get("Host") == "" {
			input.GetHeaders().Set("Host", *overrides.DestAddr)
		}
	}
}

func applySimpleOverrides(overrides *config.Overrides, input *Input) {
	if overrides.Port != nil {
		input.Port = overrides.Port
	}

	if overrides.Protocol != nil {
		input.Protocol = overrides.Protocol
	}

	if overrides.URI != nil {
		input.URI = overrides.URI
	}

	if overrides.Version != nil {
		input.Version = overrides.Version
	}

	if overrides.Method != nil {
		input.Method = overrides.Method
	}

	if overrides.Data != nil {
		input.Data = overrides.Data
	}

	if overrides.SaveCookie != nil {
		input.SaveCookie = overrides.SaveCookie
	}

	if overrides.EncodedRequest != nil {
		input.EncodedRequest = *overrides.EncodedRequest
	}

	if overrides.RAWRequest != nil {
		//nolint:staticcheck
		input.RAWRequest = *overrides.RAWRequest
	}
}

func applyHeadersOverride(overrides *config.Overrides, input *Input) {
	if overrides.Headers != nil {
		if input.Headers == nil {
			input.Headers = ftwhttp.Header{}
		}
		for k, v := range overrides.Headers {
			input.GetHeaders().Set(k, v)
		}
	}
}

func postLoadTestFTWTest(ftwTest *FTWTest, fileName string) {
	ftwTest.FileName = fileName
	postLoadRuleId(ftwTest)
	for index := 0; index < len(ftwTest.Tests); index++ {
		postLoadTest(ftwTest.RuleId, uint(index+1), &ftwTest.Tests[index])
	}
}

func postLoadRuleId(ftwTest *FTWTest) {
	if ftwTest.RuleId > 0 {
		return
	}

	if len(ftwTest.FileName) == 0 {
		log.Fatal().Msg("The rule_id field is required for the top-level test structure")
	} else {
		ruleIdString := regexp.MustCompile(`\d+`).FindString(ftwTest.FileName)
		if len(ruleIdString) == 0 {
			log.Fatal().Msg("Failed to fall back on filename to find rule ID of test. The rule_id field is required for the top-level test structure")
			return
		}
		ruleId, err := strconv.ParseUint(ruleIdString, 10, 0)
		if err != nil {
			log.Fatal().Msgf("failed to parse rule ID from filename '%s'", ftwTest.FileName)
			return
		}
		ftwTest.RuleId = uint(ruleId)
	}
}
func postLoadTest(ruleId uint, testId uint, test *schema.Test) {
	test.RuleId = ruleId
	// Retain explicitly defined test IDs
	if test.TestId == 0 {
		test.TestId = testId
	}
	for index := range test.Stages {
		postLoadStage(&test.Stages[index])
	}
}

func postLoadStage(stage *schema.Stage) {
	postLoadInput((*Input)(&stage.Input))
}

func postLoadInput(input *Input) {
	//nolint:staticcheck
	postProcessAutocompleteHeaders(input.AutocompleteHeaders, input.StopMagic, input)
}

func postProcessAutocompleteHeaders(autocompleteHeaders *bool, stopMagic *bool, input *Input) {
	autocompleteHeadersMissing := autocompleteHeaders == nil
	stopMagicMissing := stopMagic == nil
	// default value
	finalValue := true

	if autocompleteHeadersMissing && !stopMagicMissing {
		// StopMagic has the inverse boolean logic
		finalValue = !*stopMagic
	} else if !autocompleteHeadersMissing {
		finalValue = *autocompleteHeaders
	}
	input.AutocompleteHeaders = &finalValue
	// StopMagic has the inverse boolean logic
	//nolint:staticcheck
	input.StopMagic = func() *bool { b := !finalValue; return &b }()
}
