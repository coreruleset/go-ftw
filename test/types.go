// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"text/template"

	"slices"

	"github.com/Masterminds/sprig/v3"
	schema "github.com/coreruleset/ftw-tests-schema/v3/types"
	overridesSchema "github.com/coreruleset/ftw-tests-schema/v3/types/overrides"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"

	"github.com/coreruleset/go-ftw/v2/config"
)

// ApplyInputOverride will check if config had global overrides and write that into the test.
func ApplyInputOverrides(conf *config.RunnerConfig, input *Input) {
	overrides := &conf.TestOverride.Overrides
	applySimpleOverrides(overrides, input)
	applyDestAddrOverride(overrides, input)
	applyHeadersOverride(overrides, input)
	//nolint:staticcheck
	if overrides.AutocompleteHeaders != nil || overrides.StopMagic != nil {
		//nolint:staticcheck
		postProcessAutocompleteHeaders(overrides.AutocompleteHeaders, overrides.StopMagic, input.Input)
	}
}

func ApplyPlatformOverrides(conf *config.RunnerConfig, testCase *schema.Test) {
	platformOverrides := conf.PlatformOverrides
	log.Debug().Msgf("Applying overrides for engine '%s', platform '%s'", platformOverrides.Meta.Engine, platformOverrides.Meta.Platform)
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

//nolint:staticcheck
func applyDestAddrOverride(overrides *config.Overrides, input *Input) {
	if overrides.DestAddr != nil {
		input.DestAddr = overrides.DestAddr
		if input.Headers == nil {
			input.Headers = map[string]string{}
		}
		headers := input.GetHeaders()
		if overrides.OverrideEmptyHostHeader != nil &&
			*overrides.OverrideEmptyHostHeader &&
			!headers.HasAny("Host") {
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
	if overrides.VirtualHostMode != nil {
		input.VirtualHostMode = *overrides.VirtualHostMode
	}
}

//nolint:staticcheck
func applyHeadersOverride(overrides *config.Overrides, input *Input) {
	if overrides.Headers == nil {
		return
	}
	headers := input.GetHeaders()
	for k, v := range overrides.Headers {
		headers.Set(k, v)
	}
}

func postLoadTestFTWTest(ftwTest *FTWTest, fileName string) error {
	ftwTest.FileName = fileName
	if err := postLoadRuleId(ftwTest); err != nil {
		return err
	}
	for index := 0; index < len(ftwTest.Tests); index++ {
		if err := postLoadTest(ftwTest.RuleId, uint(index+1), ftwTest.Template, &ftwTest.Tests[index]); err != nil {
			return err
		}
	}
	return nil
}

func postLoadRuleId(ftwTest *FTWTest) error {
	if ftwTest.RuleId > 0 {
		return nil
	}

	if len(ftwTest.FileName) == 0 {
		return fmt.Errorf("the rule_id field is required for the top-level test structure")
	} else {
		ruleIdString := regexp.MustCompile(`\d+`).FindString(ftwTest.FileName)
		if len(ruleIdString) == 0 {
			return fmt.Errorf("failed to fall back on filename to find rule ID of test. The rule_id field is required for the top-level test structure")
		}
		ruleId, err := strconv.ParseUint(ruleIdString, 10, 0)
		if err != nil {
			return fmt.Errorf("failed to parse rule ID from filename '%s'", ftwTest.FileName)
		}
		ftwTest.RuleId = uint(ruleId)
	}
	return nil
}
func postLoadTest(ruleId uint, testId uint, fileTemplate *schema.RequestTemplate, test *schema.Test) error {
	test.RuleId = ruleId
	// Retain explicitly defined test IDs
	if test.TestId == 0 {
		test.TestId = testId
	}
	if test.Payload != nil {
		stage, err := payloadStage(fileTemplate, test)
		if err != nil {
			return fmt.Errorf("test %s: %w", test.IdString(), err)
		}
		test.Stages = []schema.Stage{stage}
	}
	for index := range test.Stages {
		postLoadStage(&test.Stages[index])
	}
	return nil
}

// payloadStage expands a v3 payload test into a single stage, built from the
// file-level template, the per-test template overrides and the test's output.
func payloadStage(fileTemplate *schema.RequestTemplate, test *schema.Test) (schema.Stage, error) {
	if len(test.Stages) > 0 {
		return schema.Stage{}, errors.New("payload and stages are mutually exclusive")
	}
	if fileTemplate == nil && test.Template == nil {
		return schema.Stage{}, errors.New("payload requires a file-level or per-test template")
	}
	tmpl := mergeTemplates(fileTemplate, test.Template)
	vars := struct{ Payload string }{*test.Payload}
	render := func(text string) (string, error) {
		t, err := template.New("payload").Funcs(sprig.TxtFuncMap()).Parse(text)
		if err != nil {
			return "", err
		}
		var out bytes.Buffer
		err = t.Execute(&out, vars)
		return out.String(), err
	}

	input := schema.Input{
		DestAddr:            tmpl.DestAddr,
		Port:                tmpl.Port,
		Protocol:            tmpl.Protocol,
		Version:             tmpl.Version,
		Method:              tmpl.Method,
		AutocompleteHeaders: tmpl.AutocompleteHeaders,
		StopMagic:           tmpl.StopMagic, //nolint:staticcheck
		SaveCookie:          tmpl.SaveCookie,
	}
	if tmpl.URI != nil {
		uri, err := render(*tmpl.URI)
		if err != nil {
			return schema.Stage{}, fmt.Errorf("rendering uri: %w", err)
		}
		input.URI = &uri
	}
	if tmpl.Data != nil {
		data, err := render(*tmpl.Data)
		if err != nil {
			return schema.Stage{}, fmt.Errorf("rendering data: %w", err)
		}
		// `data` is evaluated as a template again at request time; encoding it
		// keeps payloads such as `{{7*7}}` literal.
		encoded := base64.StdEncoding.EncodeToString([]byte(data))
		input.EncodedData = &encoded
	}
	for _, header := range tmpl.Headers {
		value, err := render(header.Value)
		if err != nil {
			return schema.Stage{}, fmt.Errorf("rendering header %s: %w", header.Name, err)
		}
		input.OrderedHeaders = append(input.OrderedHeaders, schema.HeaderTuple{Name: header.Name, Value: value})
	}

	stage := schema.Stage{Input: input}
	if test.Output != nil {
		stage.Output = *test.Output
	}
	return stage, nil
}

// mergeTemplates returns base with every field that is set in override replaced.
func mergeTemplates(base *schema.RequestTemplate, override *schema.RequestTemplate) schema.RequestTemplate {
	var merged schema.RequestTemplate
	if base != nil {
		merged = *base
	}
	if override == nil {
		return merged
	}
	if override.DestAddr != nil {
		merged.DestAddr = override.DestAddr
	}
	if override.Port != nil {
		merged.Port = override.Port
	}
	if override.Protocol != nil {
		merged.Protocol = override.Protocol
	}
	if override.URI != nil {
		merged.URI = override.URI
	}
	if override.Version != nil {
		merged.Version = override.Version
	}
	if override.Method != nil {
		merged.Method = override.Method
	}
	if override.Headers != nil {
		merged.Headers = override.Headers
	}
	if override.Data != nil {
		merged.Data = override.Data
	}
	if override.AutocompleteHeaders != nil {
		merged.AutocompleteHeaders = override.AutocompleteHeaders
	}
	//nolint:staticcheck
	if override.StopMagic != nil {
		//nolint:staticcheck
		merged.StopMagic = override.StopMagic
	}
	if override.SaveCookie != nil {
		merged.SaveCookie = override.SaveCookie
	}
	return merged
}

func postLoadStage(stage *schema.Stage) {
	postLoadInput(&stage.Input)
	postLoadOutput(&stage.Output)
}

func postLoadInput(input *schema.Input) {
	//nolint:staticcheck
	postProcessAutocompleteHeaders(input.AutocompleteHeaders, input.StopMagic, input)
	postProcessHeaders(input)
}
func postLoadOutput(output *schema.Output) {
	postProcessLogContains(output)
}

func postProcessAutocompleteHeaders(autocompleteHeaders *bool, stopMagic *bool, input *schema.Input) {
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

func postProcessLogContains(output *schema.Output) {
	log := &output.Log
	//nolint:staticcheck
	if output.LogContains != "" && log.ExpectIds == nil && log.MatchRegex == "" {
		//nolint:staticcheck
		log.MatchRegex = output.LogContains
	}
	//nolint:staticcheck
	if output.NoLogContains != "" && log.NoExpectIds == nil && log.NoMatchRegex == "" {
		//nolint:staticcheck
		log.NoMatchRegex = output.NoLogContains
	}
}

//nolint:staticcheck
func postProcessHeaders(input *schema.Input) {
	if input.Headers == nil || input.OrderedHeaders != nil {
		return
	}

	sortedHeaderNames := maps.Keys(input.Headers)
	// sort headers to guarantee stable ordering of headers
	slices.Sort(sortedHeaderNames)
	input.OrderedHeaders = make([]schema.HeaderTuple, len(sortedHeaderNames))
	for index, name := range sortedHeaderNames {
		input.OrderedHeaders[index] = schema.HeaderTuple{
			Name:  name,
			Value: input.Headers[name],
		}
	}
}
