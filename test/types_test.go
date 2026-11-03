// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"

	schema "github.com/coreruleset/ftw-tests-schema/v3/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type typesTestSuite struct {
	suite.Suite
}

func (s *typesTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestTypesTestSuite(t *testing.T) {
	suite.Run(t, new(typesTestSuite))
}

var autocompleteHeadersDefaultYaml = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    description: "autocomplete headers by default"
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
  - test_id: 2
    description: "autocomplete headers by default"
    stages:
      - input:
          stop_magic: true
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
  - test_id: 3
    description: "autocomplete headers by default"
    stages:
      - input:
          stop_magic: false
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
`

var autocompleteHeadersFalseYaml = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    description: "autocomplete headers explicitly"
    stages:
      - input:
          autocomplete_headers: false
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
  - test_id: 2
    description: "autocomplete headers explicitly"
    stages:
      - input:
          autocomplete_headers: false
          stop_magic: true
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
  - test_id: 3
    description: "autocomplete headers explicitly"
    stages:
      - input:
          autocomplete_headers: false
          stop_magic: false
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
`

var autocompleteHeadersTrueYaml = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    description: "do not autocomplete headers explicitly"
    stages:
      - input:
          autocomplete_headers: true
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
  - test_id: 2
    description: "do not autocomplete headers explicitly"
    stages:
      - input:
          autocomplete_headers: true
          stop_magic: true
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
  - test_id: 3
    description: "do not autocomplete headers explicitly"
    stages:
      - input:
          autocomplete_headers: true
          stop_magic: false
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          expect_error: False
          status: 200
`

var logContainsSetsMatchRegex = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          log_contains: homer
`

var logContainsDoesNotOverrideMatchRegex = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          log_contains: homer
          log:
            match_regex: marge
`

var logContainsDoesNotOverrideExpectId = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          log_contains: homer
          log:
            expect_ids: [123456]
`

var noLogContainsSetsNoMatchRegex = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          no_log_contains: homer
`

var noLogContainsDoesNotOverrideNoMatchRegex = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          no_log_contains: homer
          log:
            no_match_regex: marge
`

var noLogContainsDoesNotOverrideNoExpectId = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          no_log_contains: homer
          log:
            no_expect_ids: [123456]
`

var headersEmpty = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
        output:
          no_log_contains: homer
          log:
            no_expect_ids: [123456]
`

var onlyHeaders = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
        output:
          no_log_contains: homer
          log:
            no_expect_ids: [123456]
`

var onlyOrderedHeaders = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          ordered_headers:
            - name: User-Agent
              value: "ordered agent"
            - name: Accept
              value: "ordered/agent"
        output:
          no_log_contains: homer
          log:
            no_expect_ids: [123456]
`

var headersAndOrderedHeaders = `---
meta:
  author: "tester"
  description: "Example Test"
rule_id: 123456
tests:
  - test_id: 1
    stages:
      - input:
          dest_addr: "localhost"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Accept: "*/*"
            Host: "localhost"
          ordered_headers:
            - name: User-Agent
              value: "ordered agent"
            - name: Accept
              value: "ordered/agent"
        output:
          no_log_contains: homer
          log:
            no_expect_ids: [123456]
`

func (s *typesTestSuite) TestAutocompleteHeadersDefault_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersDefaultYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	s.True(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersDefault_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersDefaultYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].Input
	s.False(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.True(*input.StopMagic)
}
func (s *typesTestSuite) TestAutocompleteHeadersDefault_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersDefaultYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].Input
	s.True(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersFalse_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersFalseYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	s.False(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersFalse_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersFalseYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].Input
	s.False(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersFalse_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersFalseYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].Input
	s.False(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersTrue_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersTrueYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	s.True(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersTrue_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersTrueYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].Input
	s.True(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersTrue_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersTrueYaml), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].Input
	s.True(*input.AutocompleteHeaders)
	//nolint:staticcheck
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestLogContainsSetsMatchRegex() {
	test, err := GetTestFromYaml([]byte(logContainsSetsMatchRegex), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	output := test.Tests[0].Stages[0].Output
	s.Equal("homer", output.Log.MatchRegex)
}

func (s *typesTestSuite) TestLogContainsDoesNotOverrideMatchRegex() {
	test, err := GetTestFromYaml([]byte(logContainsDoesNotOverrideMatchRegex), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	output := test.Tests[0].Stages[0].Output
	s.Equal("marge", output.Log.MatchRegex)
}

func (s *typesTestSuite) TestLogContainsDoesNotOverrideExpectIds() {
	test, err := GetTestFromYaml([]byte(logContainsDoesNotOverrideExpectId), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	output := test.Tests[0].Stages[0].Output
	s.Equal("", output.Log.MatchRegex)
}

func (s *typesTestSuite) TestNoLogContainsSetsNoMatchRegex() {
	test, err := GetTestFromYaml([]byte(noLogContainsSetsNoMatchRegex), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	output := test.Tests[0].Stages[0].Output
	s.Equal("homer", output.Log.NoMatchRegex)
}

func (s *typesTestSuite) TestNoLogContainsDoesNotOverrideNoMatchRegex() {
	test, err := GetTestFromYaml([]byte(noLogContainsDoesNotOverrideNoMatchRegex), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	output := test.Tests[0].Stages[0].Output
	s.Equal("marge", output.Log.NoMatchRegex)
}

func (s *typesTestSuite) TestNoLogContainsDoesNotOverrideNoExpectIds() {
	test, err := GetTestFromYaml([]byte(noLogContainsDoesNotOverrideNoExpectId), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	output := test.Tests[0].Stages[0].Output
	s.Equal("", output.Log.NoMatchRegex)
}

func (s *typesTestSuite) TestPostLoadHeaders_EmptyHeaders() {
	test, err := GetTestFromYaml([]byte(headersEmpty), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	//nolint:staticcheck
	s.Nil(input.Headers)
	s.Nil(input.OrderedHeaders)
}

//nolint:staticcheck
func (s *typesTestSuite) TestPostLoadHeaders_OnlyHeaders() {
	test, err := GetTestFromYaml([]byte(onlyHeaders), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	s.NotNil(input.Headers)
	s.NotNil(input.OrderedHeaders)
	s.Len(input.Headers, 3)
	s.Len(input.OrderedHeaders, 3)
	s.Equal("Accept", input.OrderedHeaders[0].Name)
	s.Equal("*/*", input.OrderedHeaders[0].Value)
	s.Equal("Host", input.OrderedHeaders[1].Name)
	s.Equal("localhost", input.OrderedHeaders[1].Value)
	s.Equal("User-Agent", input.OrderedHeaders[2].Name)
	s.Equal("ModSecurity CRS 3 Tests", input.OrderedHeaders[2].Value)
}

func (s *typesTestSuite) TestPostLoadHeaders_OnlyOrderedHeaders() {
	test, err := GetTestFromYaml([]byte(onlyOrderedHeaders), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	//nolint:staticcheck
	s.Nil(input.Headers)
	s.NotNil(input.OrderedHeaders)
	s.Len(input.OrderedHeaders, 2)
	s.Equal("User-Agent", input.OrderedHeaders[0].Name)
	s.Equal("ordered agent", input.OrderedHeaders[0].Value)
	s.Equal("Accept", input.OrderedHeaders[1].Name)
	s.Equal("ordered/agent", input.OrderedHeaders[1].Value)
}

//nolint:staticcheck
func (s *typesTestSuite) TestPostLoadHeaders_HeadersAndOrderedHeaders() {
	test, err := GetTestFromYaml([]byte(headersAndOrderedHeaders), "")
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Input
	s.NotNil(input.Headers)
	s.NotNil(input.OrderedHeaders)
	s.Len(input.Headers, 3)
	s.Len(input.OrderedHeaders, 2)
	s.Equal("User-Agent", input.OrderedHeaders[0].Name)
	s.Equal("ordered agent", input.OrderedHeaders[0].Value)
	s.Equal("Accept", input.OrderedHeaders[1].Name)
	s.Equal("ordered/agent", input.OrderedHeaders[1].Value)
}

var payloadTemplateYaml = `---
meta:
  author: "tester"
rule_id: 942100
template:
  method: GET
  uri: "/?q={{.Payload | urlquery}}"
  headers:
    - name: Host
      value: localhost
    - name: X-Payload
      value: "{{.Payload}}"
tests:
  - id: 1
    payload: "1 UNION SELECT 1,2,3--"
    output:
      log:
        expect_ids: [942100]
  - id: 2
    template:
      method: POST
      data: "q={{.Payload}}"
    payload: "{{7*7}}"
`

func (s *typesTestSuite) TestPayloadTemplate_FileLevel() {
	test, err := GetTestFromYaml([]byte(payloadTemplateYaml), "")
	s.Require().NoError(err)

	s.Require().Len(test.Tests[0].Stages, 1)
	stage := test.Tests[0].Stages[0]
	s.Equal("GET", *stage.Input.Method)
	s.Equal("/?q=1+UNION+SELECT+1%2C2%2C3--", *stage.Input.URI)
	s.Equal([]schema.HeaderTuple{{Name: "Host", Value: "localhost"}, {Name: "X-Payload", Value: "1 UNION SELECT 1,2,3--"}}, stage.Input.OrderedHeaders)
	s.Equal([]uint{942100}, stage.Output.Log.ExpectIds)
	s.True(*stage.Input.AutocompleteHeaders, "stage should be post-processed")
}

func (s *typesTestSuite) TestPayloadTemplate_PerTestOverride() {
	test, err := GetTestFromYaml([]byte(payloadTemplateYaml), "")
	s.Require().NoError(err)

	s.Require().Len(test.Tests[1].Stages, 1)
	input := NewInput(&test.Tests[1].Stages[0].Input)
	s.Equal("POST", input.GetMethod())
	s.Equal("/?q=%7B%7B7%2A7%7D%7D", input.GetURI(), "unset fields fall through to the file-level template")
	s.Equal("q={{7*7}}", string(input.GetData()), "payload must not be evaluated as a template")
}

func (s *typesTestSuite) TestPayloadTemplate_WithStagesFails() {
	yaml := `---
rule_id: 1
template:
  uri: "/{{.Payload}}"
tests:
  - payload: x
    stages:
      - input: {}
`
	_, err := GetTestFromYaml([]byte(yaml), "")
	s.ErrorContains(err, "mutually exclusive")
}

func (s *typesTestSuite) TestPayloadTemplate_WithoutTemplateFails() {
	yaml := `---
rule_id: 1
tests:
  - payload: x
`
	_, err := GetTestFromYaml([]byte(yaml), "")
	s.ErrorContains(err, "requires a file-level or per-test template")
}

func (s *typesTestSuite) TestPayloadTemplate_RenderFails() {
	for name, tmpl := range map[string]string{
		"uri parse error":   "  uri: \"/{{.Payload\"",
		"uri exec error":    "  uri: \"/{{.Missing}}\"",
		"data exec error":   "  data: \"{{.Missing}}\"",
		"header exec error": "  headers:\n    - name: X\n      value: \"{{.Missing}}\"",
	} {
		s.Run(name, func() {
			yaml := "---\nrule_id: 1\ntemplate:\n" + tmpl + "\ntests:\n  - payload: x\n"
			_, err := GetTestFromYaml([]byte(yaml), "")
			s.ErrorContains(err, "test 1-1: rendering")
		})
	}
}

func (s *typesTestSuite) TestPayloadTemplate_StopMagicFails() {
	for name, yaml := range map[string]string{
		"file-level": "---\nrule_id: 1\ntemplate:\n  stop_magic: true\ntests:\n  - payload: x\n",
		"per-test":   "---\nrule_id: 1\ntemplate:\n  uri: /\ntests:\n  - payload: x\n    template:\n      stop_magic: true\n",
	} {
		s.Run(name, func() {
			_, err := GetTestFromYaml([]byte(yaml), "")
			s.ErrorContains(err, "stop_magic is not supported in templates")
		})
	}
}
