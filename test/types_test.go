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

var autocompleteHeadersYaml = `---
rule_id: 123456
tests:
  - id: 1
    stages:
      - input: {}
  - id: 2
    stages:
      - input:
          autocomplete_headers: false
  - id: 3
    stages:
      - input:
          autocomplete_headers: true
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
          log:
            no_expect_ids: [123456]
`

func (s *typesTestSuite) TestAutocompleteHeaders() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersYaml), "")
	s.Require().NoError(err, "Parsing YAML shouldn't fail")

	s.True(*test.Tests[0].Stages[0].Input.AutocompleteHeaders, "should default to true")
	s.False(*test.Tests[1].Stages[0].Input.AutocompleteHeaders)
	s.True(*test.Tests[2].Stages[0].Input.AutocompleteHeaders)
}

func (s *typesTestSuite) TestRemovedFieldsFail() {
	for field, expected := range map[string]string{
		"input:\n          stop_magic: true":        "test 123456-1, stage 0: stop_magic is no longer supported",
		"output:\n          log_contains: homer":    "test 123456-1, stage 0: log_contains is no longer supported",
		"output:\n          no_log_contains: homer": "test 123456-1, stage 0: no_log_contains is no longer supported",
	} {
		s.Run(expected, func() {
			yaml := "---\nrule_id: 123456\ntests:\n  - stages:\n      - " + field + "\n"
			_, err := GetTestFromYaml([]byte(yaml), "")
			s.ErrorContains(err, expected)
		})
	}
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
