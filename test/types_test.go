// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type typesTestSuite struct {
	suite.Suite
}

func TestTypesTestSuite(t *testing.T) {
	suite.Run(t, new(typesTestSuite))
}

var autocompleteHeadersDefaultYaml = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test"
tests:
  - test_title: "001"
    description: "autocomplete headers by default"
    stages:
      - stage:
          input:
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
  - test_title: "002"
    description: "autocomplete headers by default"
    stages:
      - stage:
          input:
            stop_magic: true
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
  - test_title: "003"
    description: "autocomplete headers by default"
    stages:
      - stage:
          input:
            stop_magic: false
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
`

var autocompleteHeadersFalseYaml = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test"
tests:
  - test_title: "001"
    description: "autocomplete headers explicitly"
    stages:
      - stage:
          input:
            autocomplete_headers: false
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
  - test_title: "002"
    description: "autocomplete headers explicitly"
    stages:
      - stage:
          input:
            autocomplete_headers: false
            stop_magic: true
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
  - test_title: "003"
    description: "autocomplete headers explicitly"
    stages:
      - stage:
          input:
            autocomplete_headers: false
            stop_magic: false
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
`

var autocompleteHeadersTrueYaml = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test"
tests:
  - test_title: "001"
    description: "do not autocomplete headers explicitly"
    stages:
      - stage:
          input:
            autocomplete_headers: true
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
  - test_title: "002"
    description: "do not autocomplete headers explicitly"
    stages:
      - stage:
          input:
            autocomplete_headers: true
            stop_magic: true
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
  - test_title: "003"
    description: "do not autocomplete headers explicitly"
    stages:
      - stage:
          input:
            autocomplete_headers: true
            stop_magic: false
            dest_addr: "localhost"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            expect_error: False
            status: [200]
`

func (s *typesTestSuite) TestAutocompleteHeadersDefault_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersDefaultYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].SD.Input
	s.True(*input.AutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersDefault_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersDefaultYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].SD.Input
	s.False(*input.AutocompleteHeaders)
	s.True(*input.StopMagic)
}
func (s *typesTestSuite) TestAutocompleteHeadersDefault_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersDefaultYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].SD.Input
	s.True(*input.AutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersFalse_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersFalseYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].SD.Input
	s.False(*input.AutocompleteHeaders)
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersFalse_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersFalseYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].SD.Input
	s.False(*input.AutocompleteHeaders)
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersFalse_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersFalseYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].SD.Input
	s.False(*input.AutocompleteHeaders)
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersTrue_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersTrueYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].SD.Input
	s.True(*input.AutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersTrue_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersTrueYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].SD.Input
	s.True(*input.AutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestAutocompleteHeadersTrue_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(autocompleteHeadersTrueYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].SD.Input
	s.True(*input.AutocompleteHeaders)
	s.False(*input.StopMagic)
}
