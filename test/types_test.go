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

var noAutocompleteHeadersDefaultYaml = `---
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

var noAutocompleteHeadersFalseYaml = `---
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
            no_autocomplete_headers: false
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
            no_autocomplete_headers: false
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
            no_autocomplete_headers: false
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

var noAutocompleteHeadersTrueYaml = `---
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
            no_autocomplete_headers: true
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
            no_autocomplete_headers: true
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
            no_autocomplete_headers: true
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

func (s *typesTestSuite) TestNoAutocompleteHeadersDefault_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersDefaultYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Stage.Input
	s.False(*input.NoAutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersDefault_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersDefaultYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].Stage.Input
	s.True(*input.NoAutocompleteHeaders)
	s.True(*input.StopMagic)
}
func (s *typesTestSuite) TestNoAutocompleteHeadersDefault_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersDefaultYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].Stage.Input
	s.False(*input.NoAutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersFalse_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersFalseYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Stage.Input
	s.False(*input.NoAutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersFalse_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersFalseYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].Stage.Input
	s.False(*input.NoAutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersFalse_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersFalseYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].Stage.Input
	s.False(*input.NoAutocompleteHeaders)
	s.False(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersTrue_StopMagicDefault() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersTrueYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[0].Stages[0].Stage.Input
	s.True(*input.NoAutocompleteHeaders)
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersTrue_StopMagicTrue() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersTrueYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[1].Stages[0].Stage.Input
	s.True(*input.NoAutocompleteHeaders)
	s.True(*input.StopMagic)
}

func (s *typesTestSuite) TestNoAutocompleteHeadersTrue_StopMagicFalse() {
	test, err := GetTestFromYaml([]byte(noAutocompleteHeadersTrueYaml))
	s.NoError(err, "Parsing YAML shouldn't fail")

	input := test.Tests[2].Stages[0].Stage.Input
	s.True(*input.NoAutocompleteHeaders)
	s.True(*input.StopMagic)
}
