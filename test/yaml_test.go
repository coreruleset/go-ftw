// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type yamlTestSuite struct {
	suite.Suite
}

func (s *yamlTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestYamlTestSuite(t *testing.T) {
	suite.Run(t, new(yamlTestSuite))
}

func (s *yamlTestSuite) TestUnmarshalling_LineFeed() {
	s.testUnmarshalling(`\n`, "\n")
}

func (s *yamlTestSuite) TestUnmarshalling_CarriageReturn() {
	s.testUnmarshalling(`\r`, "\r")

}

func (s *yamlTestSuite) testUnmarshalling(escapeSequence string, literal string) {
	yamlTemplate := `---
tests:
  - test_id: 1234
    stages:
      - input:
          headers:
            "%s": "%s"
`
	keyTemplate := "Some%sHeader"
	valueTemplate := "some%svalue"

	key := fmt.Sprintf(keyTemplate, escapeSequence)
	value := fmt.Sprintf(valueTemplate, escapeSequence)
	expectedKey := fmt.Sprintf(keyTemplate, literal)
	expectedValue := fmt.Sprintf(valueTemplate, literal)

	yamlString := fmt.Sprintf(yamlTemplate, key, value)
	test := &FTWTest{}

	err := yaml.Unmarshal([]byte(yamlString), test)
	s.Require().NoError(err)

	headers := test.FTWTest.Tests[0].Stages[0].Input.Headers
	s.Contains(headers, expectedKey)
	s.Equal(expectedValue, headers[expectedKey])
}
