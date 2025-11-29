// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
	"go.yaml.in/yaml/v4"
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

	//nolint:staticcheck
	headers := test.FTWTest.Tests[0].Stages[0].Input.Headers
	s.Contains(headers, expectedKey)
	s.Equal(expectedValue, headers[expectedKey])
}

func (s *yamlTestSuite) TestOrderedHeaders() {
	yamlString := `---
tests:
  - test_id: 1234
    stages:
      - input:
          headers:
            "User-Agent": "test agent"
            "Accept": "*/*"
          ordered_headers:
            - name: Host
              value: localhost
            - name: User-Agent
              value: "test agent1"
            - name: Host
              value: localhost
            - name: Accept
              value: "*/*"
`
	test := &FTWTest{}

	err := yaml.Unmarshal([]byte(yamlString), test)
	s.Require().NoError(err)

	//nolint:staticcheck
	headers := test.Tests[0].Stages[0].Input.Headers
	s.Len(headers, 2)
	s.Contains(headers, "User-Agent")
	s.Equal("test agent", headers["User-Agent"])
	s.Contains(headers, "Accept")
	s.Equal("*/*", headers["Accept"])

	orderedHeaders := test.Tests[0].Stages[0].Input.OrderedHeaders
	s.Len(orderedHeaders, 4)
	s.Equal("Host", orderedHeaders[0].Name)
	s.Equal("localhost", orderedHeaders[0].Value)
	s.Equal("User-Agent", orderedHeaders[1].Name)
	s.Equal("test agent1", orderedHeaders[1].Value)
	s.Equal("Host", orderedHeaders[2].Name)
	s.Equal("localhost", orderedHeaders[2].Value)
	s.Equal("Accept", orderedHeaders[3].Name)
	s.Equal("*/*", orderedHeaders[3].Value)
}
