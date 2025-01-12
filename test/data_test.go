// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

var repeatTestSprig = `foo=%3d++++++++++++++++++++++++++++++++++`

type dataTestSuite struct {
	suite.Suite
}

func (s *dataTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestDataTestSuite(t *testing.T) {
	suite.Run(t, new(dataTestSuite))
}

func (s *dataTestSuite) TestGetDataFromYAML() {
	yamlString := `
dest_addr: "127.0.0.1"
method: "POST"
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
data: "hi=test"
protocol: "http"
autocomplete_headers: true
uri: "/"
`
	input := &schema.Input{}
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)
	s.True(*input.AutocompleteHeaders)
}

func (s *dataTestSuite) TestGetPartialDataFromYAML() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
data: "hi=test"
version: ""
protocol: "http"
autocomplete_headers: false
uri: "/"
`
	input := &schema.Input{}
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)
	s.Empty(*input.Version)
	s.False(*input.AutocompleteHeaders)
}

func (s *dataTestSuite) TestDataTemplateFromYAML() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
data: 'foo=%3d{{ "+" | repeat 34 }}'
version: ""
protocol: "http"
autocomplete_headers: true
uri: "/"
`
	input := &schema.Input{}
	var data []byte
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)

	internalInput := NewInput(input)
	data = internalInput.parseData()
	s.Equal([]byte(repeatTestSprig), data)

	s.True(*input.AutocompleteHeaders)
}

func (s *dataTestSuite) TestGetData_FromDataWithTemplate() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
data: 'foo=%3d{{ "+" | repeat 34 }}'
version: ""
protocol: "http"
autocomplete_headers: true
uri: "/"
`
	input := &schema.Input{}
	var data []byte
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)

	internalData := NewInput(input)
	data = internalData.GetData()
	s.Equal([]byte(repeatTestSprig), data)

	s.True(*input.AutocompleteHeaders)
}

func (s *dataTestSuite) TestGetData_FromData_InvalidTemplate() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
data: 'foo=%3d{{ "+" | repeat 34 }'
version: ""
protocol: "http"
autocomplete_headers: true
uri: "/"
`
	input := &schema.Input{}
	var data []byte
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)

	internalData := NewInput(input)
	data = internalData.GetData()
	s.Nil(data)
}

func (s *dataTestSuite) TestGetData_FromEncodedData() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
encoded_data: VGhpcyBpcyBTcHJpbmdmaWVsZA==
version: ""
protocol: "http"
uri: "/"
`
	input := &schema.Input{}
	var data []byte
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)

	internalData := NewInput(input)
	data = internalData.GetData()
	s.Equal("This is Springfield", string(data))
}

func (s *dataTestSuite) TestGetData_FromEncodedData_InvalidEncoding() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: header_values.ApplicationXWwwFormUrlencoded
encoded_data: VGhpcyBpcyBTcHJpbmdmaWVsZA===
version: ""
protocol: "http"
uri: "/"
`
	input := &schema.Input{}
	var data []byte
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.Require().NoError(err)

	internalData := NewInput(input)
	data = internalData.GetData()
	s.Nil(data)
}
