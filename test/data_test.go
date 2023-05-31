package test

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/goccy/go-yaml"
)

var repeatTestSprig = `foo=%3d++++++++++++++++++++++++++++++++++`

type dataTestSuite struct {
	suite.Suite
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
Content-Type: "application/x-www-form-urlencoded"
data: "hi=test"
protocol: "http"
stop_magic: true
uri: "/"
`
	input := Input{}
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.NoError(err)
	s.True(input.StopMagic)
}

func (s *dataTestSuite) TestGetPartialDataFromYAML() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: "application/x-www-form-urlencoded"
data: "hi=test"
version: ""
protocol: "http"
stop_magic: true
uri: "/"
`
	input := Input{}
	err := yaml.Unmarshal([]byte(yamlString), &input)
	s.NoError(err)
	s.Empty(*input.Version)
}

func (s *dataTestSuite) TestDataTemplateFromYAML() {
	yamlString := `
dest_addr: "127.0.0.1"
method: ""
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: "application/x-www-form-urlencoded"
data: 'foo=%3d{{ "+" | repeat 34 }}'
version: ""
protocol: "http"
stop_magic: true
uri: "/"
`
	input := Input{}
	var data []byte
	err := yaml.Unmarshal([]byte(yamlString), &input)

	s.NoError(err)
	data = input.ParseData()
	s.Equal([]byte(repeatTestSprig), data)
}
