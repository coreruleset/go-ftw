package test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/goccy/go-yaml"
)

var repeatTestSprig = `foo=%3d++++++++++++++++++++++++++++++++++`

func TestGetDataFromYAML(t *testing.T) {
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
	assert.NoError(t, err)
	assert.True(t, input.StopMagic)
}

func TestGetPartialDataFromYAML(t *testing.T) {
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
	assert.NoError(t, err)
	assert.Empty(t, *input.Version)
}

func TestDataTemplateFromYAML(t *testing.T) {
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

	assert.NoError(t, err)
	data = input.ParseData()
	assert.Equal(t, []byte(repeatTestSprig), data)
}
