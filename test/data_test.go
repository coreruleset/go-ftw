package test

import (
	"bytes"
	"testing"

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

	if err == nil && input.StopMagic == true {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
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

	if err == nil && *input.Version == "" {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
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

	if err != nil {
		t.Fatalf("Failed !")
	}

	if data = input.ParseData(); bytes.Equal(data, []byte(repeatTestSprig)) {
		t.Logf("Success !")
	} else {
		t.Fatalf("Failed: %s", data)
	}
}
