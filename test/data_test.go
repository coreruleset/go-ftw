package test

import (
	"fmt"
	"testing"

	"gopkg.in/yaml.v2"
)

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
	fmt.Printf("%v", input)

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
