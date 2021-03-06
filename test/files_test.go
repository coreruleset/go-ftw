package test

import (
	"testing"

	"github.com/fzipi/go-ftw/utils"
)

var yamlTest = `
---
  meta:
    author: "tester"
    enabled: true
    name: "911100.yaml"
    description: "Description"
  tests:
    -
      test_title: 911100-1
      stages:
        -
          stage:
            input:
              dest_addr: "127.0.0.1"
              port: 80
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "localhost"
            output:
              no_log_contains: "id \"911100\""
    -
      test_title: 911100-2
      stages:
        -
          stage:
            input:
              dest_addr: "127.0.0.1"
              port: 80
              method: "OPTIONS"
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "localhost"
            output:
              no_log_contains: "id \"911100\""
`

var wrongYamlTest = `
this is not yaml
`

func TestGetTestFromYAML(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(yamlTest, "test-yaml-*")
	tests, _ := GetTestsFromFiles(filename)

	for _, ft := range tests {
		if ft.Meta.Author != "tester" {
			t.Fatalf("Error!")
		}
		if ft.Meta.Name != "911100.yaml" {
			t.Fatalf("Error!")
		}
	}
}

func TestGetFromBadYAML(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(wrongYamlTest, "test-yaml-*")
	_, err := GetTestsFromFiles(filename)

	if err != nil {
		t.Fatalf("Error!")
	}
}
