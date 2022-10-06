package test

import (
	"regexp"
	"testing"

	"github.com/coreruleset/go-ftw/utils"
	"github.com/stretchr/testify/assert"
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
		assert.Equal(t, filename, ft.FileName)
		assert.Equal(t, "tester", ft.Meta.Author)
		assert.Equal(t, "911100.yaml", ft.Meta.Name)

		re := regexp.MustCompile("911100*")

		for _, test := range ft.Tests {
			assert.True(t, re.MatchString(test.TestTitle), "Can't read test title")
		}
	}
}

func TestGetFromBadYAML(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(wrongYamlTest, "test-yaml-*")
	_, err := GetTestsFromFiles(filename)

	assert.NotNil(t, err, "reading yaml should fail")
}
