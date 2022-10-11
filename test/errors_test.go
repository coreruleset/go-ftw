package test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/utils"
)

var errorsTest = `---
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

func TestGetLinesFromTestName(t *testing.T) {
	filename, _ := utils.CreateTempFileWithContent(errorsTest, "test-yaml-*")
	tests, _ := GetTestsFromFiles(filename)

	for _, ft := range tests {
		line, _ := ft.GetLinesFromTest("911100-2")
		assert.Equal(t, 22, line, "Not getting the proper line.")
	}
}
