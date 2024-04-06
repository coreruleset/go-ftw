// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/utils"
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
              autocomplete_headers: false
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

type filesTestSuite struct {
	suite.Suite
}

func TestFilesTestSuite(t *testing.T) {
	suite.Run(t, new(filesTestSuite))
}

func (s *filesTestSuite) TestGetTestFromYAML() {
	filename, _ := utils.CreateTempFileWithContent(yamlTest, "test-yaml-*")
	tests, _ := GetTestsFromFiles(filename)

	for _, ft := range tests {
		s.Equal(filename, ft.FileName)
		s.Equal("tester", ft.Meta.Author)
		s.Equal("911100.yaml", ft.Meta.Name)

		re := regexp.MustCompile("911100*")

		for _, test := range ft.Tests {
			s.True(re.MatchString(test.TestTitle), "Can't read test title")
		}
	}
}

func (s *filesTestSuite) TestGetFromBadYAML() {
	filename, _ := utils.CreateTempFileWithContent(wrongYamlTest, "test-yaml-*")
	_, err := GetTestsFromFiles(filename)

	s.Error(err, "reading yaml should fail")
}

// This test guards against performance regressions in goccy/yaml. It uses
// an artificially large test file to force the YAML parser to run long
// enough so that the performance difference becomse large enough to test.
// The impacted versions of goccy (v1.9.2 - v1.11.3) will score well above
// 0.01 nano seconds per operation.
func (s *filesTestSuite) TestBenchmarkGetTestsFromFiles() {
	result := testing.Benchmark(func(b *testing.B) {
		_, err := GetTestsFromFiles("testdata/TestCheckBenchmarkCheckFiles.yaml")
		if err != nil {
			b.FailNow()
		}
	})
	nsPerOp := float64(result.T.Nanoseconds()) / float64(result.N)
	s.T().Logf("Nano seconds per operation: %f", nsPerOp)
	if nsPerOp > 0.01 {
		s.FailNow("Nano seconds per operation exceeded limit for benchmark: ", nsPerOp)
	}
}
