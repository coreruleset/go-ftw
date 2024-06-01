// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"regexp"

	"github.com/goccy/go-yaml"
)

type errorMap struct {
	matchers    []string
	explanation string
}

// GetTestFromYaml will get the tests to be processed from a YAML string.
func GetTestFromYaml(testYaml []byte, fileName string) (ftwTest *FTWTest, err error) {
	ftwTest = &FTWTest{}
	err = yaml.Unmarshal(testYaml, ftwTest)
	if err != nil {
		return nil, err
	}

	if err := postLoadTestFTWTest(ftwTest, fileName); err != nil {
		return nil, err
	}

	return ftwTest, nil
}

func DescribeYamlError(yamlError error) string {
	errorMaps := []errorMap{
		{
			matchers: []string{`.*int was used where sequence is expected.*`},
			explanation: "Tip: This might refer to a \"status\" line being '200', where it should be '[200]'.\n" +
				"The default \"status\" is a list now.\n" +
				"A simple example would be like this:\n\n" +
				"status: 403\n" +
				"needs to be changed to:\n\n" +
				"status: 403",
		},
		{
			matchers: []string{`.*cannot unmarshal \[]interface {} into Go struct field FTWTest.Tests of type string.*`},
			explanation: "Tip: This might refer to \"data\" on the test being a list of strings instead of a proper YAML multiline.\n" +
				"To fix this, convert this \"data\" string list to a multiline YAML and this will be fixed.\n" +
				"A simple example would be like this:\n\n" +
				"data:\n" +
				"  - 'Hello'\n" +
				"  - 'World'\n" +
				"can be expressed as:\n\n" +
				"data: |\n" +
				"  Hello\n" +
				"  World\n\n" +
				"You can also remove single/double quotes from beggining and end of text, they are not needed. See https://yaml-multiline.info/ for additional help.",
		},
		{
			matchers: []string{
				"The rule_id field is required for the top-level test structure",
				"Failed to fall back on filename to find rule ID of test. The rule_id field is required for the top-level test structure",
				"failed to parse rule ID from filename ",
			},
			explanation: "The `rule_id` field is missing from this file and the rule ID could not be determined otherwise.\n" +
				"This might be a YAML file that is not a test.",
		},
	}
	errorMessage := yamlError.Error()
	for _, em := range errorMaps {
		for _, regex := range em.matchers {
			matched, err := regexp.MatchString(regex, errorMessage)
			if err != nil {
				return err.Error()
			}
			if !matched {
				continue
			}
			return "\n" + em.explanation + "\n\n"
		}
	}

	return "\nWe do not have an extended explanation of this error\n\n"
}
