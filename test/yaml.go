// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"regexp"

	"github.com/goccy/go-yaml"
)

// GetTestFromYaml will get the tests to be processed from a YAML string.
func GetTestFromYaml(testYaml []byte, fileName string) (ftwTest *FTWTest, err error) {
	ftwTest = &FTWTest{}
	err = yaml.Unmarshal(testYaml, ftwTest)
	if err != nil {
		return &FTWTest{}, err
	}

	postLoadTestFTWTest(ftwTest, fileName)

	return ftwTest, nil
}

func DescribeYamlError(yamlError error) string {
	matched, err := regexp.MatchString(`.*int was used where sequence is expected.*`, yamlError.Error())
	if err != nil {
		return err.Error()
	}
	if matched {
		return "\nTip: This might refer to a \"status\" line being '200', where it should be '[200]'.\n" +
			"The default \"status\" is a list now.\n" +
			"A simple example would be like this:\n\n" +
			"status: 403\n" +
			"needs to be changed to:\n\n" +
			"status: 403\n\n"
	}
	matched, err = regexp.MatchString(`.*cannot unmarshal \[]interface {} into Go struct field FTWTest.Tests of type string.*`, yamlError.Error())
	if err != nil {
		return err.Error()
	}
	if matched {
		return "\nTip: This might refer to \"data\" on the test being a list of strings instead of a proper YAML multiline.\n" +
			"To fix this, convert this \"data\" string list to a multiline YAML and this will be fixed.\n" +
			"A simple example would be like this:\n\n" +
			"data:\n" +
			"  - 'Hello'\n" +
			"  - 'World'\n" +
			"can be expressed as:\n\n" +
			"data: |\n" +
			"  Hello\n" +
			"  World\n\n" +
			"You can also remove single/double quotes from beggining and end of text, they are not needed. See https://yaml-multiline.info/ for additional help.\n"
	}

	return "We do not have an extended explanation of this error."
}
