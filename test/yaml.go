// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"go.yaml.in/yaml/v4"
)

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
