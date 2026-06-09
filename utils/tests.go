// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"os"
)

// CreateTempFileWithContent will create a temporary file with the content passed, and using the nameTemplate.
// `dir` must be the path to an existing directory.
// Returns the name of the created file
func CreateTempFileWithContent(dir string, content string, nameTemplate string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", dir)
	}

	tmpFile, err := os.CreateTemp(dir, nameTemplate)
	if err != nil {
		return "", err
	}

	defer tmpFile.Close()

	if content != "" {
		if _, err = tmpFile.WriteString(content); err != nil {
			return "", err
		}
	}

	return tmpFile.Name(), nil
}

// CreateTempFile will create a temporary file using the nameTemplate.
// `dir` must be the path to an existing directory.
// Returns the name of the created file
func CreateTempFile(dir string, nameTemplate string) (string, error) {
	return CreateTempFileWithContent(dir, "", nameTemplate)
}
