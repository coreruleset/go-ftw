// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"
)

// CreateTempFileWithContent will create a temporary file with the content passed, and using the nameTemplate.
// If `tempDir` is the empty string, `os.TempDir()` will be used as the target directory.
// Returns the name of the created file, and error is not nil if some problem happened
func CreateTempFileWithContent(tempDir string, content string, nameTemplate string) (string, error) {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tmpFile, err := os.CreateTemp(tempDir, nameTemplate)
	if err != nil {
		return "", err
	}

	// Example writing to the file
	text := []byte(content)
	if _, err = tmpFile.Write(text); err != nil {
		return "", err
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

// CreateTempFile will create a temporary file using the nameTemplate.
// If `tempDir` is the empty string, `os.TempDir()` will be used as the target directory.
// Returns the name of the created file, and error is not nil if some problem happened
func CreateTempFile(tempDir string, nameTemplate string) (string, error) {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tmpFile, err := os.CreateTemp(tempDir, nameTemplate)
	if err != nil {
		return "", err
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}
