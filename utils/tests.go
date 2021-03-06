package utils

import (
	"io/ioutil"
	"os"
)

// CreateTempFileWithContent will create a temporary file with the content passed, and using the nameTemplate.
// returns the name of the created file, and error is not nil if some problem happened
func CreateTempFileWithContent(content string, nameTemplate string) (string, error) {
	tmpFile, err := ioutil.TempFile(os.TempDir(), nameTemplate)
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
