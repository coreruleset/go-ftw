package utils

import (
	"os"
	"testing"
)

var content = `This is the content`

func TestCreateTempFile(t *testing.T) {
	filename, err := CreateTempFileWithContent(content, "test-content-*")
	// Remember to clean up the file afterwards
	defer os.Remove(filename)

	if err != nil {
		t.Fatalf("Error!")
	}
}
