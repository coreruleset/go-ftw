package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var content = `This is the content`

func TestCreateTempFile(t *testing.T) {
	filename, err := CreateTempFileWithContent(content, "test-content-*")
	// Remember to clean up the file afterwards
	defer os.Remove(filename)

	assert.NoError(t, err)
}

func TestCreateBadTempFile(t *testing.T) {
	filename, err := CreateTempFileWithContent(content, "/dev/null/*")
	// Remember to clean up the file afterwards
	defer os.Remove(filename)

	assert.NotNil(t, err)
}
