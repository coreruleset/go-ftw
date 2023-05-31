package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

var content = `This is the content`

type testFilesTestSuite struct {
	suite.Suite
}

func TestFilesTestSuite(t *testing.T) {
	suite.Run(t, new(testFilesTestSuite))
}

func (s *testFilesTestSuite) TestCreateTempFile() {
	filename, err := CreateTempFileWithContent(content, "test-content-*")
	// Remember to clean up the file afterwards
	defer os.Remove(filename)

	s.NoError(err)
}

func (s *testFilesTestSuite) TestCreateBadTempFile() {
	filename, err := CreateTempFileWithContent(content, "/dev/null/*")
	// Remember to clean up the file afterwards
	defer os.Remove(filename)

	s.Error(err)
}
