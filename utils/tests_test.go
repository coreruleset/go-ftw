// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

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

	s.Require().NoError(err)
}

func (s *testFilesTestSuite) TestCreateBadTempFile() {
	filename, err := CreateTempFileWithContent(content, "/dev/null/*")
	// Remember to clean up the file afterwards
	defer os.Remove(filename)

	s.Error(err)
}
