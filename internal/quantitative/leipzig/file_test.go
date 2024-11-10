// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type fileTestSuite struct {
	suite.Suite
}

func TestFileSuite(t *testing.T) {
	suite.Run(t, new(fileTestSuite))
}

func (s *fileTestSuite) TestFile_CacheDir() {
	f := NewFile()
	f = f.WithCacheDir("cacheDir")
	s.Require().Equal("cacheDir", f.CacheDir())
	f = f.WithFilePath("filePath")
	s.Require().Equal("filePath", f.FilePath())
}
