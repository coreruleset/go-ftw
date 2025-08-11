// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/experimental/corpus"
)

type rawCorpusTestSuite struct {
	suite.Suite
	corpus   corpus.Corpus
	tempFile string
	tempDir  string
}

func (s *rawCorpusTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestRawCorpusTestSuite(t *testing.T) {
	suite.Run(t, new(rawCorpusTestSuite))
}

func (s *rawCorpusTestSuite) SetupTest() {
	s.corpus = NewRawCorpus()

	// Create a temporary directory
	var err error
	s.tempDir, err = os.MkdirTemp("", "raw_corpus_test")
	s.Require().NoError(err)

	// Create a test file with sample payloads
	s.tempFile = filepath.Join(s.tempDir, "test_corpus.txt")
	testContent := `This is the first payload
<script>alert('xss')</script>
../../../etc/passwd
SELECT * FROM users WHERE id = '1' OR '1'='1'
Normal sentence with no malicious content`

	err = os.WriteFile(s.tempFile, []byte(testContent), 0644)
	s.Require().NoError(err)

	// Set the file path in the corpus
	s.corpus = s.corpus.WithURL(s.tempFile)
}

func (s *rawCorpusTestSuite) TearDownTest() {
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

func (s *rawCorpusTestSuite) TestNewRawCorpus() {
	c := NewRawCorpus()
	s.Require().Equal("", c.URL())
	s.Require().Equal("unknown", c.Language())
	s.Require().Equal("unknown", c.Size())
	s.Require().Equal("file", c.Source())
	s.Require().Equal("unknown", c.Year())
}

func (s *rawCorpusTestSuite) TestWithSize() {
	s.corpus = s.corpus.WithSize("1000")
	s.Require().Equal("1000", s.corpus.Size())
}

func (s *rawCorpusTestSuite) TestWithYear() {
	s.corpus = s.corpus.WithYear("2024")
	s.Require().Equal("2024", s.corpus.Year())
}

func (s *rawCorpusTestSuite) TestWithSource() {
	s.corpus = s.corpus.WithSource("custom")
	s.Require().Equal("custom", s.corpus.Source())
}

func (s *rawCorpusTestSuite) TestWithLanguage() {
	s.corpus = s.corpus.WithLanguage("en")
	s.Require().Equal("en", s.corpus.Language())
}

func (s *rawCorpusTestSuite) TestWithURL() {
	testPath := "/path/to/test/file.txt"
	s.corpus = s.corpus.WithURL(testPath)
	s.Require().Equal(testPath, s.corpus.URL())
}

func (s *rawCorpusTestSuite) TestFetchCorpusFile() {
	// Test with valid file
	file := s.corpus.FetchCorpusFile()
	s.Require().NotNil(file)
	s.Require().Equal(s.tempFile, file.FilePath())
}

func (s *rawCorpusTestSuite) TestGetIterator() {
	file := s.corpus.FetchCorpusFile()
	iter := s.corpus.GetIterator(file)
	s.Require().NotNil(iter)

	// Test that we can iterate through the payloads
	s.Require().True(iter.HasNext())
	payload1 := iter.Next()
	s.Require().Equal(1, payload1.LineNumber())
	s.Require().Equal("This is the first payload", payload1.Content())

	s.Require().True(iter.HasNext())
	payload2 := iter.Next()
	s.Require().Equal(2, payload2.LineNumber())
	s.Require().Equal("<script>alert('xss')</script>", payload2.Content())

	s.Require().True(iter.HasNext())
	payload3 := iter.Next()
	s.Require().Equal(3, payload3.LineNumber())
	s.Require().Equal("../../../etc/passwd", payload3.Content())

	s.Require().True(iter.HasNext())
	payload4 := iter.Next()
	s.Require().Equal(4, payload4.LineNumber())
	s.Require().Equal("SELECT * FROM users WHERE id = '1' OR '1'='1'", payload4.Content())

	s.Require().True(iter.HasNext())
	payload5 := iter.Next()
	s.Require().Equal(5, payload5.LineNumber())
	s.Require().Equal("Normal sentence with no malicious content", payload5.Content())

	// Should be at end of file now
	s.Require().False(iter.HasNext())
}
