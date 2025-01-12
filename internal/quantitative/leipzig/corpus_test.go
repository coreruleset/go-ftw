// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/experimental/corpus"
)

type leipzigCorpusTestSuite struct {
	suite.Suite
	corpus corpus.Corpus
	cache  corpus.File
	iter   corpus.Iterator
}

func (s *leipzigCorpusTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestLeipzigCorpusTestSuite(t *testing.T) {
	suite.Run(t, new(leipzigCorpusTestSuite))
}

func (s *leipzigCorpusTestSuite) SetupTest() {
	s.corpus = NewLeipzigCorpus()
	s.Require().Equal("https://downloads.wortschatz-leipzig.de/corpora", s.corpus.URL())
	s.Require().Equal("eng", s.corpus.Language())
	s.Require().Equal("100K", s.corpus.Size())
	s.Require().Equal("news", s.corpus.Source())
	s.Require().Equal("2023", s.corpus.Year())
}

func (s *leipzigCorpusTestSuite) TestWithSize() {
	s.corpus.WithSize("300K")
	s.Require().Equal("300K", s.corpus.Size())
}

func (s *leipzigCorpusTestSuite) TestWithYear() {
	s.corpus.WithYear("2024")
	s.Require().Equal("2024", s.corpus.Year())
}

func (s *leipzigCorpusTestSuite) TestWithSource() {
	s.corpus.WithSource("news")
	s.Require().Equal("news", s.corpus.Source())
}

func (s *leipzigCorpusTestSuite) TestWithLanguage() {
	s.corpus.WithLanguage("eng")
	s.Require().Equal("eng", s.corpus.Language())
}

func (s *leipzigCorpusTestSuite) TestWithURL() {
	s.corpus.WithURL("https://downloads.wortschatz-leipzig.de/corpora")
	s.Require().Equal("https://downloads.wortschatz-leipzig.de/corpora", s.corpus.URL())
}

func (s *leipzigCorpusTestSuite) TestGetIterator() {
	s.corpus = s.corpus.WithSize("10K")
	s.cache = s.corpus.FetchCorpusFile()
	s.iter = s.corpus.GetIterator(s.cache)
}

func (s *leipzigCorpusTestSuite) TestNextSentenceFromCorpus() {
	s.cache = s.corpus.FetchCorpusFile()
	s.iter = s.corpus.GetIterator(s.cache)
	s.Require().True(s.iter.HasNext())
	payload := s.iter.Next()
	s.Require().Equal(1, payload.LineNumber())
	s.Require().Equal("$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.", payload.Content())
}
