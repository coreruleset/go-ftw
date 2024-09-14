package leipzig

import (
	"github.com/coreruleset/go-ftw/experimental/corpus"
	"github.com/stretchr/testify/suite"
	"testing"
)

type leipzigCorpusTestSuite struct {
	suite.Suite
	corpus corpus.Corpus
	cache  corpus.CorpusFile
	iter   corpus.Iterator
}

func TestLeipzigCorpusTestSuite(t *testing.T) {
	suite.Run(t, new(leipzigCorpusTestSuite))
}

func (s *leipzigCorpusTestSuite) SetupTest() {
	s.corpus = NewLeipzigCorpus()
	s.Require().Equal("https://downloads.wortschatz-leipzig.de/corpora", s.corpus.URL())
	s.Require().Equal("eng", s.corpus.Lang())
	s.Require().Equal("100K", s.corpus.Size())
	s.Require().Equal("news", s.corpus.Source())
	s.Require().Equal("2023", s.corpus.Year())
}

func (s *leipzigCorpusTestSuite) TestWithSize() {
	s.corpus.WithSize("300K")
	s.Require().Equal("300K", s.corpus.Size())
}

func (s *leipzigCorpusTestSuite) TestGetIterator() {
	s.corpus.WithSize("10K")
	s.cache = s.corpus.GetCorpusFile()
	s.iter = s.corpus.GetIterator(s.cache)
}

func (s *leipzigCorpusTestSuite) TestNextSentenceFromCorpus() {
	s.cache = s.corpus.GetCorpusFile()
	s.iter = s.corpus.GetIterator(s.cache)
	s.Require().True(s.iter.HasNext())
	s.Require().Equal("1\t$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.", s.iter.Next())
}

func (s *leipzigCorpusTestSuite) TestGetPayloadFromString() {
	s.cache = s.corpus.GetCorpusFile()
	s.iter = s.corpus.GetIterator(s.cache)
	s.Require().True(s.iter.HasNext())
	s.Require().Equal("1\t$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.", s.iter.Next())
}
