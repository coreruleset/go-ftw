// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-getter"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/experimental/corpus"
	"github.com/coreruleset/go-ftw/output"
)

type runnerTestSuite struct {
	suite.Suite
	params Params
	c      corpus.Corpus
	dir    string
}

func TestRunnerTestSuite(t *testing.T) {
	suite.Run(t, new(runnerTestSuite))
}

func (s *runnerTestSuite) SetupTest() {
	s.params = Params{
		Lines:         1000,
		Fast:          10,
		Rule:          1000,
		Payload:       "test",
		Number:        1000,
		Directory:     path.Join(s.dir, fmt.Sprintf("coreruleset-%s", crsTestVersion)),
		ParanoiaLevel: 1,
		CorpusSize:    "10K",
		Corpus:        "leipzig",
		CorpusLang:    "eng",
		CorpusYear:    "2023",
		CorpusSource:  "news",
	}
	s.dir = path.Join(os.TempDir())
	s.Require().NoError(os.MkdirAll(s.dir, 0755))
	client := &getter.Client{
		Mode: getter.ClientModeAny,
		Src:  crsUrl,
		Dst:  s.dir,
	}

	err := client.Get()
	s.Require().NoError(err)
}

func (s *runnerTestSuite) TeardownTest() {
	err := os.RemoveAll(s.dir)
	s.Require().NoError(err)
}

func (s *runnerTestSuite) TestCorpusFactory() {
	var err error
	s.c, err = CorpusFactory(corpus.Leipzig)
	s.Require().NoError(err)
	s.Require().NotNil(s.c)
	s.Require().Equal(s.c.URL(), "https://downloads.wortschatz-leipzig.de/corpora")

	s.c, err = CorpusFactory(corpus.NoType)
	s.Require().Error(err)
}

func (s *runnerTestSuite) TestRunQuantitativeTests() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	err := RunQuantitativeTests(s.params, out)
	s.Require().NoError(err)
}
