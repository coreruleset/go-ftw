// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-getter/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/internal/corpus"
	"github.com/coreruleset/go-ftw/output"
)

type runnerTestSuite struct {
	suite.Suite
	params Params
	c      corpus.Corpus
	dir    string
}

func (s *runnerTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestRunnerTestSuite(t *testing.T) {
	suite.Run(t, new(runnerTestSuite))
}

func (s *runnerTestSuite) SetupTest() {
	s.params = Params{
		Lines:          1000,
		Fast:           10,
		Rule:           1000,
		Directory:      path.Join(s.dir, fmt.Sprintf("coreruleset-%s", crsTestVersion)),
		ParanoiaLevel:  1,
		MaxConcurrency: 10,
		CorpusSize:     "10K",
		Corpus:         "leipzig",
		CorpusLang:     "eng",
		CorpusYear:     "2023",
		CorpusSource:   "news",
	}
	s.dir = path.Join(os.TempDir())
	s.Require().NoError(os.MkdirAll(s.dir, 0755))
	request := &getter.Request{
		Src:     crsUrl,
		Dst:     s.dir,
		GetMode: getter.ModeAny,
	}
	client := &getter.Client{
		Getters: []getter.Getter{
			new(getter.HttpGetter),
		},
	}

	_, err := client.Get(context.Background(), request)
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

func (s *runnerTestSuite) TestRunQuantitative() {
	s.Run("with corpus", func() {
		var b bytes.Buffer
		out := output.NewOutput("plain", &b)
		err := RunQuantitativeTests(s.params, out)
		s.Require().Contains(b.String(), "Run 1000 payloads (0 skipped)")
		s.Require().NoError(err)
	})

	s.Run("with corpus and specific corpus line", func() {
		s.params.Number = 100
		var b bytes.Buffer
		out := output.NewOutput("plain", &b)
		err := RunQuantitativeTests(s.params, out)
		s.Require().Contains(b.String(), "(999 skipped)")
		s.Require().NoError(err)
	})

	s.Run("with payload", func() {
		s.params.Payload = "<script>alert('0')</script>"
		s.params.Rule = 0 // Reset the field, we don't want to check only a specific rule
		var b bytes.Buffer
		out := output.NewOutput("plain", &b)
		err := RunQuantitativeTests(s.params, out)
		s.Require().NoError(err)
		s.Require().Contains(b.String(), "1 false positives")
	})
}
