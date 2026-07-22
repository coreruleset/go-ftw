// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"testing"

	"github.com/hashicorp/go-getter/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/output"
)

type runnerTestSuite struct {
	suite.Suite
	params  Params
	c       corpus.Corpus
	tempDir string
}

func (s *runnerTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestRunnerTestSuite(t *testing.T) {
	suite.Run(t, new(runnerTestSuite))
}

func (s *runnerTestSuite) SetupTest() {
	s.tempDir = s.T().TempDir()
	paranoiaLevels, err := NewParanoiaLevels(1)
	s.Require().NoError(err)
	s.params = Params{
		Lines:          1000,
		Fast:           10,
		Rules:          []int{1000},
		Directory:      path.Join(s.tempDir, fmt.Sprintf("coreruleset-%s", crsTestVersion)),
		ParanoiaLevels: paranoiaLevels,
		MaxConcurrency: 10,
		CorpusSize:     "10K",
		Corpus:         "leipzig",
		CorpusLang:     "eng",
		CorpusYear:     "2023",
		CorpusSource:   "news",
	}
	request := &getter.Request{
		Src:     crsUrl,
		Dst:     s.tempDir,
		GetMode: getter.ModeAny,
	}
	client := &getter.Client{
		Getters: []getter.Getter{
			new(getter.HttpGetter),
		},
	}

	_, err = client.Get(context.Background(), request)
	s.Require().NoError(err)
}

func (s *runnerTestSuite) TestEvaluateThreshold() {
	newStats := func() *QuantitativeRunStats {
		q := NewQuantitativeStats(nil)
		q.incrementRun()
		q.incrementRun()
		q.incrementRun()
		q.incrementRun()
		q.addFalsePositive(920100, 1) // ratio 0.25
		q.addFalsePositive(920200, 2) // ratio 0.25
		q.addFalsePositive(920200, 2) // ratio 0.5 total for 920200
		return q
	}

	s.Run("disabled when threshold is zero", func() {
		result := evaluateThreshold(Params{Threshold: 0, Rules: []int{920200}}, newStats())
		s.Require().Nil(result)
	})

	s.Run("passes when all requested rules are under threshold", func() {
		result := evaluateThreshold(Params{Threshold: 0.6, Rules: []int{920100, 920200}}, newStats())
		s.Require().NotNil(result)
		s.Require().True(result.Passed)
		s.Require().NoError(thresholdError(result))
	})

	s.Run("fails when one of several requested rules exceeds threshold", func() {
		result := evaluateThreshold(Params{Threshold: 0.3, Rules: []int{920100, 920200}}, newStats())
		s.Require().NotNil(result)
		s.Require().False(result.Passed)
		s.Require().Equal([]ThresholdRuleResult{
			{RuleID: 920100, Ratio: 0.25, Passed: true},
			{RuleID: 920200, Ratio: 0.5, Passed: false},
		}, result.Rules)

		err := thresholdError(result)
		s.Require().ErrorIs(err, ErrThresholdExceeded)
		s.Require().Contains(err.Error(), "920200")
		s.Require().NotContains(err.Error(), "920100")
	})

	s.Run("rule never seen in results passes trivially", func() {
		result := evaluateThreshold(Params{Threshold: 0.1, Rules: []int{999999}}, newStats())
		s.Require().NotNil(result)
		s.Require().True(result.Passed)
		s.Require().NoError(thresholdError(result))
	})
}

func (s *runnerTestSuite) TestCorpusFactory_NoType() {
	_, err := CorpusFactory(corpus.NoType, "")
	s.Require().Error(err)
}

func (s *runnerTestSuite) TestCorpusFactory_Leipzig() {
	var err error
	s.c, err = CorpusFactory(corpus.Leipzig, "")
	s.Require().NoError(err)
	s.Require().NotNil(s.c)
	s.Require().Equal(s.c.URL(), "https://downloads.wortschatz-leipzig.de/corpora")

	userDefinedCacheDir := s.T().TempDir()
	s.c, err = CorpusFactory(corpus.Leipzig, userDefinedCacheDir)
	s.Require().NoError(err)
	s.Require().NotNil(s.c)
	s.Require().Equal(s.c.URL(), "https://downloads.wortschatz-leipzig.de/corpora")
	s.Require().Equal(s.c.LocalPath(), userDefinedCacheDir)
}

func (s *runnerTestSuite) TestCorpusFactory_Raw() {
	var err error
	filePath := path.Join(s.tempDir, "corpus.txt")
	s.c, err = CorpusFactory(corpus.Raw, filePath)
	s.Require().NoError(err)
	s.Require().NotNil(s.c)
	s.Require().Equal(s.c.URL(), "")
	s.Require().Equal(s.c.LocalPath(), filePath)
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
		s.params.Rules = nil // Reset the field, we don't want to check only a specific rule
		var b bytes.Buffer
		out := output.NewOutput("plain", &b)
		err := RunQuantitativeTests(s.params, out)
		s.Require().NoError(err)
		s.Require().Contains(b.String(), "1 false positives")
	})
}
