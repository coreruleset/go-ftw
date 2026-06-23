// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/output"
)

// Params holds the parameters for the quantitative tests
type Params struct {
	// Lines is the number of lines of input to process before stopping
	Lines int
	// Fast is the process 1 in every X lines of input ('fast run' mode)
	// TODO: to be implemented
	Fast int
	// Rule is the rule ID of interest: only show false positives for specified rule ID
	Rule int
	// Payload is just a string to use instead of reading from the corpus
	Payload string
	// Number is the payload number (the line in the corpus) to exclusively send
	Number int
	// Directory is the directory where the CRS rules are stored
	Directory string
	// CorpusLocalPath is the path to store the local corpora
	CorpusLocalPath string
	// ParanoiaLevels are the paranoia levels to report from a single run.
	ParanoiaLevels ParanoiaLevels
	// CorpusSize is the corpus size to use for the quantitative tests
	CorpusSize string
	// Corpus is the corpus to use for the quantitative tests
	Corpus corpus.Type
	// CorpusLang is the language of the corpus
	CorpusLang string
	// CorpusYear is the year of the corpus
	CorpusYear string
	// CorpusSource is the source of the corpus: e.g. most corpus will have a source like "news", "web", "wikipedia", etc.
	CorpusSource string
	// MaxConcurrency is the maximum number of goroutines spawned
	MaxConcurrency int
	// BaselinePath is a prior quantitative JSON result to compare the current run against
	BaselinePath string
	// CompareCRSPath is the path to the baseline CRS tree to compare against the current directory
	CompareCRSPath string
}

// ErrRegressionsDetected is returned when a quantitative comparison finds regressions.
var ErrRegressionsDetected = errors.New("quantitative regressions detected")

// RunQuantitativeTests runs all quantitative tests
func RunQuantitativeTests(params Params, out *output.Output) error {
	currentStats, err := runQuantitativeTest(params)
	if err != nil {
		return err
	}

	if params.BaselinePath == "" && params.CompareCRSPath == "" {
		currentStats.printSummary(out)
		return nil
	}

	baselineStats, err := baselineStatsForComparison(params)
	if err != nil {
		return err
	}

	comparison := currentStats.Compare(baselineStats)
	comparison.PrintSummary(out)
	if comparison.HasRegressions() {
		return ErrRegressionsDetected
	}
	return nil
}

func baselineStatsForComparison(params Params) (*QuantitativeRunStats, error) {
	if params.BaselinePath != "" {
		return LoadQuantitativeRunStats(params.BaselinePath)
	}

	baselineParams := params
	baselineParams.Directory = params.CompareCRSPath
	baselineParams.BaselinePath = ""
	baselineParams.CompareCRSPath = ""
	return runQuantitativeTest(baselineParams)
}

func runQuantitativeTest(params Params) (*QuantitativeRunStats, error) {
	var lc corpus.File
	log.Info().Msgf("⏳Running quantitative tests with %d goroutines", params.MaxConcurrency)
	log.Trace().Msgf("Rule: %d", params.Rule)
	log.Trace().Msgf("Payload: %s", params.Payload)
	log.Trace().Msgf("Directory: %s", params.Directory)
	log.Trace().Msgf("Local path to corpus file: %s", params.CorpusLocalPath)
	log.Trace().Msgf("Paranoia levels: %v", params.ParanoiaLevels.All())

	startTime := time.Now()
	// create the results
	stats := NewQuantitativeStats()
	stats.SetEvaluatedParanoiaLevels(params.ParanoiaLevels)

	// The engine runs at the highest requested paranoia level so that every
	// rule up to that level is active; lower levels are reported from the matches.
	highestParanoiaLevel := params.ParanoiaLevels.Highest()
	var engine LocalEngine = &localEngine{}
	runner := engine.Create(params.Directory, highestParanoiaLevel)

	// Are we using the corpus at all?
	// TODO: this could be moved to a generic "file" iterator (instead of "corpus"), with a Factory method
	if params.Payload != "" {
		log.Trace().Msgf("--payload is used, ignoring corpus related parameters. Payload received: %q", params.Payload)
		p, err := PayloadFactory(params.Corpus)
		if err != nil {
			return nil, err
		}
		p.SetContent(params.Payload)
		stats.incrementRun()
		// CrsCall with payload
		doEngineCall(runner, p, params.Rule, stats)

		stats.SetTotalTime(time.Since(startTime))
		return stats, nil

	}
	// we are using the corpus
	log.Trace().Msgf("Lines: %d", params.Lines)
	log.Trace().Msgf("Fast: %d", params.Fast)
	log.Trace().Msgf("Read Corpus Line: %d", params.Number)
	log.Trace().Msgf("Corpus size: %s", params.CorpusSize)
	log.Trace().Msgf("Corpus lang: %s", params.CorpusLang)
	log.Trace().Msgf("Corpus name: %s", params.Corpus)
	log.Trace().Msgf("Corpus year: %s", params.CorpusYear)
	log.Trace().Msgf("Corpus source: %s", params.CorpusSource)

	// create a new corpusRunner
	corpusRunner, err := CorpusFactory(params.Corpus, params.CorpusLocalPath)
	if err != nil {
		return nil, err
	}
	corpusRunner = corpusRunner.
		WithSize(params.CorpusSize).
		WithYear(params.CorpusYear).
		WithSource(params.CorpusSource).
		WithLanguage(params.CorpusLang)

	// download the corpusRunner file
	lc = corpusRunner.FetchCorpusFile()

	// iterate over the corpus
	log.Trace().Msgf("Iterating over corpus")
	var wg sync.WaitGroup
	ch := make(chan int, params.MaxConcurrency)

	for iter := corpusRunner.GetIterator(lc); iter.HasNext(); {
		payload := iter.Next()

		// check if we only want to process a specific number of lines
		if params.Lines > 0 && stats.Count() >= params.Lines {
			break
		}

		stats.incrementRun()

		// check if we are looking for a specific payload line #
		if skipPayload(params.Number, stats.Count()) {
			stats.incrementSkip()
			continue
		}
		log.Trace().Int("Line #", stats.Count()).Msgf("Payload: %s", payload.Content())

		wg.Add(1)
		ch <- 1
		go func(runner LocalEngine, payload corpus.Payload, rule int, stats *QuantitativeRunStats) {
			defer func() { wg.Done(); <-ch }()
			doEngineCall(runner, payload, rule, stats)
		}(runner, payload, params.Rule, stats)
	}
	wg.Wait()
	if err := corpusRunner.CloseIterator(); err != nil {
		return nil, err
	}

	stats.SetTotalTime(time.Since(startTime))
	return stats, nil
}

// skipPayload returns true when the payload corresponding to the provided line has to be skipped
func skipPayload(want int, have int) bool {
	// If zero value is set, we have to test all the lines
	if want == 0 {
		return false
	}
	return want != have
}

// wantSpecificRuleResults returns true
func wantSpecificRuleResults(specific int, rule int) bool {
	return specific > 0 && specific != rule
}

// doEngineCall
func doEngineCall(engine LocalEngine, payload corpus.Payload, specificRule int, stats *QuantitativeRunStats) {
	matchedRules := engine.CrsCall(payload.Content())
	log.Trace().Msgf("Rules: %v", matchedRules)
	if len(matchedRules) != 0 {
		// append the line to the false positives
		log.Trace().Msgf("False positive with string: %s", payload)
		log.Trace().Msgf("=> rules matched: %+v", matchedRules)
		for ruleId, match := range matchedRules {
			// check if we only want to show false positives for a specific rule
			if wantSpecificRuleResults(specificRule, ruleId) {
				continue
			}
			stats.addFalsePositive(ruleId, match.ParanoiaLevel)
			log.Debug().Msgf("**> rule %d (PL%d) with payload %d => %s", ruleId, match.ParanoiaLevel, payload.LineNumber(), match.MatchData)
		}
	}
}
