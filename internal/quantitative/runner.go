// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/experimental/corpus"
	"github.com/coreruleset/go-ftw/output"
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
	// ParanoiaLevel is the paranoia level in where to run the quantitative tests
	ParanoiaLevel int
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
}

// RunQuantitativeTests runs all quantitative tests
func RunQuantitativeTests(params Params, out *output.Output) error {
	var lc corpus.File
	out.Println(":hourglass: Running quantitative tests")
	log.Trace().Msgf("Rule: %d", params.Rule)
	log.Trace().Msgf("Payload: %s", params.Payload)
	log.Trace().Msgf("Directory: %s", params.Directory)
	log.Trace().Msgf("Paranoia level: %d", params.ParanoiaLevel)

	startTime := time.Now()
	// create the results
	stats := NewQuantitativeStats()

	var engine LocalEngine = &localEngine{}
	runner := engine.Create(params.Directory, params.ParanoiaLevel)

	// Are we using the corpus at all?
	// TODO: this could be moved to a generic "file" iterator (instead of "corpus"), with a Factory method
	if params.Payload != "" {
		log.Trace().Msgf("--payload is used, ignoring corpus related parameters. Payload received: %q", params.Payload)
		p, err := PayloadFactory(params.Corpus)
		if err != nil {
			return err
		}
		p.SetContent(params.Payload)
		stats.incrementRun()
		// CrsCall with payload
		doEngineCall(runner, p, params.Rule, stats)

		stats.SetTotalTime(time.Since(startTime))
		stats.printSummary(out)
		return nil

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
	corpusRunner, err := CorpusFactory(params.Corpus)
	if err != nil {
		return err
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
	for iter := corpusRunner.GetIterator(lc); iter.HasNext(); {
		payload := iter.Next()
		stats.incrementRun()
		content := payload.Content()
		log.Trace().Msgf("Line: %s", content)
		// check if we are looking for a specific payload line #
		if needSpecificPayload(params.Number, stats.Count()) {
			continue
		}
		log.Trace().Msgf("Payload: %s", payload)

		// check if we only want to process a specific number of lines
		if params.Lines > 0 && stats.Count() >= params.Lines {
			break
		}
		doEngineCall(runner, payload, params.Rule, stats)
	}

	stats.SetTotalTime(time.Since(startTime))
	stats.printSummary(out)
	return nil
}

// needSpecificPayload returns true when the line we have is the one we want
func needSpecificPayload(want int, have int) bool {
	return want == have
}

// wantSpecificRuleResults returns true
func wantSpecificRuleResults(specific int, rule int) bool {
	skip := false
	if specific > 0 && specific != rule {
		skip = true
	}
	return skip
}

// doEngineCall
func doEngineCall(engine LocalEngine, payload corpus.Payload, specificRule int, stats *QuantitativeRunStats) {
	matchedRules := engine.CrsCall(payload.Content())
	log.Trace().Msgf("Rules: %v", matchedRules)
	if len(matchedRules) != 0 {
		// append the line to the false positives
		log.Trace().Msgf("False positive with string: %s", payload)
		log.Trace().Msgf("=> rules matched: %+v", matchedRules)
		for rule, data := range matchedRules {
			// check if we only want to show false positives for a specific rule
			if wantSpecificRuleResults(specificRule, rule) {
				continue
			}
			stats.addFalsePositive(rule)
			log.Debug().Msgf("**> rule %d with payload %d => %s", rule, payload.LineNumber(), data)
		}
	}
}
