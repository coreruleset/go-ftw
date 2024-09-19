package quantitative

import (
	"github.com/coreruleset/go-ftw/experimental/corpus"
	"github.com/coreruleset/go-ftw/internal/quantitative/leipzig"
	"github.com/coreruleset/go-ftw/output"
	"github.com/rs/zerolog/log"
	"net/http"
	"time"
)

// QuantitativeParams holds the parameters for the quantitative tests
type QuantitativeParams struct {
	// Lines is the number of lines of input to process before stopping
	Lines int
	// Fast is the process 1 in every X lines of input ('fast run' mode)
	Fast int
	// Rule is the rule ID of interest: only show false positives for specified rule ID
	Rule int
	// Payload is just a string to use instead of reading from the corpus
	Payload string
	// Number is the payload number (the line in the corpus) to exclusively send
	Number int
	// Directory is the directory where the CRS rules are stored
	Directory string
	// Markdown is the Markdown table output mode
	Markdown bool
	// ParanoiaLevel is the paranoia level in where to run the quantitative tests
	ParanoiaLevel int
	// CorpusSize is the corpus size to use for the quantitative tests
	CorpusSize string
	// Corpus is the corpus to use for the quantitative tests
	Corpus string
	// CorpusLang is the language of the corpus
	CorpusLang string
	// CorpusYear is the year of the corpus
	CorpusYear string
	// CorpusSource is the source of the corpus: e.g. most corpus will have a source like "news", "web", "wikipedia", etc.
	CorpusSource string
}

// NewCorpus creates a new corpus
func NewCorpus(name string) corpus.Corpus {
	switch name {
	case "leipzig":
		return leipzig.NewLeipzigCorpus()
	default:
		log.Fatal().Msgf("Unknown corpus %s", name)
		return nil
	}
}

// RunQuantitativeTests runs all quantitative tests
func RunQuantitativeTests(params QuantitativeParams, out *output.Output) error {
	log.Info().Msg("Running quantitative tests")

	log.Trace().Msgf("Lines: %d", params.Lines)
	log.Trace().Msgf("Fast: %d", params.Fast)
	log.Trace().Msgf("Rule: %d", params.Rule)
	log.Trace().Msgf("Payload: %s", params.Payload)
	log.Trace().Msgf("Read Corpus Line: %d", params.Number)
	log.Trace().Msgf("Directory: %s", params.Directory)
	log.Trace().Msgf("Markdown: %t", params.Markdown)
	log.Trace().Msgf("Paranoia level: %d", params.ParanoiaLevel)
	log.Trace().Msgf("Corpus size: %s", params.CorpusSize)
	log.Trace().Msgf("Corpus lang: %s", params.CorpusLang)
	log.Trace().Msgf("Corpus: %s", params.Corpus)

	startTime := time.Now()
	// create a new corpusRunner
	corpusRunner := NewCorpus(params.Corpus).
		WithSize(params.CorpusSize).
		WithYear(params.CorpusYear).
		WithSource(params.CorpusSource).
		WithLanguage(params.CorpusLang)

	// download the corpusRunner file
	lc := corpusRunner.GetCorpusFile()
	// create the results
	stats := NewQuantitativeStats()

	runner := NewEngine(params.Directory, params.ParanoiaLevel)

	// Are we using the corpus at all?
	if params.Payload != "" {
		// CrsCall with payload
		doEngineCall(runner, params.Payload, params.Rule, stats)
	} else { // iterate over the corpus
		for iter := corpusRunner.GetIterator(lc); iter.HasNext(); {
			line := iter.Next()
			stats.Run++
			log.Trace().Msgf("Line: %s", line)
			// check if we are looking for a specific payload line #
			if needSpecificPayload(params.Number, stats.Run) {
				continue
			}
			// ask the corpus to get the payload
			payload := corpusRunner.GetPayload(line)

			log.Trace().Msgf("Payload: %s", payload)

			// check if we only want to process a specific number of lines
			if params.Lines > 0 && stats.Run >= params.Lines {
				break
			}
		}
	}

	stats.TotalTime = time.Since(startTime)
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
func doEngineCall(engine *LocalEngine, payload string, specificRule int, stats *QuantitativeRunStats) {
	status, matchedRules := engine.CRSCall(payload)
	log.Trace().Msgf("Status: %d", status)
	log.Trace().Msgf("Rules: %v", matchedRules)
	if status == http.StatusForbidden {
		// append the line to the false positives
		log.Debug().Msgf("False positive with string: %s", payload)
		log.Trace().Msgf("=> rules matched: %+v", matchedRules)
		for rule, data := range matchedRules {
			// check if we only want to show false positives for a specific rule
			if wantSpecificRuleResults(rule, specificRule) {
				log.Debug().Msgf("rule %d does not match the specific rule we wanted %d", rule, specificRule)
				continue
			}
			stats.addFalsePositive(rule)
			log.Debug().Msgf("==> rule %d matched with data: %s", rule, data)
		}
	}
}
