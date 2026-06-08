// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative/leipzig"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative/raw"
	"github.com/coreruleset/go-ftw/v2/output"
)

// Params holds the inputs for a regex performance run.
type Params struct {
	// Pattern is a raw regex; when set, the assembler is skipped.
	Pattern string
	// RaFile is the path to a regex-assembly (.ra) file.
	RaFile string
	// CrsPath is the coreruleset root for resolving .ra includes.
	CrsPath string
	// Subject is a single inline subject; when set, the corpus is skipped.
	Subject string
	// Repeat is how many times each subject is matched (minimum time kept).
	Repeat int
	// TopN is how many slowest subjects to report.
	TopN int
	// Lines optionally limits how many corpus subjects are processed (0 = all).
	Lines int
	// Corpus selection and metadata (used in corpus mode).
	Corpus          corpus.Type
	CorpusSize      string
	CorpusYear      string
	CorpusLang      string
	CorpusSource    string
	CorpusLocalPath string
}

// repeatOrOne returns the repetition count, defaulting to 1 when unset.
func (p Params) repeatOrOne() int {
	if p.Repeat < 1 {
		return 1
	}
	return p.Repeat
}

// Run resolves the regex, then times it against the inline subject or the
// configured corpus, writing a report to out.
func Run(params Params, out *output.Output) error {
	regexStr, source, err := resolveRegex(params)
	if err != nil {
		return err
	}
	re, err := Compile(regexStr)
	if err != nil {
		return err
	}
	stats := NewStats(source, len(regexStr), params.repeatOrOne(), params.TopN)

	if params.Subject != "" {
		ns, matched := timeMatch(re, params.Subject, params.repeatOrOne())
		stats.Add(params.Subject, ns, matched)
		stats.printSummary(out)
		return nil
	}

	if err := runCorpus(params, re, stats); err != nil {
		return err
	}
	if stats.subjectCount == 0 {
		return fmt.Errorf("no subjects found in corpus")
	}
	stats.printSummary(out)
	return nil
}

// resolveRegex returns the regex string and a human-readable source label.
func resolveRegex(p Params) (regexStr string, source string, err error) {
	if p.Pattern != "" {
		return p.Pattern, "pattern", nil
	}
	if p.RaFile == "" {
		return "", "", fmt.Errorf("either a pattern or a regex-assembly file is required")
	}
	regexStr, err = AssembleFile(p.RaFile, p.CrsPath)
	if err != nil {
		return "", "", err
	}
	return regexStr, "file:" + p.RaFile, nil
}

// runCorpus iterates the configured corpus, timing the regex against each subject.
func runCorpus(params Params, re *regexp.Regexp, stats *Stats) error {
	corpusRunner, err := newCorpus(params.Corpus, params.CorpusLocalPath)
	if err != nil {
		return err
	}
	corpusRunner = corpusRunner.
		WithSize(params.CorpusSize).
		WithYear(params.CorpusYear).
		WithSource(params.CorpusSource).
		WithLanguage(params.CorpusLang)

	cf := corpusRunner.FetchCorpusFile()
	repeat := params.repeatOrOne()
	for iter := corpusRunner.GetIterator(cf); iter.HasNext(); {
		if params.Lines > 0 && stats.subjectCount >= params.Lines {
			break
		}
		payload := iter.Next()
		ns, matched := timeMatch(re, payload.Content(), repeat)
		stats.Add(payload.Content(), ns, matched)
	}
	return corpusRunner.CloseIterator()
}

// newCorpus builds a corpus runner for the given type (mirrors the quantitative
// factory without importing it, to avoid pulling in the Coraza engine).
func newCorpus(t corpus.Type, localPath string) (corpus.Corpus, error) {
	switch t {
	case corpus.Leipzig:
		return leipzig.NewLeipzigCorpus(localPath), nil
	case corpus.Raw:
		return raw.NewRawCorpus(localPath), nil
	default:
		return nil, fmt.Errorf("unsupported corpus type: %s", t)
	}
}

// timeMatch matches subject `repeat` times and returns the minimum elapsed
// nanoseconds (the cleanest estimator of true cost) and whether it matched.
func timeMatch(re *regexp.Regexp, subject string, repeat int) (int64, bool) {
	var minNs int64 = math.MaxInt64
	var matched bool
	for i := 0; i < repeat; i++ {
		start := time.Now()
		m := re.MatchString(subject)
		elapsed := time.Since(start).Nanoseconds()
		if i == 0 {
			matched = m
		}
		if elapsed < minNs {
			minNs = elapsed
		}
	}
	return minNs, matched
}
