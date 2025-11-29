// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative"
	"github.com/coreruleset/go-ftw/v2/output"
)

const (
	corpusFlag          = "corpus"
	corpusLangFlag      = "corpus-lang"
	corpusLineFlag      = "corpus-line"
	corpusSizeFlag      = "corpus-size"
	corpusSourceFlag    = "corpus-source"
	corpusYearFlag      = "corpus-year"
	corpusLocalPathFlag = "corpus-local-path"
	crsPathFlag         = "crs-path"
	corpusFileFlag      = "file"
	linesFlag           = "lines"
	maxConcurrencyFlag  = "max-concurrency"
	corpusOutputFlag    = "output"
	paranoiaLevelFlag   = "paranoia-level"
	payloadFlag         = "payload"
	ruleFlag            = "rule"

	minCrsParanoiaLevel = 1
	maxCrsParanoiaLevel = 4
)

// NewQuantitativeCmd
// Returns a new cobra command for running quantitative tests
func NewQuantitativeCmd() *cobra.Command {
	runCmd := &cobra.Command{
		Use:     "quantitative",
		Aliases: []string{"q"},
		Short:   "Run quantitative tests",
		Long:    `Run all quantitative tests`,
		RunE:    runQuantitativeE,
	}

	runCmd.Flags().IntP(linesFlag, "l", 0, "Number of lines of input to process before stopping.")
	runCmd.Flags().IntP(paranoiaLevelFlag, "P", 1, "Paranoia level used to run the quantitative tests.")
	runCmd.Flags().IntP(corpusLineFlag, "n", 0, "Number is the payload line from the corpus to exclusively send.")
	runCmd.Flags().StringP(payloadFlag, "p", "", "Payload is a string you want to test using quantitative tests. Will not use the corpus.")
	runCmd.Flags().IntP(ruleFlag, "r", 0, "Rule ID of interest: only show false positives for specified rule ID.")
	runCmd.Flags().IntP(maxConcurrencyFlag, "", 10, "maximum number of goroutines. Defaults to 10, or 1 if log level is debug/trace.")
	runCmd.Flags().StringP(corpusFlag, "c", "leipzig", "Corpus to use for the quantitative tests.")
	runCmd.Flags().StringP(corpusLangFlag, "L", "eng", "Corpus language to use for the quantitative tests.")
	runCmd.Flags().StringP(corpusSizeFlag, "s", "100K", "Corpus size to use for the quantitative tests. Most corpora will have sizes like \"100K\", \"1M\", etc.")
	runCmd.Flags().StringP(corpusYearFlag, "y", "2023", "Corpus year to use for the quantitative tests. Most corpus will have a year like \"2023\", \"2022\", etc.")
	runCmd.Flags().StringP(corpusSourceFlag, "S", "news", "Corpus source to use for the quantitative tests. Most corpus will have a source like \"news\", \"web\", \"wikipedia\", etc.")
	runCmd.Flags().String(corpusLocalPathFlag, "", "Path to store the local corpora. Defaults to .ftw folder under user's home directory.")
	runCmd.Flags().StringP(crsPathFlag, "C", ".", "Path to top folder of local CRS installation.")
	runCmd.Flags().StringP(corpusFileFlag, "f", "", "Output file path for quantitative tests. Prints to standard output by default.")
	runCmd.Flags().StringP(corpusOutputFlag, "o", "normal", "Output type for quantitative tests.")

	return runCmd
}

//gocyclo:ignore
func runQuantitativeE(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	corpusTypeAsString, err := cmd.Flags().GetString(corpusFlag)
	if err != nil {
		return err
	}
	corpusSize, err := cmd.Flags().GetString(corpusSizeFlag)
	if err != nil {
		return err
	}
	corpusLang, err := cmd.Flags().GetString(corpusLangFlag)
	if err != nil {
		return err
	}
	corpusYear, err := cmd.Flags().GetString(corpusYearFlag)
	if err != nil {
		return err
	}
	corpusSource, err := cmd.Flags().GetString(corpusSourceFlag)
	if err != nil {
		return err
	}
	directory, err := cmd.Flags().GetString(crsPathFlag)
	if err != nil {
		return err
	}
	corpusLocalPath, err := cmd.Flags().GetString(corpusLocalPathFlag)
	if err != nil {
		return err
	}
	lines, err := cmd.Flags().GetInt(linesFlag)
	if err != nil {
		return err
	}
	outputFilename, err := cmd.Flags().GetString(corpusFileFlag)
	if err != nil {
		return err
	}
	paranoiaLevel, err := cmd.Flags().GetInt(paranoiaLevelFlag)
	if err != nil {
		return err
	}
	payload, err := cmd.Flags().GetString(payloadFlag)
	if err != nil {
		return err
	}
	number, err := cmd.Flags().GetInt(corpusLineFlag)
	if err != nil {
		return err
	}
	rule, err := cmd.Flags().GetInt(ruleFlag)
	if err != nil {
		return err
	}
	wantedOutput, err := cmd.Flags().GetString(corpusOutputFlag)
	if err != nil {
		return err
	}
	maxConcurrency, err := cmd.Flags().GetInt(maxConcurrencyFlag)
	if err != nil {
		return err
	}

	// --max-concurrency defaults to 1 if debug/trace is enabled, but if set explicitly, it should override this
	if !cmd.Flags().Changed(maxConcurrencyFlag) && zerolog.GlobalLevel() <= zerolog.DebugLevel {
		maxConcurrency = 1
	}

	if paranoiaLevel < minCrsParanoiaLevel || paranoiaLevel > maxCrsParanoiaLevel {
		return fmt.Errorf("paranoia level must be between %d and %d", minCrsParanoiaLevel, maxCrsParanoiaLevel)
	}

	if paranoiaLevel > minCrsParanoiaLevel && rule > 0 {
		return fmt.Errorf("paranoia level and rule ID cannot be used together")
	}

	// use outputFile to write to file
	var outputFile *os.File
	if outputFilename == "" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.OpenFile(outputFilename, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
	}
	out := output.NewOutput(wantedOutput, outputFile)

	var corpusType corpus.Type
	if corpusTypeAsString != "" {
		err = corpusType.Set(corpusTypeAsString)
		if err != nil {
			return err
		}
	}

	params := quantitative.Params{
		Corpus:          corpusType,
		CorpusSize:      corpusSize,
		CorpusYear:      corpusYear,
		CorpusLang:      corpusLang,
		CorpusSource:    corpusSource,
		Directory:       directory,
		CorpusLocalPath: corpusLocalPath,
		Lines:           lines,
		ParanoiaLevel:   paranoiaLevel,
		Number:          number,
		Payload:         payload,
		Rule:            rule,
		MaxConcurrency:  maxConcurrency,
	}

	return quantitative.RunQuantitativeTests(params, out)
}
