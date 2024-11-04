// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/experimental/corpus"
	"github.com/coreruleset/go-ftw/internal/quantitative"
	"github.com/coreruleset/go-ftw/output"
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

	runCmd.Flags().IntP("lines", "l", 0, "Number of lines of input to process before stopping.")
	runCmd.Flags().IntP("paranoia-level", "P", 1, "Paranoia level used to run the quantitative tests.")
	runCmd.Flags().IntP("corpus-line", "n", 0, "Number is the payload line from the corpus to exclusively send.")
	runCmd.Flags().StringP("payload", "p", "", "Payload is a string you want to test using quantitative tests. Will not use the corpus.")
	runCmd.Flags().IntP("rule", "r", 0, "Rule ID of interest: only show false positives for specified rule ID.")
	runCmd.Flags().IntP("max-concurrency", "", 10, "maximum number of goroutines. Defaults to 10, or 1 if log level is debug/trace.")
	runCmd.Flags().StringP("corpus", "c", "leipzig", "Corpus to use for the quantitative tests.")
	runCmd.Flags().StringP("corpus-lang", "L", "eng", "Corpus language to use for the quantitative tests.")
	runCmd.Flags().StringP("corpus-size", "s", "100K", "Corpus size to use for the quantitative tests. Most corpora will have sizes like \"100K\", \"1M\", etc.")
	runCmd.Flags().StringP("corpus-year", "y", "2023", "Corpus year to use for the quantitative tests. Most corpus will have a year like \"2023\", \"2022\", etc.")
	runCmd.Flags().StringP("corpus-source", "S", "news", "Corpus source to use for the quantitative tests. Most corpus will have a source like \"news\", \"web\", \"wikipedia\", etc.")
	runCmd.Flags().StringP("crs-path", "C", ".", "Path to top folder of local CRS installation.")
	runCmd.Flags().StringP("file", "f", "", "Output file path for quantitative tests. Prints to standard output by default.")
	runCmd.Flags().StringP("output", "o", "normal", "Output type for quantitative tests. \"normal\" is the default.")

	return runCmd
}

func runQuantitativeE(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	corpusTypeAsString, _ := cmd.Flags().GetString("corpus")
	corpusSize, _ := cmd.Flags().GetString("corpus-size")
	corpusLang, _ := cmd.Flags().GetString("corpus-lang")
	corpusYear, _ := cmd.Flags().GetString("corpus-year")
	corpusSource, _ := cmd.Flags().GetString("corpus-source")
	directory, _ := cmd.Flags().GetString("crs-path")
	fast, _ := cmd.Flags().GetInt("fast")
	lines, _ := cmd.Flags().GetInt("lines")
	outputFilename, _ := cmd.Flags().GetString("file")
	paranoiaLevel, _ := cmd.Flags().GetInt("paranoia-level")
	payload, _ := cmd.Flags().GetString("payload")
	number, _ := cmd.Flags().GetInt("number")
	rule, _ := cmd.Flags().GetInt("rule")
	wantedOutput, _ := cmd.Flags().GetString("output")
	maxConcurrency, _ := cmd.Flags().GetInt("max-concurrency")

	// --max-concurrency defaults to 1 if debug/trace is enabled, but if set explicitly, it should override this
	if !cmd.Flags().Changed("max-concurrency") && zerolog.GlobalLevel() <= zerolog.DebugLevel {
		maxConcurrency = 1
	}

	if paranoiaLevel > 1 && rule > 0 {
		return fmt.Errorf("paranoia level and rule ID cannot be used together")
	}

	// use outputFile to write to file
	var outputFile *os.File
	var err error
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
		Corpus:         corpusType,
		CorpusSize:     corpusSize,
		CorpusYear:     corpusYear,
		CorpusLang:     corpusLang,
		CorpusSource:   corpusSource,
		Directory:      directory,
		Fast:           fast,
		Lines:          lines,
		ParanoiaLevel:  paranoiaLevel,
		Number:         number,
		Payload:        payload,
		Rule:           rule,
		MaxConcurrency: maxConcurrency,
	}

	return quantitative.RunQuantitativeTests(params, out)
}
