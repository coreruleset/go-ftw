// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/coreruleset/go-ftw/internal/quantitative"
	"github.com/coreruleset/go-ftw/output"
	"github.com/spf13/cobra"
	"os"
)

// NewQuantitativeCmd
// Returns a new cobra command for running quantitative tests
func NewQuantitativeCmd() *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "quantitative",
		Short: "Run Quantitative Tests",
		Long:  `Run all quantitative tests`,
		RunE:  runQuantitativeE,
	}

	runCmd.Flags().BoolP("markdown", "m", false, "Markdown table output mode")
	runCmd.Flags().IntP("fast", "x", 0, "Process 1 in every X lines of input ('fast run' mode)")
	runCmd.Flags().IntP("lines", "l", 0, "Number of lines of input to process before stopping")
	runCmd.Flags().IntP("paranoia-level", "P", 1, "Paranoia level used to run the quantitative tests")
	runCmd.Flags().IntP("number", "n", 0, "Number is the payload line from the corpus to exclusively send")
	runCmd.Flags().StringP("payload", "p", "", "Payload is a string you want to test using quantitative tests. Will not use the corpus.")
	runCmd.Flags().IntP("rule", "r", 0, "Rule ID of interest: only show false positives for specified rule ID")
	runCmd.Flags().StringP("corpus", "c", "leipzig", "Corpus to use for the quantitative tests")
	runCmd.Flags().StringP("corpus-lang", "L", "eng", "Corpus language to use for the quantitative tests.")
	runCmd.Flags().StringP("corpus-size", "s", "100K", "Corpus size to use for the quantitative tests. Most corpus will have a size like \"100K\", \"1M\", etc.")
	runCmd.Flags().StringP("corpus-year", "y", "2023", "Corpus year to use for the quantitative tests. Most corpus will have a year like \"2023\", \"2022\", etc.")
	runCmd.Flags().StringP("corpus-source", "S", "news", "Corpus source to use for the quantitative tests. Most corpus will have a source like \"news\", \"web\", \"wikipedia\", etc.")
	runCmd.Flags().StringP("directory", "d", ".", "Directory where the CRS rules are stored")
	runCmd.Flags().StringP("file", "f", "", "output file path for quantitative tests. Prints to standard output by default.")
	runCmd.Flags().StringP("output", "o", "normal", "output type for quantitative tests. \"normal\" is the default.")

	return runCmd
}

func runQuantitativeE(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	corpus, _ := cmd.Flags().GetString("corpus")
	corpusSize, _ := cmd.Flags().GetString("corpus-size")
	corpusLang, _ := cmd.Flags().GetString("corpus-lang")
	corpusYear, _ := cmd.Flags().GetString("corpus-year")
	corpusSource, _ := cmd.Flags().GetString("corpus-source")
	directory, _ := cmd.Flags().GetString("directory")
	fast, _ := cmd.Flags().GetInt("fast")
	lines, _ := cmd.Flags().GetInt("lines")
	markdown, _ := cmd.Flags().GetBool("markdown")
	outputFilename, _ := cmd.Flags().GetString("file")
	paranoiaLevel, _ := cmd.Flags().GetInt("paranoia-level")
	payload, _ := cmd.Flags().GetString("payload")
	number, _ := cmd.Flags().GetInt("number")
	rule, _ := cmd.Flags().GetInt("rule")
	wantedOutput, _ := cmd.Flags().GetString("output")

	// use outputFile to write to file
	var outputFile *os.File
	var err error
	if outputFilename == "" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.Open(outputFilename)
		if err != nil {
			return err
		}
	}
	out := output.NewOutput(wantedOutput, outputFile)

	params := quantitative.QuantitativeParams{
		Corpus:        corpus,
		CorpusSize:    corpusSize,
		CorpusYear:    corpusYear,
		CorpusLang:    corpusLang,
		CorpusSource:  corpusSource,
		Directory:     directory,
		Fast:          fast,
		Lines:         lines,
		Markdown:      markdown,
		ParanoiaLevel: paranoiaLevel,
		Number:        number,
		Payload:       payload,
		Rule:          rule,
	}

	return quantitative.RunQuantitativeTests(params, out)
}
