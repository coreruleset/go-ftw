// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative"
	"github.com/coreruleset/go-ftw/v2/output"
)

const (
	allParanoiaLevelsFlag = "all-paranoia-levels"
	corpusFlag            = "corpus"
	corpusLangFlag        = "corpus-lang"
	corpusLineFlag        = "corpus-line"
	corpusSizeFlag        = "corpus-size"
	corpusSourceFlag      = "corpus-source"
	corpusYearFlag        = "corpus-year"
	corpusLocalPathFlag   = "corpus-local-path"
	crsPathFlag           = "crs-path"
	baselineFlag          = "baseline"
	compareCRSFlag        = "compare-crs"
	outputFileFlag        = "file"
	linesFlag             = "lines"
	maxConcurrencyFlag    = "max-concurrency"
	outputTypeFlag        = "output"
	paranoiaLevelFlag     = "paranoia-level"
	paranoiaLevelsFlag    = "paranoia-levels"
	payloadFlag           = "payload"
	ruleFlag              = "rule"

	minCrsParanoiaLevel = quantitative.MinParanoiaLevel
	maxCrsParanoiaLevel = quantitative.MaxParanoiaLevel
)

var emptyParams = quantitative.Params{}

// New returns a new cobra command for running quantitative tests
func New(cmdContext *internal.CommandContext) *cobra.Command {
	runCmd := &cobra.Command{
		Use:     "quantitative",
		Aliases: []string{"q"},
		Short:   "Run quantitative tests",
		Long:    `Run all quantitative tests`,
		RunE:    runQuantitativeE,
	}

	runCmd.Flags().IntP(linesFlag, "l", 0, "Number of lines of input to process before stopping.")
	runCmd.Flags().IntP(paranoiaLevelFlag, "P", 1, "Paranoia level used to run the quantitative tests.")
	runCmd.Flags().IntSlice(paranoiaLevelsFlag, nil, "Paranoia levels to evaluate in one run, e.g. 1,2,3,4.")
	runCmd.Flags().Bool(allParanoiaLevelsFlag, false, "Evaluate all CRS paranoia levels in one run.")
	runCmd.Flags().IntP(corpusLineFlag, "n", 0, "Number is the payload line from the corpus to exclusively send.")
	runCmd.Flags().StringP(payloadFlag, "p", "", "Payload is a string you want to test using quantitative tests. Will not use the corpus.")
	runCmd.Flags().IntP(ruleFlag, "r", 0, "Rule ID of interest: only show false positives for specified rule ID. Defaults to paranoia level 4 unless -P is also set.")
	runCmd.Flags().IntP(maxConcurrencyFlag, "", 10, "maximum number of goroutines. Defaults to 10, or 1 if log level is debug/trace.")
	runCmd.Flags().StringP(corpusFlag, "c", "leipzig", "Corpus to use for the quantitative tests (leipzig, raw).")
	runCmd.Flags().StringP(corpusLangFlag, "L", "eng", "Corpus language to use for the quantitative tests.")
	runCmd.Flags().StringP(corpusSizeFlag, "s", "100K", "Corpus size to use for the quantitative tests. Most corpora will have sizes like \"100K\", \"1M\", etc.")
	runCmd.Flags().StringP(corpusYearFlag, "y", "2023", "Corpus year to use for the quantitative tests. Most corpus will have a year like \"2023\", \"2022\", etc.")
	runCmd.Flags().StringP(corpusSourceFlag, "S", "news", "Corpus source to use for the quantitative tests. Most corpus will have a source like \"news\", \"web\", \"wikipedia\", etc.")
	runCmd.Flags().String(corpusLocalPathFlag, "", `For corpora being downloaded, this flag specifies the storage path. Defaults to .ftw folder under user's home directory.
For the "raw" corpus type, this flag specifies the path to the corpus file.`)
	runCmd.Flags().StringP(crsPathFlag, "C", ".", "Path to top folder of local CRS installation.")
	runCmd.Flags().String(baselineFlag, "", "Path to a prior quantitative JSON result to compare against.")
	runCmd.Flags().String(compareCRSFlag, "", "Path to another CRS tree to run with the same parameters and compare against.")
	runCmd.Flags().StringP(outputFileFlag, "f", "", "Output file path for quantitative tests. Prints to standard output by default.")
	runCmd.Flags().StringP(outputTypeFlag, "o", "normal", "Output type for quantitative tests.")
	_ = runCmd.Flags().MarkDeprecated(paranoiaLevelFlag, fmt.Sprintf("use --%s instead", paranoiaLevelsFlag))
	runCmd.MarkFlagsMutuallyExclusive(paranoiaLevelFlag, paranoiaLevelsFlag, allParanoiaLevelsFlag)
	runCmd.MarkFlagsMutuallyExclusive(baselineFlag, compareCRSFlag)

	return runCmd
}

func runQuantitativeE(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	params, err := buildParams(cmd)
	if err != nil {
		return err
	}

	outputFilename, err := cmd.Flags().GetString(outputFileFlag)
	if err != nil {
		return err
	}
	wantedOutput, err := cmd.Flags().GetString(outputTypeFlag)
	if err != nil {
		return err
	}

	var outputFile *os.File
	if outputFilename == "" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.OpenFile(outputFilename, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer func() { _ = outputFile.Close() }()
	}
	out := output.NewOutput(wantedOutput, outputFile)

	return quantitative.RunQuantitativeTests(params, out)
}

//gocyclo:ignore
func buildParams(cmd *cobra.Command) (quantitative.Params, error) {
	corpusTypeAsString, err := cmd.Flags().GetString(corpusFlag)
	if err != nil {
		return emptyParams, err
	}
	corpusSize, err := cmd.Flags().GetString(corpusSizeFlag)
	if err != nil {
		return emptyParams, err
	}
	corpusLang, err := cmd.Flags().GetString(corpusLangFlag)
	if err != nil {
		return emptyParams, err
	}
	corpusYear, err := cmd.Flags().GetString(corpusYearFlag)
	if err != nil {
		return emptyParams, err
	}
	corpusSource, err := cmd.Flags().GetString(corpusSourceFlag)
	if err != nil {
		return emptyParams, err
	}
	directory, err := cmd.Flags().GetString(crsPathFlag)
	if err != nil {
		return emptyParams, err
	}
	corpusLocalPath, err := cmd.Flags().GetString(corpusLocalPathFlag)
	if err != nil {
		return emptyParams, err
	}
	if corpusLocalPath != "" {
		info, err := os.Stat(corpusLocalPath)
		if err != nil {
			return emptyParams, err
		}
		if info.IsDir() {
			return emptyParams, fmt.Errorf("corpus-local-path must be a file, not a directory: %s", corpusLocalPath)
		}
	}
	lines, err := cmd.Flags().GetInt(linesFlag)
	if err != nil {
		return emptyParams, err
	}
	paranoiaLevel, err := cmd.Flags().GetInt(paranoiaLevelFlag)
	if err != nil {
		return emptyParams, err
	}
	paranoiaLevels, err := cmd.Flags().GetIntSlice(paranoiaLevelsFlag)
	if err != nil {
		return emptyParams, err
	}
	allParanoiaLevels, err := cmd.Flags().GetBool(allParanoiaLevelsFlag)
	if err != nil {
		return emptyParams, err
	}
	payload, err := cmd.Flags().GetString(payloadFlag)
	if err != nil {
		return emptyParams, err
	}
	number, err := cmd.Flags().GetInt(corpusLineFlag)
	if err != nil {
		return emptyParams, err
	}
	rule, err := cmd.Flags().GetInt(ruleFlag)
	if err != nil {
		return emptyParams, err
	}
	maxConcurrency, err := cmd.Flags().GetInt(maxConcurrencyFlag)
	if err != nil {
		return emptyParams, err
	}
	baselinePath, err := cmd.Flags().GetString(baselineFlag)
	if err != nil {
		return emptyParams, err
	}
	compareCRSPath, err := cmd.Flags().GetString(compareCRSFlag)
	if err != nil {
		return emptyParams, err
	}
	if baselinePath != "" {
		info, err := os.Stat(baselinePath)
		if err != nil {
			return emptyParams, fmt.Errorf("--%s path does not exist: %w", baselineFlag, err)
		}
		if info.IsDir() {
			return emptyParams, fmt.Errorf("--%s must point to a file: %s", baselineFlag, baselinePath)
		}
	}
	if compareCRSPath != "" {
		info, err := os.Stat(compareCRSPath)
		if err != nil {
			return emptyParams, fmt.Errorf("--%s path does not exist: %w", compareCRSFlag, err)
		}
		if !info.IsDir() {
			return emptyParams, fmt.Errorf("--%s must point to a directory: %s", compareCRSFlag, compareCRSPath)
		}
	}

	// --max-concurrency defaults to 1 if debug/trace is enabled, but if set explicitly, it should override this
	if !cmd.Flags().Changed(maxConcurrencyFlag) && zerolog.GlobalLevel() <= zerolog.DebugLevel {
		maxConcurrency = 1
	}

	requestedParanoiaLevels := []int{paranoiaLevel}

	switch {
	case allParanoiaLevels:
		requestedParanoiaLevels = make([]int, 0, maxCrsParanoiaLevel)
		for level := minCrsParanoiaLevel; level <= maxCrsParanoiaLevel; level++ {
			requestedParanoiaLevels = append(requestedParanoiaLevels, level)
		}
	case len(paranoiaLevels) > 0:
		requestedParanoiaLevels = paranoiaLevels
	case rule > 0 && !cmd.Flags().Changed(paranoiaLevelFlag):
		// Default to max paranoia level so that all rules (including the one of interest) are run.
		requestedParanoiaLevels = []int{maxCrsParanoiaLevel}
	}

	paranoiaLevelSet, err := quantitative.NewParanoiaLevels(requestedParanoiaLevels...)
	if err != nil {
		return emptyParams, err
	}

	corpusType := corpus.NoType
	if corpusTypeAsString != "" {
		if err = corpusType.Set(corpusTypeAsString); err != nil {
			return emptyParams, err
		}
	}

	return quantitative.Params{
		Corpus:          corpusType,
		CorpusSize:      corpusSize,
		CorpusYear:      corpusYear,
		CorpusLang:      corpusLang,
		CorpusSource:    corpusSource,
		Directory:       directory,
		CorpusLocalPath: corpusLocalPath,
		Lines:           lines,
		ParanoiaLevels:  paranoiaLevelSet,
		Number:          number,
		Payload:         payload,
		Rule:            rule,
		MaxConcurrency:  maxConcurrency,
		BaselinePath:    baselinePath,
		CompareCRSPath:  compareCRSPath,
	}, nil
}
