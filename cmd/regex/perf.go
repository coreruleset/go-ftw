// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/regexperf"
	"github.com/coreruleset/go-ftw/v2/output"
)

const (
	fileFlag            = "file"
	patternFlag         = "pattern"
	subjectFlag         = "subject"
	crsPathFlag         = "crs-path"
	repeatFlag          = "repeat"
	topFlag             = "top"
	linesFlag           = "lines"
	corpusFlag          = "corpus"
	corpusSizeFlag      = "corpus-size"
	corpusLangFlag      = "corpus-lang"
	corpusYearFlag      = "corpus-year"
	corpusSourceFlag    = "corpus-source"
	corpusLocalPathFlag = "corpus-local-path"
	outputTypeFlag      = "output"
	outFileFlag         = "out-file"
)

// newPerfCommand builds the `regex perf` subcommand.
func newPerfCommand(_ *internal.CommandContext) *cobra.Command {
	perfCmd := &cobra.Command{
		Use:   "perf",
		Short: "Benchmark the runtime performance of a regex against input subjects",
		Long: `Compile a regex from a CRS regex-assembly (.ra) file or a raw pattern,
then measure how it performs against the quantitative corpus or a single subject.`,
		RunE: runPerfE,
	}

	perfCmd.Flags().StringP(fileFlag, "f", "", "Path to a regex-assembly (.ra) file to compile and benchmark.")
	perfCmd.Flags().StringP(patternFlag, "p", "", "Raw regex pattern to benchmark (skips the assembler).")
	perfCmd.Flags().String(subjectFlag, "", "Single inline subject to benchmark against (skips the corpus).")
	perfCmd.Flags().StringP(crsPathFlag, "C", ".", "Path to top folder of local CRS installation (for .ra includes).")
	perfCmd.Flags().IntP(repeatFlag, "R", 10, "Times each subject is matched; the minimum time is kept.")
	perfCmd.Flags().Int(topFlag, 10, "Number of slowest subjects to report.")
	perfCmd.Flags().IntP(linesFlag, "l", 0, "Maximum number of corpus subjects to process (0 = all).")
	perfCmd.Flags().StringP(corpusFlag, "c", "leipzig", "Corpus to use (leipzig, raw).")
	perfCmd.Flags().StringP(corpusSizeFlag, "s", "100K", "Corpus size, e.g. \"100K\", \"1M\".")
	perfCmd.Flags().StringP(corpusLangFlag, "L", "eng", "Corpus language.")
	perfCmd.Flags().StringP(corpusYearFlag, "y", "2023", "Corpus year.")
	perfCmd.Flags().StringP(corpusSourceFlag, "S", "news", "Corpus source, e.g. \"news\", \"web\".")
	perfCmd.Flags().String(corpusLocalPathFlag, "", "Storage path for downloaded corpora; for \"raw\", the path to the corpus file.")
	perfCmd.Flags().StringP(outputTypeFlag, "o", "normal", "Output type: normal or json.")
	perfCmd.Flags().String(outFileFlag, "", "Write the report to this file (default stdout).")

	return perfCmd
}

func runPerfE(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	file, err := cmd.Flags().GetString(fileFlag)
	if err != nil {
		return err
	}
	pattern, err := cmd.Flags().GetString(patternFlag)
	if err != nil {
		return err
	}
	if file != "" && pattern != "" {
		return fmt.Errorf("only one of --%s or --%s may be set", fileFlag, patternFlag)
	}
	if file == "" && pattern == "" {
		return fmt.Errorf("either --%s or --%s is required", fileFlag, patternFlag)
	}

	subject, err := cmd.Flags().GetString(subjectFlag)
	if err != nil {
		return err
	}
	if subject != "" && cmd.Flags().Changed(corpusFlag) {
		return fmt.Errorf("--%s cannot be combined with --%s", subjectFlag, corpusFlag)
	}

	params, err := buildPerfParams(cmd, file, pattern, subject)
	if err != nil {
		return err
	}

	if err := validateRawCorpusPath(params); err != nil {
		return err
	}

	out, closer, err := openPerfOutput(cmd)
	if err != nil {
		return err
	}
	defer closer()

	return regexperf.Run(params, out)
}

// buildPerfParams reads the remaining flags into a regexperf.Params.
func buildPerfParams(cmd *cobra.Command, file, pattern, subject string) (regexperf.Params, error) {
	var p regexperf.Params
	var err error

	p.RaFile = file
	p.Pattern = pattern
	p.Subject = subject

	if p.CrsPath, err = cmd.Flags().GetString(crsPathFlag); err != nil {
		return p, err
	}
	if p.Repeat, err = cmd.Flags().GetInt(repeatFlag); err != nil {
		return p, err
	}
	if p.TopN, err = cmd.Flags().GetInt(topFlag); err != nil {
		return p, err
	}
	if p.Lines, err = cmd.Flags().GetInt(linesFlag); err != nil {
		return p, err
	}
	if p.CorpusSize, err = cmd.Flags().GetString(corpusSizeFlag); err != nil {
		return p, err
	}
	if p.CorpusLang, err = cmd.Flags().GetString(corpusLangFlag); err != nil {
		return p, err
	}
	if p.CorpusYear, err = cmd.Flags().GetString(corpusYearFlag); err != nil {
		return p, err
	}
	if p.CorpusSource, err = cmd.Flags().GetString(corpusSourceFlag); err != nil {
		return p, err
	}
	if p.CorpusLocalPath, err = cmd.Flags().GetString(corpusLocalPathFlag); err != nil {
		return p, err
	}

	corpusType := corpus.NoType
	corpusTypeStr, err := cmd.Flags().GetString(corpusFlag)
	if err != nil {
		return p, err
	}
	if subject == "" && corpusTypeStr != "" {
		if err := corpusType.Set(corpusTypeStr); err != nil {
			return p, err
		}
	}
	p.Corpus = corpusType
	return p, nil
}

// validateRawCorpusPath ensures the raw corpus file exists and is a regular file
// before the run, preventing the corpus layer from calling os.Exit on a missing file.
func validateRawCorpusPath(p regexperf.Params) error {
	if p.Subject != "" || p.Corpus != corpus.Raw {
		return nil
	}
	if p.CorpusLocalPath == "" {
		return fmt.Errorf("--%s is required for the raw corpus", corpusLocalPathFlag)
	}
	info, err := os.Stat(p.CorpusLocalPath)
	if err != nil {
		return fmt.Errorf("raw corpus file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("raw corpus path %q is a directory, expected a file", p.CorpusLocalPath)
	}
	return nil
}

// openPerfOutput creates the Output and a closer for the destination file.
func openPerfOutput(cmd *cobra.Command) (*output.Output, func(), error) {
	wantedOutput, err := cmd.Flags().GetString(outputTypeFlag)
	if err != nil {
		return nil, func() {}, err
	}
	outFilename, err := cmd.Flags().GetString(outFileFlag)
	if err != nil {
		return nil, func() {}, err
	}

	if outFilename == "" {
		return output.NewOutput(wantedOutput, cmd.OutOrStdout()), func() {}, nil
	}
	f, err := os.OpenFile(outFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, func() {}, err
	}
	return output.NewOutput(wantedOutput, f), func() { _ = f.Close() }, nil
}
