// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/test"
)

// NewCheckCmd represents the check command
func NewCheckCommand() *cobra.Command {
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Checks ftw test files for syntax errors.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, _ := cmd.Flags().GetString("dir")
			return checkFiles(dir)

		},
	}
	checkCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	return checkCmd
}

func checkFiles(dir string) error {
	files := fmt.Sprintf("%s/**/*.yaml", dir)
	log.Trace().Msgf("ftw/check: checking files using glob pattern: %s", files)
	tests, err := test.GetTestsFromFiles(files)
	if err == nil {
		fmt.Printf("ftw/check: checked %d files, everything looks good!\n", len(tests))
	}
	return err
}
