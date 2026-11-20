// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regex

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
)

// New returns the `regex` parent command and registers its subcommands.
func New(cmdContext *internal.CommandContext) *cobra.Command {
	regexCmd := &cobra.Command{
		Use:   "regex",
		Short: "Tools for working with CRS regular expressions",
		Long:  "Tools for working with OWASP CRS regular expressions, such as performance benchmarking.",
	}
	regexCmd.AddCommand(newPerfCommand(cmdContext))
	return regexCmd
}
