// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
)

func TestRegexCommandRegistered(t *testing.T) {
	rootCmd := NewRootCommand(internal.NewCommandContext())
	addSubcommands(rootCmd, internal.NewCommandContext())

	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "regex" {
			found = true
			break
		}
	}
	require.True(t, found, "expected 'regex' command to be registered")
}
