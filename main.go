// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package go-ftw is a Framework for Testing Web Application Firewalls
// It is derived from the work made with the pytest plugin `ftw`
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	_ "time/tzdata"

	"github.com/coreruleset/go-ftw/cmd"
)

const (
	ExecutableName = "go-ftw"
)

// These variables will be set by goreleaser through
// `-ldflags="-X '<variable path>=value'"`.
// nolint: gochecknoglobals
var (
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	err := cmd.Execute(
		buildVersion(version, commit, date, builtBy),
	)

	if errors.Is(err, context.DeadlineExceeded) {
		os.Exit(2)
	} else if err != nil {
		os.Exit(1)
	}
}

func buildVersion(version, commit, date, builtBy string) string {
	var result = version
	if commit != "" {
		result = fmt.Sprintf("%s\ncommit: %s", result, commit)
	}
	if date != "" {
		result = fmt.Sprintf("%s\nbuilt at: %s", result, date)
	}
	if builtBy != "" {
		result = fmt.Sprintf("%s\nbuilt by: %s", result, builtBy)
	}
	return result
}
