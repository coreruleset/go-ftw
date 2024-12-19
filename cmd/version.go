// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/internal/updater"
)

func NewVersionCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version number of go-ftw",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("go-ftw", version)
			// do not run when in CI (e.g. GitHub Actions)
			if os.Getenv("CI") != "true" {
				latest, err := updater.LatestVersion()
				if err != nil {
					log.Error().Err(err).Msg("Failed to check for updates")
				} else if latest != "" {
					fmt.Println("Latest version is:", latest)
					fmt.Println("Run 'go-ftw self-update' to update")
				}
			}
		},
	}
}
