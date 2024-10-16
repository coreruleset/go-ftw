// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/internal/updater"
)

// NewSelfUpdateCommand represents the self-update command
func NewSelfUpdateCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "self-update",
		Short: "Performs self-update",
		Long: "Checks GitHub releases for the latest version of this command. If a new version is available, " +
			"it will fetch it and replace this binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if version == "dev" {
				log.Info().Msg("You are running a development version, skipping self-update")
				return nil
			}
			newVersion, err := updater.Updater(version, "")
			if err != nil {
				return err
			}
			if newVersion != "" {
				log.Info().Msgf("Updated to version %s", newVersion)
			} else {
				log.Info().Msg("No updates available")
			}
			return nil
		},
	}
}
