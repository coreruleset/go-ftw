// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/internal/updater"
)

var logger = log.With().Str("component", "cmd.self_update").Logger()

// NewSelfUpdateCommand represents the self-update command
func NewSelfUpdateCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "self-update",
		Short: "Performs self-update",
		Long: "Checks GitHub releases for the latest version of this command. If a new version is available, " +
			"it will fetch it and replace this binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			effectiveVersion := "v0.0.0-dev"
			currentCmd := cmd
			for currentCmd.HasParent() {
				currentCmd = currentCmd.Parent()
				if currentCmd.Version != "" {
					effectiveVersion = currentCmd.Version
					break
				}
			}
			newVersion, err := updater.Updater(effectiveVersion, "")
			if err != nil {
				return err
			}
			if newVersion != "" {
				logger.Info().Msgf("Updated to version %s", newVersion)
			} else {
				logger.Info().Msg("No updates available")
			}
			return nil
		},
	}
}
