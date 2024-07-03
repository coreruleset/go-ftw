// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/internal/updater"
)

// selfUpdateCmd represents the self-update command
var selfUpdateCmd = createSelfUpdateCommand()

func init() {
	buildSelfUpdateCommand()
}

func createSelfUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "self-update",
		Short: "Performs self-update",
		Long: "Checks GitHub releases for the latest version of this command. If a new version is available, " +
			"it will get it and replace this binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			version := "dev"
			if rootCmd.Version != "" {
				version = rootCmd.Version
			}
			newVersion, err := updater.Updater(version, "")
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

func buildSelfUpdateCommand() {
	rootCmd.AddCommand(selfUpdateCmd)
}

func rebuildSelfUpdateCommand() {
	if selfUpdateCmd != nil {
		selfUpdateCmd.Parent().RemoveCommand(selfUpdateCmd)
	}

	selfUpdateCmd = createSelfUpdateCommand()
	buildSelfUpdateCommand()
}
