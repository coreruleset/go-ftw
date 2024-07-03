// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package updater

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/creativeprojects/go-selfupdate"
	"github.com/rs/zerolog/log"
)

var logger = log.With().Str("component", "updater").Logger()

// getLatestVersionFromGitHub checks the latest version on GitHub and returns it.
func getLatestVersionFromGitHub() (*selfupdate.Release, error) {
	source, err := selfupdate.NewGitHubSource(selfupdate.GitHubConfig{})
	if err != nil {
		logger.Fatal().Err(err)
	}
	updater, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:    source,
		Validator: &selfupdate.ChecksumValidator{UniqueFilename: "crs-toolchain-checksums.txt"}, // checksum from goreleaser
	})
	if err != nil {
		return nil, err
	}
	latest, found, err := updater.DetectLatest(context.Background(), selfupdate.ParseSlug("coreruleset/crs-toolchain"))
	if err != nil {
		return latest, fmt.Errorf("error occurred while detecting version: %w", err)
	}
	if !found {
		return latest, fmt.Errorf("latest version for %s/%s could not be found on GitHub repository", runtime.GOOS, runtime.GOARCH)
	}
	return latest, nil
}

// LatestVersion checks the latest version on GitHub and returns it.
func LatestVersion() (string, error) {
	latest, err := getLatestVersionFromGitHub()
	if err != nil {
		return "", err
	}
	return latest.Version(), nil
}

// Updater checks the latest version on GitHub and self-updates if there is a newer release.
// Returns the version string of the updated release, or an error if something went wrong.
func Updater(version string, executablePath string) (string, error) {
	emptyVersion := ""
	latest, err := getLatestVersionFromGitHub()
	if err != nil {
		return emptyVersion, err
	}

	if latest.LessOrEqual(version) {
		logger.Info().Msgf("You have the latest version installed, %s", version)
		return version, nil
	}
	logger.Info().Msgf("Your version is %s.", version)
	// passing executablePath allows to test the updater without actually updating the binary
	if executablePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return emptyVersion, fmt.Errorf("could not locate executable path: %w", err)
		}
		executablePath = exe
		logger.Info().Msgf("Updating file \"%s\"", executablePath)
	}

	if err := selfupdate.UpdateTo(context.Background(), latest.AssetURL, latest.AssetName, executablePath); err != nil {
		return emptyVersion, fmt.Errorf("error occurred while updating binary: %w", err)
	}
	logger.Info().Msgf("Successfully updated to version %s", latest.Version())
	return latest.Version(), nil
}
