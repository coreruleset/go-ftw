// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var addLicenseVersion = "v1.1.1" // https://github.com/google/addlicense
var golangCILintVer = "v1.53.1"  // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.3.8"     // https://github.com/rinchsan/gosimports/releases/tag/v0.1.5
var goGciVer = "v0.10.1"         // https://github.com/daixiang0/gci/releases/tag/v0.8.2
var goCycloVer = "v0.6.0"        // https://github.com/fzipp/gocyclo/releases/tag/v0.6.0

var errCommitFormatting = errors.New("files not formatted, please commit formatting changes")
var errNoGitDir = errors.New("no .git directory found")

// Format formats code in this repository.
func Format() error {
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	// addlicense strangely logs skipped files to stderr despite not being erroneous, so use the long sh.Exec form to
	// discard stderr too.
	if _, err := sh.Exec(map[string]string{}, io.Discard, io.Discard, "go", "run", fmt.Sprintf("github.com/google/addlicense@%s", addLicenseVersion),
		"-c", "OWASP CRS Project",
		"-s=only",
		"-ignore", "**/*.yml",
		"-ignore", "**/*.yaml",
		"-ignore", "examples/**", "."); err != nil {
		return err
	}
	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer),
		"-w",
		"-local",
		"github.com/coreruleset/go-ftw",
		"."); err != nil {
		return err
	}

	return sh.RunV("go", "run", fmt.Sprintf("github.com/daixiang0/gci@%s", goGciVer),
		"write",
		"--section",
		"standard",
		"--section",
		"default",
		"--section",
		"blank",
		"--section",
		"prefix(github.com/coreruleset/go-ftw)",
		"--custom-order",
		"--skip-generated",
		".")
}

// Lint verifies code quality.
func Lint() error {
	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run"); err != nil {
		return err
	}

	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/fzipp/gocyclo/cmd/gocyclo@%s", goCycloVer), "-over", "15", "."); err != nil {
		return err
	}

	sh.Run("git", "stash", "-k", "-u") // stash unstagged changes so they don't interfere with git diff below
	defer sh.Run("git", "stash", "pop")

	mg.SerialDeps(Format)

	if sh.Run("git", "diff", "--exit-code") != nil {
		return errCommitFormatting
	}

	return nil
}

// Test runs all tests.
func Test() error {
	if err := sh.RunV("go", "test", "-v", "./...", "-race"); err != nil {
		return err
	}

	return nil
}

// Coverage runs tests with coverage and race detector enabled.
func Coverage() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-v", "-race", "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}

	return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")
}

// Doc runs godoc, access at http://localhost:6060
func Doc() error {
	return sh.RunV("go", "run", "golang.org/x/tools/cmd/godoc@latest", "-http=:6060")
}

// Precommit installs a git hook to run check when committing
func Precommit() error {
	if _, err := os.Stat(filepath.Join(".git", "hooks")); os.IsNotExist(err) {
		return errNoGitDir
	}

	f, err := os.ReadFile(".pre-commit.hook")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(".git", "hooks", "pre-commit"), f, 0755)
}

// Check runs lint and tests.
func Check() {
	mg.SerialDeps(Lint, Test)
}
