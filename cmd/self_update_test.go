// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"runtime"
	"testing"

	"github.com/coreruleset/go-ftw/internal/updater"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type selfUpdateTestSuite struct {
	suite.Suite
	tempDir        string
	executablePath string
}

func (s *selfUpdateTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *selfUpdateTestSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "self-update-tests")
	s.Require().NoError(err)

	s.executablePath = path.Join(s.tempDir, "ftw")
	err = os.WriteFile(s.executablePath, []byte("Fake Binary"), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *selfUpdateTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

// Do not run test suite until there is a new release with the "version" command
func TestRunSelfUpdateTestSuite(t *testing.T) {
	suite.Run(t, new(selfUpdateTestSuite))
}

func (s *selfUpdateTestSuite) TestSelfUpdateDev() {
	_, err := updater.Updater("v0.0.0-dev", s.executablePath)
	s.Require().NoError(err)
}

func (s *selfUpdateTestSuite) TestSelfUpdateBigVersion() {
	newVersion, err := updater.Updater("v10000.1.1", s.executablePath)
	s.Require().NoError(err)
	s.Equal("v10000.1.1", newVersion)
}

func (s *selfUpdateTestSuite) TestSelfUpdateWithExecutablePath() {
	if runtime.GOOS == "windows" {
		// Using exec on Windows isn't fun
		s.T().SkipNow()
	}

	newVersion, err := updater.Updater("v1.1.2", s.executablePath)
	s.Require().NoError(err)
	s.NotEmpty(newVersion)

	s.FileExists(s.executablePath, "The executable should exist")
	contents, err := os.ReadFile(s.executablePath)
	s.Require().NoError(err)
	s.NotContains(string(contents), "Fake Binary", "The executable should be replaced")

	var out, stderr bytes.Buffer

	cmd := exec.Command(s.executablePath, "version")
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		versionString := fmt.Sprintf("ftw %s", newVersion)
		s.Contains(out.String(), versionString)
	} else {
		s.Equal("exit status 1", err.Error())
		oldBinaryWithUnsupportedVersionFlagError := "Error: unknown command \"version\" for \"go-ftw\"\nRun 'go-ftw --help' for usage.\n"
		s.Equal(oldBinaryWithUnsupportedVersionFlagError, stderr.String())
	}
}
