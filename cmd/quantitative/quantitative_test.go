// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/coreruleset/go-ftw/cmd/internal"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

var crsSetupFileContents = `# CRS Setup Configuration filename`
var emptyRulesFile = `# Empty Rules filename`

type quantitativeCmdTestSuite struct {
	suite.Suite
	tempDir string
	cmd     *cobra.Command
}

func TestQuantitativeTestSuite(t *testing.T) {
	suite.Run(t, new(quantitativeCmdTestSuite))
}

func (s *quantitativeCmdTestSuite) SetupTest() {
	s.cmd = New(internal.NewCommandContext())
	s.tempDir = s.T().TempDir()

	err := os.MkdirAll(path.Join(s.tempDir, "rules"), fs.ModePerm)
	s.Require().NoError(err)
	fakeCrsSetupConf, err := os.Create(path.Join(s.tempDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	n, err := fakeCrsSetupConf.WriteString(crsSetupFileContents)
	s.Require().NoError(err)
	s.Equal(len(crsSetupFileContents), n)
	err = fakeCrsSetupConf.Close()
	s.Require().NoError(err)
	fakeRulesFile, err := os.Create(path.Join(s.tempDir, "rules", "Rules1.conf"))
	s.Require().NoError(err)
	n, err = fakeRulesFile.WriteString(emptyRulesFile)
	s.Require().NoError(err)
	s.Equal(len(emptyRulesFile), n)
}

func (s *quantitativeCmdTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *quantitativeCmdTestSuite) TestQuantitativeCommand() {
	s.cmd.SetArgs([]string{"quantitative", "-C", s.tempDir})
	cmd, err := s.cmd.ExecuteContextC(context.Background())
	s.Require().NoError(err, "quantitative command should not return error")
	s.Equal("quantitative", cmd.Name(), "quantitative command should have the name 'quantitative'")
	s.Require().NoError(err)
}
