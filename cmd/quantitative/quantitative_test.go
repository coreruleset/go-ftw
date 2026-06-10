// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
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
	err = fakeRulesFile.Close()
	s.Require().NoError(err)
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

func (s *quantitativeCmdTestSuite) TestQuantitativeCommandRuleAndParanoiaLevel() {
	tests := []struct {
		name              string
		args              []string
		wantErr           bool
		wantParanoiaLevel int
	}{
		{
			name:              "rule without PL defaults to PL4",
			args:              []string{"-C", s.tempDir, "-r", "942200", "-p", "test payload"},
			wantParanoiaLevel: maxCrsParanoiaLevel,
		},
		{
			name:              "rule with explicit PL is allowed",
			args:              []string{"-C", s.tempDir, "-r", "942200", "-P", "2", "-p", "test payload"},
			wantParanoiaLevel: 2,
		},
		{
			name:    "PL out of range errors",
			args:    []string{"-C", s.tempDir, "-P", "5", "-p", "test payload"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			cmd := New(internal.NewCommandContext())
			s.Require().NoError(cmd.ParseFlags(tc.args))
			params, err := buildParams(cmd)
			if tc.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.wantParanoiaLevel, params.ParanoiaLevel)
		})
	}
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesFlag() {
	tests := []struct {
		name            string
		args            []string
		wantErr         bool
		wantIgnoreRules []int
	}{
		{
			name:            "no ignore-rules flag",
			args:            []string{"-C", s.tempDir},
			wantIgnoreRules: []int{},
		},
		{
			name:            "single rule",
			args:            []string{"-C", s.tempDir, "--ignore-rules", "920272"},
			wantIgnoreRules: []int{920272},
		},
		{
			name:            "comma-separated rules",
			args:            []string{"-C", s.tempDir, "--ignore-rules", "920272,920273,942432"},
			wantIgnoreRules: []int{920272, 920273, 942432},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			cmd := New(internal.NewCommandContext())
			s.Require().NoError(cmd.ParseFlags(tc.args))
			params, err := buildParams(cmd)
			if tc.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.wantIgnoreRules, params.IgnoreRules)
		})
	}
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesFileFlag() {
	// Write a file with two rule IDs (and a comment and blank line)
	rulesFile := path.Join(s.tempDir, "ignore-rules.txt")
	content := "# comment\n920272\n920273\n\n942432\n"
	s.Require().NoError(os.WriteFile(rulesFile, []byte(content), 0644))

	cmd := New(internal.NewCommandContext())
	s.Require().NoError(cmd.ParseFlags([]string{"-C", s.tempDir, "--ignore-rules-file", rulesFile}))
	params, err := buildParams(cmd)
	s.Require().NoError(err)
	s.Equal([]int{920272, 920273, 942432}, params.IgnoreRules)
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesFileFlag_MergesWithFlag() {
	// Write a file with one rule ID
	rulesFile := path.Join(s.tempDir, "ignore-rules.txt")
	s.Require().NoError(os.WriteFile(rulesFile, []byte("942432\n"), 0644))

	cmd := New(internal.NewCommandContext())
	s.Require().NoError(cmd.ParseFlags([]string{"-C", s.tempDir, "--ignore-rules", "920272", "--ignore-rules-file", rulesFile}))
	params, err := buildParams(cmd)
	s.Require().NoError(err)
	s.Equal([]int{920272, 942432}, params.IgnoreRules)
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesFileFlag_InvalidFile() {
	cmd := New(internal.NewCommandContext())
	s.Require().NoError(cmd.ParseFlags([]string{"-C", s.tempDir, "--ignore-rules-file", "/nonexistent/path.txt"}))
	_, err := buildParams(cmd)
	s.Require().Error(err)
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesCommand() {
	s.cmd.SetArgs([]string{"quantitative", "-C", s.tempDir, "--ignore-rules", "920272,920273", "-p", "test payload"})
	cmd, err := s.cmd.ExecuteContextC(context.Background())
	s.Require().NoError(err, "quantitative command with --ignore-rules should not return error")
	s.Equal("quantitative", cmd.Name())
}
