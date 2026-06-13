// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
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

func writeFakeCRS(t *testing.T, root string) {
	t.Helper()

	err := os.MkdirAll(path.Join(root, "rules"), fs.ModePerm)
	if err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	err = os.WriteFile(path.Join(root, "crs-setup.conf.example"), []byte(crsSetupFileContents), 0644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err = os.WriteFile(path.Join(root, "rules", "Rules1.conf"), []byte(emptyRulesFile), 0644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
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

func (s *quantitativeCmdTestSuite) TestBuildParamsComparisonFlags() {
	fakeBaseline := path.Join(s.T().TempDir(), "baseline.json")
	fakeOtherCRS := s.T().TempDir()

	s.cmd.SetArgs([]string{
		"-C", s.tempDir,
		"--baseline", fakeBaseline,
		"--compare-crs", fakeOtherCRS,
		"-p", "test payload",
	})

	err := s.cmd.ExecuteContext(context.Background())
	s.Require().Error(err, "expected mutual exclusion error for --baseline and --compare-crs")
}

func (s *quantitativeCmdTestSuite) TestBuildParamsComparisonPaths() {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing baseline file",
			args:    []string{"-C", s.tempDir, "--baseline", path.Join(s.T().TempDir(), "missing.json"), "-p", "test payload"},
			wantErr: "--baseline path does not exist",
		},
		{
			name:    "baseline must be file",
			args:    []string{"-C", s.tempDir, "--baseline", s.T().TempDir(), "-p", "test payload"},
			wantErr: "--baseline must point to a file",
		},
		{
			name:    "missing compare crs directory",
			args:    []string{"-C", s.tempDir, "--compare-crs", path.Join(s.T().TempDir(), "missing-crs"), "-p", "test payload"},
			wantErr: "--compare-crs path does not exist",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			cmd := New(internal.NewCommandContext())
			s.Require().NoError(cmd.ParseFlags(tt.args))
			_, err := buildParams(cmd)
			s.Require().Error(err)
			s.Require().Contains(err.Error(), tt.wantErr)
		})
	}
}

func (s *quantitativeCmdTestSuite) TestQuantitativeCommandCompareCRSJSON() {
	compareCRS := path.Join(s.tempDir, "compare-crs")
	writeFakeCRS(s.T(), compareCRS)

	outputFile, err := os.CreateTemp(s.T().TempDir(), "quantitative-*.json")
	s.Require().NoError(err)
	defer func() { _ = outputFile.Close() }()

	s.cmd.SetArgs([]string{
		"-C", s.tempDir,
		"--compare-crs", compareCRS,
		"-p", "test payload",
		"-o", "json",
		"-f", outputFile.Name(),
	})

	s.Require().NoError(s.cmd.ExecuteContext(context.Background()))

	b, err := os.ReadFile(outputFile.Name())
	s.Require().NoError(err)

	var got struct {
		Baseline    map[string]any `json:"baseline"`
		Current     map[string]any `json:"current"`
		Regressions struct {
			Detected bool `json:"detected"`
		} `json:"regressions"`
	}
	s.Require().NoError(json.Unmarshal(b, &got))
	s.Require().NotNil(got.Baseline, "expected baseline results in comparison output")
	s.Require().NotNil(got.Current, "expected current results in comparison output")
	s.Require().False(got.Regressions.Detected, "expected no regressions for identical empty CRS trees")
}

func (s *quantitativeCmdTestSuite) TestQuantitativeCommandSavedBaselineComparisonJSON() {
	baselineFile, err := os.CreateTemp(s.T().TempDir(), "quantitative-baseline-*.json")
	s.Require().NoError(err)
	defer func() { _ = baselineFile.Close() }()

	baselineCmd := New(internal.NewCommandContext())
	baselineCmd.SetArgs([]string{
		"-C", s.tempDir,
		"-p", "test payload",
		"-o", "json",
		"-f", baselineFile.Name(),
	})
	s.Require().NoError(baselineCmd.ExecuteContext(context.Background()))

	comparisonFile, err := os.CreateTemp(s.T().TempDir(), "quantitative-comparison-*.json")
	s.Require().NoError(err)
	defer func() { _ = comparisonFile.Close() }()

	comparisonCmd := New(internal.NewCommandContext())
	comparisonCmd.SetArgs([]string{
		"-C", s.tempDir,
		"--baseline", baselineFile.Name(),
		"-p", "test payload",
		"-o", "json",
		"-f", comparisonFile.Name(),
	})
	s.Require().NoError(comparisonCmd.ExecuteContext(context.Background()))

	b, err := os.ReadFile(comparisonFile.Name())
	s.Require().NoError(err)

	var got struct {
		Baseline    map[string]any `json:"baseline"`
		Current     map[string]any `json:"current"`
		Regressions struct {
			Detected bool `json:"detected"`
		} `json:"regressions"`
	}
	s.Require().NoError(json.Unmarshal(b, &got))
	s.Require().NotNil(got.Baseline, "expected baseline results in comparison output")
	s.Require().NotNil(got.Current, "expected current results in comparison output")
	s.Require().False(got.Regressions.Detected, "expected no regressions for identical saved baseline results")
}
