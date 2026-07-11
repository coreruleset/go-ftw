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

var (
	crsSetupFileContents = `# CRS Setup Configuration filename`
	emptyRulesFile       = `# Empty Rules filename`
)

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
	err = os.WriteFile(path.Join(root, "crs-setup.conf.example"), []byte(crsSetupFileContents), 0o644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err = os.WriteFile(path.Join(root, "rules", "Rules1.conf"), []byte(emptyRulesFile), 0o644)
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
		name                      string
		args                      []string
		wantErr                   bool
		wantOrderedParanoiaLevels []int
	}{
		{
			name:                      "rule without PL defaults to PL4",
			args:                      []string{"-C", s.tempDir, "-r", "942200", "-p", "test payload"},
			wantOrderedParanoiaLevels: []int{maxCrsParanoiaLevel},
		},
		{
			name:                      "rule with explicit PL is allowed",
			args:                      []string{"-C", s.tempDir, "-r", "942200", "-P", "2", "-p", "test payload"},
			wantOrderedParanoiaLevels: []int{2},
		},
		{
			name:                      "multi PLs are normalized and use highest PL to run",
			args:                      []string{"-C", s.tempDir, "--paranoia-levels", "3,1,3,2", "-p", "test payload"},
			wantOrderedParanoiaLevels: []int{1, 2, 3},
		},
		{
			name:                      "all paranoia levels expands to all CRS levels",
			args:                      []string{"-C", s.tempDir, "--all-paranoia-levels", "-p", "test payload"},
			wantOrderedParanoiaLevels: []int{1, 2, 3, 4},
		},
		{
			name:    "PL out of range errors",
			args:    []string{"-C", s.tempDir, "-P", "5", "-p", "test payload"},
			wantErr: true,
		},
		{
			name:    "multi PL out of range errors",
			args:    []string{"-C", s.tempDir, "--paranoia-levels", "1,5", "-p", "test payload"},
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
			s.Equal(tc.wantOrderedParanoiaLevels, params.ParanoiaLevels.All())
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

func (s *quantitativeCmdTestSuite) TestQuantitativeCommandParanoiaLevelFlagConflicts() {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "single and multi PL flags conflict",
			args: []string{"-C", s.tempDir, "-P", "2", "--paranoia-levels", "1,2", "-p", "test payload"},
		},
		{
			name: "all and multi PL flags conflict",
			args: []string{"-C", s.tempDir, "--all-paranoia-levels", "--paranoia-levels", "1,2", "-p", "test payload"},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			cmd := New(internal.NewCommandContext())
			cmd.SetArgs(tc.args)
			err := cmd.ExecuteContext(context.Background())
			s.Require().Error(err, "expected mutually exclusive paranoia level flag error")
		})
	}
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesFileFlag() {
	// Write a file with two rule IDs (and a comment and blank line)
	rulesFile := path.Join(s.tempDir, "ignore-rules.txt")
	content := "# comment\n920272\n920273\n\n942432\n"
	s.Require().NoError(os.WriteFile(rulesFile, []byte(content), 0o644))

	cmd := New(internal.NewCommandContext())
	s.Require().NoError(cmd.ParseFlags([]string{"-C", s.tempDir, "--ignore-rules-file", rulesFile}))
	params, err := buildParams(cmd)
	s.Require().NoError(err)
	s.Equal([]int{920272, 920273, 942432}, params.IgnoreRules)
}

func (s *quantitativeCmdTestSuite) TestIgnoreRulesFileFlag_MergesWithFlag() {
	// Write a file with one rule ID
	rulesFile := path.Join(s.tempDir, "ignore-rules.txt")
	s.Require().NoError(os.WriteFile(rulesFile, []byte("942432\n"), 0o644))

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
