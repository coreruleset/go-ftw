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

func TestBuildParamsComparisonFlags(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	err := os.MkdirAll(path.Join(tempDir, "rules"), fs.ModePerm)
	if err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	err = os.WriteFile(path.Join(tempDir, "crs-setup.conf.example"), []byte(crsSetupFileContents), 0644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err = os.WriteFile(path.Join(tempDir, "rules", "Rules1.conf"), []byte(emptyRulesFile), 0644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cmd := New(internal.NewCommandContext())
	cmd.SetArgs([]string{
		"-C", tempDir,
		"--baseline", "/tmp/baseline.json",
		"--compare-crs", "/tmp/other-crs",
		"-p", "test payload",
	})

	err = cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected mutual exclusion error for --baseline and --compare-crs")
	}
}

func TestQuantitativeCommandBaselineComparisonJSON(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	for _, root := range []string{tempDir, path.Join(tempDir, "baseline-crs")} {
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

	cmd := New(internal.NewCommandContext())
	args := []string{
		"-C", tempDir,
		"--compare-crs", path.Join(tempDir, "baseline-crs"),
		"-p", "test payload",
		"-o", "json",
	}

	outputFile, err := os.CreateTemp(t.TempDir(), "quantitative-*.json")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer func() { _ = outputFile.Close() }()

	cmd.SetArgs(append(args, "-f", outputFile.Name()))

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext() error = %v", err)
	}

	b, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var got struct {
		Baseline    map[string]any `json:"baseline"`
		Current     map[string]any `json:"current"`
		Regressions struct {
			Detected bool `json:"detected"`
		} `json:"regressions"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Baseline == nil || got.Current == nil {
		t.Fatal("expected both baseline and current results in comparison output")
	}
	if got.Regressions.Detected {
		t.Fatal("expected no regressions for identical empty CRS trees")
	}
}
