package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

type runnerConfigTestSuite struct {
	suite.Suite
}

func TestRunnerConfigTestSuite(t *testing.T) {
	suite.Run(t, new(runnerConfigTestSuite))
}

func (s *baseTestSuite) TestLoadPlatformOverrides() {
	tempDir := s.T().TempDir()
	overridesFile, err := os.CreateTemp(tempDir, "overrides.yaml")
	s.Require().NoError(err)
	defer overridesFile.Close()
	_, err = overridesFile.WriteString(`---
version: "v0.0.0"
meta:
  engine: "coraza"
  platform: "go"
  annotations:
    - purpose: "Test loading overrides"
test_overrides:
  - rule_id: 920100
    test_ids: [4, 8]
    reason: 'Invalid uri, Coraza not reached - 404 page not found'
    output:
      status: 404
      log:
        match_regex: 'match.*me'
        no_expect_ids: [1234]
      response_contains: '404'`)

	s.Require().NoError(err)

	runnerConfig := &RunnerConfig{}
	err = runnerConfig.LoadPlatformOverrides(overridesFile.Name())
	s.Require().NoError(err)

	overrides := runnerConfig.PlatformOverrides
	meta := overrides.Meta
	s.Equal("v0.0.0", overrides.Version)
	s.Equal("coraza", meta.Engine)
	s.Equal("go", meta.Platform)
	s.Len(meta.Annotations, 1)
	value, ok := meta.Annotations["purpose"]
	s.True(ok)
	s.Equal("Test loading overrides", value)

	s.Len(overrides.TestOverrides, 1)
	entry := overrides.TestOverrides[0]
	s.Equal(uint(920100), entry.RuleId)
	s.ElementsMatch([]uint{4, 8}, entry.TestIds)
	s.Equal("Invalid uri, Coraza not reached - 404 page not found", entry.Reason)
	s.Equal(404, entry.Output.Status)
	s.Equal("match.*me", entry.Output.Log.MatchRegex)
	s.Len(entry.Output.Log.NoExpectIds, 1)
	s.Equal(uint(1234), entry.Output.Log.NoExpectIds[0])
	s.Equal("404", entry.Output.ResponseContains)
}
