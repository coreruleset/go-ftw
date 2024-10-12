// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package updater

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type updaterTestSuite struct {
	suite.Suite
}

func (s *updaterTestSuite) SetupTest() {
}

func (s *updaterTestSuite) TearDownTest() {
}

func TestRunUpdaterTestSuite(t *testing.T) {
	suite.Run(t, new(updaterTestSuite))
}

func (s *updaterTestSuite) TestLatestVersion() {
	latestVersion, err := LatestVersion()
	s.Require().NoError(err)
	s.NotEmpty(latestVersion)
}
