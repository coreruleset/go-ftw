// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
)

type waflogTestSuite struct {
	suite.Suite
}

func TestWafLogTestSuite(t *testing.T) {
	suite.Run(t, new(waflogTestSuite))
}

func (s *waflogTestSuite) TestNewFTWLogLines() {
	cfg := config.NewDefaultConfig()
	s.NotNil(cfg)

	// Don't call NewFTWLogLines to avoid opening the file.
	ll := &FTWLogLines{}
	ll.WithStartMarker([]byte("#"))
	ll.WithEndMarker([]byte("#"))

	s.NotNil(ll.StartMarker, "Failed! StartMarker must be set")
	s.NotNil(ll.EndMarker, "Failed! EndMarker must be set")
	err := ll.Cleanup()
	s.Require().NoError(err)
}
