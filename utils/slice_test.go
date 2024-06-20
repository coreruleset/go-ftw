// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/suite"
)

type sliceTestSuite struct {
	suite.Suite
}

func TestSliceTestSuite(t *testing.T) {
	suite.Run(t, new(sliceTestSuite))
}

func (s *sliceTestSuite) TestMatchSlice() {
	re := regexp.MustCompile("^cookie$")

	s.False(MatchSlice(re, []string{}))
	s.False(MatchSlice(re, []string{""}))
	s.False(MatchSlice(re, []string{"cooke", "php"}))
	s.False(MatchSlice(re, []string{"cookies", "php"}))
	s.True(MatchSlice(re, []string{"cookie", "php"}))
	s.True(MatchSlice(re, []string{"js", "cookie"}))
}
