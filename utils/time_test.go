// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type timeTestSuite struct {
	suite.Suite
}

func TestTimeTestSuite(t *testing.T) {
	suite.Run(t, new(timeTestSuite))
}

func (s *timeTestSuite) TestGetFormattedTime() {
	ftm := GetFormattedTime("2021-01-05T00:30:26.371Z")

	s.Equal(2021, ftm.Year())
}
