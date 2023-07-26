// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type rootCmdTestSuite struct {
	suite.Suite
}

func TestRootChoreTestSuite(t *testing.T) {
	suite.Run(t, new(rootCmdTestSuite))
}

func (s *rootCmdTestSuite) TestRootCommand() {
	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"help"})
	err := Execute("v1.0.0")
	s.Require().NoError(err)
}
