// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type emptyTestSuite struct {
	suite.Suite
}

func TestEmptyTestSuite(t *testing.T) {
	suite.Run(t, new(emptyTestSuite))
}

func (s *emptyTestSuite) TestIsEmpty() {
	data := ""
	s.True(IsEmpty(data))
}

func (s *emptyTestSuite) TestIsEmptyStringPointer() {
	var empty *string = nil
	s.True(IsEmpty(empty))
}

func (s *emptyTestSuite) TestIsEmptyByte() {
	data := []byte{}
	s.True(IsEmpty(data))
}

func (s *emptyTestSuite) TestIsNotEmpty() {
	data := "Not Empty"
	s.True(IsNotEmpty(data))
}

func (s *emptyTestSuite) TestIsNotEmptyByte() {
	data := []byte("Not Empty")
	s.True(IsNotEmpty(data))
}

func (s *emptyTestSuite) TestStringPEmpty() {
	var str *string
	s.True(IsEmpty(str))
}

func (s *emptyTestSuite) TestStringPNotEmpty() {
	str := string("Empty")
	s.True(IsNotEmpty(&str))
}

func (s *emptyTestSuite) TestAnythingNotEmpty() {
	data := make([]int, 1, 2)
	s.False(IsEmpty(data))
}

func (s *emptyTestSuite) TestAnythingEmpty() {
	data := make([]int, 1, 2)
	s.False(IsNotEmpty(data), "[]int is not implemented so it should return false")
}
