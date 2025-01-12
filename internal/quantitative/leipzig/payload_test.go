// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type payloadTestSuite struct {
	suite.Suite
}

func (s *payloadTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestPayloadTestSuite(t *testing.T) {
	suite.Run(t, new(payloadTestSuite))
}

func (s *payloadTestSuite) TestNewPayload() {
	line := "1\t$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna."
	p := NewPayload(line)
	s.Require().Equal(1, p.LineNumber())
	s.Require().Equal("$156,834 for The Pathway to Excellence in Practice program through Neighborhood Place of Puna.", p.Content())
	line2 := "2000\tThis is an additional payload"
	p2 := NewPayload(line2)
	s.Require().Equal(2000, p2.LineNumber())
	s.Require().Equal("This is an additional payload", p2.Content())
}

func (s *payloadTestSuite) TestPayloadSetters() {
	p := &Payload{}
	p.SetLineNumber(1)
	s.Require().Equal(1, p.LineNumber())
	p.SetContent("test")
	s.Require().Equal("test", p.Content())
}
