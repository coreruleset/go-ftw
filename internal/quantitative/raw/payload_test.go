// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package raw

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
	// Test creating a payload with line number and content
	p := NewPayload(1, "This is a test payload")
	s.Require().Equal(1, p.LineNumber())
	s.Require().Equal("This is a test payload", p.Content())

	// Test creating a payload with different line number
	p2 := NewPayload(42, "Another test payload with special chars: <script>alert('test')</script>")
	s.Require().Equal(42, p2.LineNumber())
	s.Require().Equal("Another test payload with special chars: <script>alert('test')</script>", p2.Content())

	// Test empty content
	p3 := NewPayload(100, "")
	s.Require().Equal(100, p3.LineNumber())
	s.Require().Equal("", p3.Content())
}

func (s *payloadTestSuite) TestPayloadSetters() {
	p := &Payload{}

	// Test setting line number
	p.SetLineNumber(99)
	s.Require().Equal(99, p.LineNumber())

	// Test setting content
	p.SetContent("Modified payload content")
	s.Require().Equal("Modified payload content", p.Content())

	// Test updating both
	p.SetLineNumber(200)
	p.SetContent("Updated again")
	s.Require().Equal(200, p.LineNumber())
	s.Require().Equal("Updated again", p.Content())
}
