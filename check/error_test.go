package check

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
)

var expectedOKTests = []struct {
	err      error
	expected bool
}{
	{nil, false},
	{errors.New("a"), true},
}

var expectedFailTests = []struct {
	err      error
	expected bool
}{
	{nil, true},
	{errors.New("a"), false},
}

type checkErrorTestSuite struct {
	suite.Suite
}

func TestCheckErrorTestSuite(t *testing.T) {
	suite.Run(t, new(checkErrorTestSuite))
}

func (s *checkErrorTestSuite) TestAssertResponseErrorOK() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)
	for _, e := range expectedOKTests {
		c.SetExpectError(e.expected)
		s.Equal(e.expected, c.AssertExpectError(e.err))
	}
}

func (s *checkErrorTestSuite) TestAssertResponseFail() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)

	for _, e := range expectedFailTests {
		c.SetExpectError(e.expected)
		s.False(c.AssertExpectError(e.err))
	}
}
