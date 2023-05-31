package check

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
)

var expectedResponseOKTests = []struct {
	response string
	expected string
}{
	{`<html><title></title><body></body></html>`, "title"},
}

var expectedResponseFailTests = []struct {
	response string
	expected string
}{
	{`<html><title></title><body></body></html>`, "not found"},
}

type checkResponseTestSuite struct {
	suite.Suite
}

func TestCheckResponseTestSuite(t *testing.T) {
	suite.Run(t, new(checkResponseTestSuite))
}

func (s *checkResponseTestSuite) TestAssertResponseTextErrorOK() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		s.Truef(c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextFailOK() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)
	for _, e := range expectedResponseFailTests {
		c.SetExpectResponse(e.expected)
		s.Falsef(c.AssertResponseContains(e.response), "response shouldn't contain text %v", e.response)
	}
}

func (s *checkResponseTestSuite) TestAssertResponseTextChecksFullResponseOK() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		s.Truef(c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}
