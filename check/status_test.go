package check

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
)

var statusOKTests = []struct {
	status         int
	expectedStatus []int
}{
	{400, []int{0, 100, 200, 400}},
	{400, []int{400}},
}

var statusFailTests = []struct {
	status         int
	expectedStatus []int
}{
	{400, []int{0, 100, 200}},
	{200, []int{400}},
	{200, []int{0}},
}

type checkStatusTestSuite struct {
	suite.Suite
}

func TestCheckStatusTestSuite(t *testing.T) {
	suite.Run(t, new(checkStatusTestSuite))
}

func (s *checkStatusTestSuite) TestStatusOK() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)

	for _, expected := range statusOKTests {
		c.SetExpectStatus(expected.expectedStatus)
		s.True(c.AssertStatus(expected.status))
	}
}

func (s *checkStatusTestSuite) TestStatusFail() {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	s.NoError(err)

	c := NewCheck(cfg)

	for _, expected := range statusFailTests {
		c.SetExpectStatus(expected.expectedStatus)
		s.False(c.AssertStatus(expected.status))
	}
}
