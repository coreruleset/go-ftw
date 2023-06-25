package check

import (
	"testing"

	"github.com/coreruleset/go-ftw/utils"

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
	cfg *config.FTWConfiguration
}

func (s *checkStatusTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()
	logName, err := utils.CreateTempFileWithContent(logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(logName)
}

func TestCheckStatusTestSuite(t *testing.T) {
	suite.Run(t, new(checkStatusTestSuite))
}

func (s *checkStatusTestSuite) TestStatusOK() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	for _, expected := range statusOKTests {
		c.SetExpectStatus(expected.expectedStatus)
		s.True(c.AssertStatus(expected.status))
	}
}

func (s *checkStatusTestSuite) TestStatusFail() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	for _, expected := range statusFailTests {
		c.SetExpectStatus(expected.expectedStatus)
		s.False(c.AssertStatus(expected.status))
	}
}

func (s *checkStatusTestSuite) TestStatusCodeRequired() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.SetExpectStatus([]int{200})
	s.True(c.StatusCodeRequired(), "status code should be required")
}
