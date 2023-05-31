package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"
)

var testString = "test"

var format = `This is the %s`

// TODO:
// GitHub
// GitLab
// CodeBuild
// CircleCI
// Jenkins
var outputTest = []struct {
	oType    string
	expected string
}{
	{"quiet", ""},
	{"github", "This is the test"},
	{"normal", "⚠️ with emoji: This is the test"},
	{"json", `{"level":"notice","message":"This is the test"}`},
}

type outputTestSuite struct {
	suite.Suite
}

func TestOutputTestSuite(t *testing.T) {
	suite.Run(t, new(outputTestSuite))
}

func (s *outputTestSuite) TestOutput() {
	var b bytes.Buffer

	for i, test := range outputTest {
		o := NewOutput(test.oType, &b)

		err := o.Printf(format, testString)
		s.NoError(err, "Error! in test %d", i)
	}
}

func (s *outputTestSuite) TestNormalCatalogOutput() {
	var b bytes.Buffer

	normal := NewOutput("normal", &b)
	for _, v := range normalCatalog {
		normal.RawPrint(v)
		s.Equal(b.String(), v, "output is not equal")
		// reset buffer
		b.Reset()
	}
}

func (s *outputTestSuite) TestPlainCatalogOutput() {
	var b bytes.Buffer

	normal := NewOutput("normal", &b)
	for _, v := range createPlainCatalog(normalCatalog) {
		normal.RawPrint(v)
		s.Equal(b.String(), v, "output is not equal")
		// reset buffer
		b.Reset()
	}
}
