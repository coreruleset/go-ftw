package output

import (
	"bytes"
	"testing"
)

var testString string = "test"

var format string = `This is the %s`

// TODO:
// GitHub
// GitLab
// CodeBuild
// CircleCI
// Jenkins
var outputTest = []struct {
	oType    Type
	expected string
}{
	{Quiet, ""},
	{GitHub, "This is the test"},
	{Normal, "⚠️ with emoji: This is the test"},
	{JSON, `{"level":"notice","message":"This is the test"}`},
}

func TestOutput(t *testing.T) {
	var b bytes.Buffer

	for i, test := range outputTest {
		o := NewOutput(test.oType, &b)

		if err := o.Printf(format, testString); err != nil {
			t.Fatalf("Error! in test %d", i)
		}
	}
}
