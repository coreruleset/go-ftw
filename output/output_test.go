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
	oType    OutputType
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

		if err := o.Notice(format, testString); err != nil {
			t.Fatalf("Error!")
		}

		if err := o.Err(format, testString); err != nil {
			t.Fatalf("Error!, in test %d val is %s and expected %s", i, testString, test.expected)
		}

		if err := o.Warn(format, testString); err != nil {
			t.Fatalf("Error!, in test %d val is %s and expected %s", i, testString, test.expected)
		}

		// if res := b.String(); strings.Compare(test.expected, res) != 0 {
		// 	t.Fatalf("Test %d failed: %s != %s", i, res, test.expected)
		// }
	}
}
