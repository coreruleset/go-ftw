package output

import (
	"bytes"
	"testing"
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

func TestOutput(t *testing.T) {
	var b bytes.Buffer

	for i, test := range outputTest {
		o := NewOutput(test.oType, &b)

		if err := o.Printf(format, testString); err != nil {
			t.Fatalf("Error! in test %d", i)
		}
	}
}

func TestValidTypes(t *testing.T) {
	vt := ValidTypes()
	for _, test := range outputTest {
		for _, ttype := range vt {
			if test.oType == ttype {
				continue
			}
		}
	}
}
