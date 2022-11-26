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

func TestNormalCatalogOutput(t *testing.T) {
	var b bytes.Buffer

	normal := NewOutput("normal", &b)
	for _, v := range normalCatalog {
		normal.RawPrint(v)
		if b.String() != v {
			t.Error("output is not equal")
		}
		// reset buffer
		b.Reset()
	}
}

func TestPlainCatalogOutput(t *testing.T) {
	var b bytes.Buffer

	normal := NewOutput("normal", &b)
	for _, v := range createPlainCatalog(normalCatalog) {
		normal.RawPrint(v)
		if b.String() != v {
			t.Error("plain output is not equal")
		}
		// reset buffer
		b.Reset()
	}
}
