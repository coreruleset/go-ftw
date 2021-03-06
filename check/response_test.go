package check

import (
	"testing"

	"github.com/fzipi/go-ftw/config"
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

func TestAssertResponseTextErrorOK(t *testing.T) {
	config.ImportFromString(yamlConfig)

	c := NewCheck(config.FTWConfig)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		if !c.AssertResponseContains(e.response) {
			t.Errorf("Failed !")
		}
	}
}

func TestAssertResponseTextFailOK(t *testing.T) {
	config.ImportFromString(yamlConfig)

	c := NewCheck(config.FTWConfig)
	for _, e := range expectedResponseFailTests {
		c.SetExpectResponse(e.expected)
		if c.AssertResponseContains(e.response) {
			t.Errorf("Failed !")
		}
	}
}
