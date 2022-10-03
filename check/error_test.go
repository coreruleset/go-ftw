package check

import (
	"errors"
	"testing"

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

func TestAssertResponseErrorOK(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)

	if err != nil {
		t.Errorf("Failed!")
	}
	c := NewCheck(config.FTWConfig)
	for _, e := range expectedOKTests {
		c.SetExpectError(e.expected)
		if c.AssertExpectError(e.err) != e.expected {
			t.Errorf("Failed !")
		}
	}
}

func TestAssertResponseFail(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)

	if err != nil {
		t.Errorf("Failed!")
	}

	c := NewCheck(config.FTWConfig)

	for _, e := range expectedFailTests {
		c.SetExpectError(e.expected)
		if c.AssertExpectError(e.err) && e.expected {
			t.Errorf("Failed !")
		}
	}
}
