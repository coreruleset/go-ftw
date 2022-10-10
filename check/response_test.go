package check

import (
	"testing"

	"github.com/stretchr/testify/assert"

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

func TestAssertResponseTextErrorOK(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(config.FTWConfig)
	for _, e := range expectedResponseOKTests {
		c.SetExpectResponse(e.expected)
		assert.Truef(t, c.AssertResponseContains(e.response), "unexpected response: %v", e.response)
	}
}

func TestAssertResponseTextFailOK(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(config.FTWConfig)
	for _, e := range expectedResponseFailTests {
		c.SetExpectResponse(e.expected)
		assert.Falsef(t, c.AssertResponseContains(e.response), "response shouldn't contain text %v", e.response)
	}
}
