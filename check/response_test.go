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
		assert.True(t, c.AssertResponseContains(e.response), "response not expected")
	}
}

func TestAssertResponseTextFailOK(t *testing.T) {
	err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(config.FTWConfig)
	for _, e := range expectedResponseFailTests {
		c.SetExpectResponse(e.expected)
		assert.False(t, c.AssertResponseContains(e.response), "response shouldn't contain text")
	}
}
