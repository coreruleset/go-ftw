package check

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

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
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(cfg)
	for _, e := range expectedOKTests {
		c.SetExpectError(e.expected)
		assert.Equal(t, e.expected, c.AssertExpectError(e.err))
	}
}

func TestAssertResponseFail(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlApacheConfig)
	assert.NoError(t, err)

	c := NewCheck(cfg)

	for _, e := range expectedFailTests {
		c.SetExpectError(e.expected)
		assert.False(t, c.AssertExpectError(e.err))
	}
}
