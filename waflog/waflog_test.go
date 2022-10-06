package waflog

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/config"
)

func TestNewFTWLogLines(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

	ll := NewFTWLogLines()
	// Loop through each option
	for _, opt := range []FTWLogOption{
		WithStartMarker([]byte("#")),
		WithEndMarker([]byte("#")),
		WithLogFile("test"),
	} {
		// Call the option giving the instantiated
		// *House as the argument
		opt(ll)
	}
	assert.NotNil(t, ll.StartMarker, "Failed! StartMarker must be set")
	assert.NotNil(t, ll.EndMarker, "Failed! EndMarker must be set")
	assert.Equal(t, "test", ll.FileName, "Failed! FileName must be set")
	err = ll.Cleanup()
	assert.NoError(t, err)
}
