package waflog

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/config"
)

func TestNewFTWLogLines(t *testing.T) {
	cfg := config.NewDefaultConfig()
	assert.NotNil(t, cfg)

	// Don't call NewFTWLogLines to avoid opening the file.
	ll := &FTWLogLines{}
	// Loop through each option
	ll.WithStartMarker([]byte("#"))
	ll.WithEndMarker([]byte("#"))

	assert.NotNil(t, ll.StartMarker, "Failed! StartMarker must be set")
	assert.NotNil(t, ll.EndMarker, "Failed! EndMarker must be set")
	err := ll.Cleanup()
	assert.NoError(t, err)
}
