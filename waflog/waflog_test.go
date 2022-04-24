package waflog

import (
	"testing"

	"github.com/fzipi/go-ftw/config"
)

func TestNewFTWLogLines(t *testing.T) {
	if err := config.NewConfigFromEnv(); err != nil {
		t.Error(err)
	}

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
	if ll.StartMarker == nil {
		t.Errorf("Failed! StartMarker must be set")
	}
	if ll.EndMarker == nil {
		t.Errorf("Failed! EndMarker must be set")
	}
	if ll.FileName != "test" {
		t.Errorf("Failed! FileName must be set")
	}

	if err := ll.Cleanup(); err != nil {
		t.Error(err)
	}
}
