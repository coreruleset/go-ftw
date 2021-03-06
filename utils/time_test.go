package utils

import (
	"testing"
)

func TestGetFormattedTime(t *testing.T) {
	ftm := GetFormattedTime("2021-01-05T00:30:26.371Z")

	if ftm.Year() != 2021 {
		t.Errorf("Error!")
	}
}
