package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFormattedTime(t *testing.T) {
	ftm := GetFormattedTime("2021-01-05T00:30:26.371Z")

	assert.Equal(t, 2021, ftm.Year())
}
