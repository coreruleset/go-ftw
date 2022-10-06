package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsEmpty(t *testing.T) {
	data := ""
	assert.True(t, IsEmpty(data))
}

func TestIsEmptyStringPointer(t *testing.T) {
	var empty *string = nil
	assert.True(t, IsEmpty(empty))
}

func TestIsEmptyByte(t *testing.T) {
	data := []byte{}
	assert.True(t, IsEmpty(data))
}

func TestIsNotEmpty(t *testing.T) {
	data := "Not Empty"
	assert.True(t, IsNotEmpty(data))
}

func TestIsNotEmptyByte(t *testing.T) {
	data := []byte("Not Empty")
	assert.True(t, IsNotEmpty(data))
}

func TestStringPEmpty(t *testing.T) {
	var s *string
	assert.True(t, IsEmpty(s))
}

func TestStringPNotEmpty(t *testing.T) {
	s := string("Empty")
	assert.True(t, IsNotEmpty(&s))
}

func TestAnythingNotEmpty(t *testing.T) {
	data := make([]int, 1, 2)
	assert.False(t, IsEmpty(data))
}

func TestAnythingEmpty(t *testing.T) {
	data := make([]int, 1, 2)
	assert.False(t, IsNotEmpty(data), "[]int is not implemented so it should return false")
}
