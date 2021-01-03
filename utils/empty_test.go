package utils

import (
	"testing"
)

func TestIsEmpty(t *testing.T) {
	data := ""

	if IsEmpty(data) {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestIsEmptyByte(t *testing.T) {
	data := []byte{}

	if IsEmpty(data) {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestIsNotEmpty(t *testing.T) {
	data := "Not Empty"

	if IsNotEmpty(data) {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestIsNotEmptyByte(t *testing.T) {
	data := []byte("Not Empty")

	if IsNotEmpty(data) {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}
