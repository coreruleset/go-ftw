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

func TestIsEmptyStringPointer(t *testing.T) {
	var empty *string = nil

	if !IsEmpty(empty) {
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

func TestStringPEmpty(t *testing.T) {
	var s *string

	if !IsEmpty(s) {
		t.Errorf("Failed")
	}
}

func TestStringPNotEmpty(t *testing.T) {
	s := string("Empty")

	if !IsNotEmpty(&s) {
		t.Errorf("Failed")
	}
}

func TestAnythingNotEmpty(t *testing.T) {
	data := make([]int, 1, 2)

	if IsEmpty(data) {
		t.Errorf("Failed !")
	}
}

func TestAnythingEmpty(t *testing.T) {
	data := make([]int, 1, 2)

	if IsNotEmpty(data) {
		t.Errorf("Failed !")
	}
}
