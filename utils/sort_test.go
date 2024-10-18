package utils

import (
	"reflect"
	"testing"
)

// Test function for GetSortedKeys
func TestGetSortedKeys(t *testing.T) {
	// Test case 1: Empty map
	t.Run("Empty map", func(t *testing.T) {
		m := map[int]string{}
		expected := []int{}
		result := GetSortedKeys(m)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	// Test case 2: Single key in map
	t.Run("Single key", func(t *testing.T) {
		m := map[int]string{5: "value"}
		expected := []int{5}
		result := GetSortedKeys(m)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	// Test case 3: Multiple integer keys
	t.Run("Multiple integer keys", func(t *testing.T) {
		m := map[int]string{
			3: "value1",
			1: "value2",
			2: "value3",
		}
		expected := []int{1, 2, 3}
		result := GetSortedKeys(m)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	// Test case 4: String keys
	t.Run("String keys", func(t *testing.T) {
		m := map[string]int{
			"banana": 1,
			"apple":  2,
			"cherry": 3,
		}
		expected := []string{"apple", "banana", "cherry"}
		result := GetSortedKeys(m)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	// Test case 5: Floating-point keys
	t.Run("Float keys", func(t *testing.T) {
		m := map[float64]string{
			1.1: "value1",
			2.5: "value2",
			0.3: "value3",
		}
		expected := []float64{0.3, 1.1, 2.5}
		result := GetSortedKeys(m)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})
}
