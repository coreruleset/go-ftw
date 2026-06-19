// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"fmt"
	"slices"
)

const (
	// MinParanoiaLevel is the lowest valid CRS paranoia level.
	MinParanoiaLevel = 1
	// MaxParanoiaLevel is the highest valid CRS paranoia level.
	MaxParanoiaLevel = 4
)

// ParanoiaLevels is a sorted, de-duplicated set of CRS paranoia levels. The
// backing slice is unexported and only ever set through NewParanoiaLevels, so
// an instance is guaranteed to stay sorted and unique. Consumers can therefore
// rely on Highest returning the maximum without re-sorting or asserting order.
type ParanoiaLevels struct {
	levels []int
}

// NewParanoiaLevels validates, sorts and de-duplicates the given paranoia levels.
func NewParanoiaLevels(levels ...int) (ParanoiaLevels, error) {
	sorted := make([]int, 0, len(levels))
	for _, level := range levels {
		if level < MinParanoiaLevel || level > MaxParanoiaLevel {
			return ParanoiaLevels{}, fmt.Errorf("paranoia level must be between %d (inclusive) and %d (inclusive)", MinParanoiaLevel, MaxParanoiaLevel)
		}
		sorted = append(sorted, level)
	}
	slices.Sort(sorted)
	return ParanoiaLevels{levels: slices.Compact(sorted)}, nil
}

// Len returns the number of distinct paranoia levels in the set.
func (p ParanoiaLevels) Len() int {
	return len(p.levels)
}

// Highest returns the largest paranoia level in the set, or 0 if the set is empty.
func (p ParanoiaLevels) Highest() int {
	if len(p.levels) == 0 {
		return 0
	}
	return p.levels[len(p.levels)-1]
}

// All returns the sorted paranoia levels as a new slice.
func (p ParanoiaLevels) All() []int {
	return slices.Clone(p.levels)
}
