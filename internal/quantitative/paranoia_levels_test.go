// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type paranoiaLevelsTestSuite struct {
	suite.Suite
}

func TestParanoiaLevelsTestSuite(t *testing.T) {
	suite.Run(t, new(paranoiaLevelsTestSuite))
}

func (s *paranoiaLevelsTestSuite) TestNewParanoiaLevels_SortsAndDeduplicates() {
	levels, err := NewParanoiaLevels(3, 1, 3, 2)
	s.Require().NoError(err)
	s.Equal([]int{1, 2, 3}, levels.All())
	s.Equal(3, levels.Highest())
	s.Equal(3, levels.Len())
}

func (s *paranoiaLevelsTestSuite) TestNewParanoiaLevels_RejectsOutOfRange() {
	tests := []struct {
		name   string
		levels []int
	}{
		{name: "below minimum", levels: []int{0}},
		{name: "above maximum", levels: []int{5}},
		{name: "mixed valid and invalid", levels: []int{1, 5}},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			_, err := NewParanoiaLevels(tc.levels...)
			s.Require().Error(err)
		})
	}
}

func (s *paranoiaLevelsTestSuite) TestParanoiaLevels_EmptyZeroValue() {
	var levels ParanoiaLevels
	s.Equal(0, levels.Len())
	s.Equal(MinParanoiaLevel, levels.Highest())
	s.Empty(levels.All())
}

func (s *paranoiaLevelsTestSuite) TestParanoiaLevels_AllReturnsCopy() {
	levels, err := NewParanoiaLevels(1, 2)
	s.Require().NoError(err)

	all := levels.All()
	all[0] = 99

	s.Equal([]int{1, 2}, levels.All(), "mutating the returned slice must not affect the set")
}
