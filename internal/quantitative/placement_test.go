// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePlacement(t *testing.T) {
	tests := []struct {
		in      string
		want    Placement
		wantErr bool
	}{
		{in: "", want: Placement{Kind: "args"}},
		{in: "args", want: Placement{Kind: "args"}},
		{in: "path", want: Placement{Kind: "path"}},
		{in: "header:Referer", want: Placement{Kind: "header", Header: "Referer"}},
		{in: "header:", wantErr: true},
		{in: "header", wantErr: true},
		{in: "body", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParsePlacement(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
