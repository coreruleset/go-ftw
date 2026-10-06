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
		{in: "", want: Placement{Kind: PlacementArgs}},
		{in: "args", want: Placement{Kind: PlacementArgs}},
		{in: "path", want: Placement{Kind: PlacementPath}},
		{in: "header:Referer", want: Placement{Kind: PlacementHeader, Header: "Referer"}},
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

func TestRequestHeaders(t *testing.T) {
	// a header placement replaces a fixed header of the same name, case-insensitively
	got := requestHeaders(Placement{Kind: PlacementHeader, Header: "user-agent"}, "payload")
	var uas []string
	for _, h := range got {
		if h[0] == "user-agent" || h[0] == "User-Agent" {
			uas = append(uas, h[1])
		}
	}
	require.Equal(t, []string{"payload"}, uas)

	// a non-colliding header is appended after the fixed ones
	got = requestHeaders(Placement{Kind: PlacementHeader, Header: "Referer"}, "payload")
	require.Len(t, got, 4)
	require.Equal(t, [2]string{"Referer", "payload"}, got[3])

	// args and path placements only send the fixed headers
	require.Len(t, requestHeaders(Placement{Kind: PlacementArgs}, "payload"), 3)
}
