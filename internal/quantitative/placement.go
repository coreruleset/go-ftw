// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"fmt"
	"strings"
)

// PlacementKind names where CrsCall puts the payload in the generated request.
type PlacementKind string

const (
	// PlacementArgs puts the payload in the query string (the default).
	PlacementArgs PlacementKind = "args"
	// PlacementPath puts the payload in a URL path segment.
	PlacementPath PlacementKind = "path"
	// PlacementHeader puts the payload in the request header named by Placement.Header.
	PlacementHeader PlacementKind = "header"
)

// Placement says where CrsCall puts the payload in the generated request.
type Placement struct {
	Kind   PlacementKind
	Header string
}

// ParsePlacement parses the --placement flag value: "args", "path" or "header:<Name>".
// An empty string means "args".
func ParsePlacement(s string) (Placement, error) {
	switch {
	case s == "" || s == string(PlacementArgs):
		return Placement{Kind: PlacementArgs}, nil
	case s == string(PlacementPath):
		return Placement{Kind: PlacementPath}, nil
	case strings.HasPrefix(s, "header:") && len(s) > len("header:"):
		return Placement{Kind: PlacementHeader, Header: s[len("header:"):]}, nil
	}
	return Placement{}, fmt.Errorf("invalid placement %q: want args, path or header:<Name>", s)
}

// String renders the placement in the same form ParsePlacement accepts.
func (p Placement) String() string {
	if p.Kind == PlacementHeader {
		return "header:" + p.Header
	}
	if p.Kind == "" {
		return string(PlacementArgs)
	}
	return string(p.Kind)
}

// fixedHeaders are sent with every request so CRS sees a plausible browser client.
var fixedHeaders = [][2]string{
	{"Host", "localhost"},
	{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75. 0.3770.100 Safari/537.36"},
	{"Accept", "*/*"},
}

// requestHeaders returns the headers to send for a payload. Coraza appends on
// AddRequestHeader, so a header placement drops the fixed header of the same
// name instead of relying on call order.
func requestHeaders(p Placement, payload string) [][2]string {
	headers := make([][2]string, 0, len(fixedHeaders)+1)
	for _, h := range fixedHeaders {
		if p.Kind == PlacementHeader && strings.EqualFold(h[0], p.Header) {
			continue
		}
		headers = append(headers, h)
	}
	if p.Kind == PlacementHeader {
		headers = append(headers, [2]string{p.Header, payload})
	}
	return headers
}
