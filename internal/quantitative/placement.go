// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"fmt"
	"strings"
)

// Placement says where CrsCall puts the payload in the generated request.
// Kind is one of "args" (query string, the default), "path" (URL path segment)
// or "header" (value of the request header named by Header).
type Placement struct {
	Kind   string
	Header string
}

// ParsePlacement parses the --placement flag value: "args", "path" or "header:<Name>".
// An empty string means "args".
func ParsePlacement(s string) (Placement, error) {
	switch {
	case s == "" || s == "args":
		return Placement{Kind: "args"}, nil
	case s == "path":
		return Placement{Kind: "path"}, nil
	case strings.HasPrefix(s, "header:") && len(s) > len("header:"):
		return Placement{Kind: "header", Header: s[len("header:"):]}, nil
	}
	return Placement{}, fmt.Errorf("invalid placement %q: want args, path or header:<Name>", s)
}

func (p Placement) String() string {
	if p.Kind == "header" {
		return "header:" + p.Header
	}
	if p.Kind == "" {
		return "args"
	}
	return p.Kind
}
