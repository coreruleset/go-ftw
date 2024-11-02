// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"regexp"
)

func MatchSlice(regex *regexp.Regexp, hayStack []string) bool {
	for _, str := range hayStack {
		if regex.MatchString(str) {
			return true
		}
	}

	return false
}
