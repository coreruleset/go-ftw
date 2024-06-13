// Copyright 2023 OWASP ModSecurity Core Rule Set Project
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
