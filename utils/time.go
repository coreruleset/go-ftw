// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package utils

import "time"

// GetFormattedTime returns a time.Time object from the string
func GetFormattedTime(t string) time.Time {
	layout := "2006-01-02T15:04:05.000Z"

	result, _ := time.Parse(layout, t)

	return result
}
