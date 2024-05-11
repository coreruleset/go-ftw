// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

// Package waflog encapsulates getting logs from a WAF to compare with expected results
package waflog

import (
	"os"
)

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	logFile             *os.File
	LogMarkerHeaderName []byte
	startMarker         []byte
	endMarker           []byte
	triggeredRules      []uint
	markedLines         [][]byte
}

func (ll *FTWLogLines) StartMarker() []byte {
	return ll.startMarker
}

func (ll *FTWLogLines) EndMarker() []byte {
	return ll.endMarker
}

func (ll *FTWLogLines) reset() {
	ll.startMarker = nil
	ll.endMarker = nil
	ll.triggeredRules = nil
	ll.markedLines = nil
}
