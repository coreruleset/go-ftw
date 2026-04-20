// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package waflog encapsulates getting logs from a WAF to compare with expected results
package waflog

import (
	"os"
	"regexp"
	"slices"

	"github.com/coreruleset/go-ftw/v2/config"
)

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	logFilePath               string
	logFile                   *os.File
	LogMarkerHeaderName       []byte
	startMarker               []byte
	endMarker                 []byte
	triggeredRules            []uint
	markedLines               [][]byte
	markedLinesInitialized    bool
	triggeredRulesInitialized bool
	runMode                   config.RunMode
	stdLogIdRegex             *regexp.Regexp
	jsonLogIdRegex            *regexp.Regexp
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
	ll.triggeredRules = slices.Delete(ll.triggeredRules, 0, len(ll.triggeredRules))
	ll.markedLines = slices.Delete(ll.markedLines, 0, len(ll.markedLines))
	ll.markedLinesInitialized = false
	ll.triggeredRulesInitialized = false
	if ll.stdLogIdRegex == nil {
		ll.stdLogIdRegex = regexp.MustCompile(config.DefaultStdLogIdRegex)
	}
	if ll.jsonLogIdRegex == nil {
		ll.jsonLogIdRegex = regexp.MustCompile(config.DefaultJsonLogIdRegex)
	}
}
