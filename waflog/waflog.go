// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/coreruleset/go-ftw/config"
)

// NewFTWLogLines is the base struct for reading the log file
func NewFTWLogLines(cfg *config.FTWConfiguration) (*FTWLogLines, error) {
	ll := &FTWLogLines{
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}

	if err := ll.openLogFile(cfg); err != nil {
		return nil, fmt.Errorf("cannot open log file: %w", err)
	}

	if cfg.RunMode == config.DefaultRunMode && ll.logFile == nil {
		return nil, errors.New("no log file supplied")
	}

	return ll, nil
}

// WithStartMarker resets the internal state of the log file checker and sets the start marker for the log file
func (ll *FTWLogLines) WithStartMarker(marker []byte) {
	ll.reset()
	ll.startMarker = bytes.ToLower(marker)
}

// WithEndMarker sets the end marker for the log file
func (ll *FTWLogLines) WithEndMarker(marker []byte) {
	ll.endMarker = bytes.ToLower(marker)
}

// Cleanup closes the log file
func (ll *FTWLogLines) Cleanup() error {
	if ll.logFile != nil {
		return ll.logFile.Close()
	}
	return nil
}

func (ll *FTWLogLines) openLogFile(cfg *config.FTWConfiguration) error {
	// Using a log file is not required in cloud mode
	if cfg.RunMode == config.DefaultRunMode {
		if cfg.LogFile != "" && ll.logFile == nil {
			var err error
			ll.logFile, err = os.Open(cfg.LogFile)
			return err
		}
	}
	return nil
}
