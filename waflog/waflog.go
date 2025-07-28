// Copyright 2024 OWASP CRS Project
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
func NewFTWLogLines(cfg *config.RunnerConfig) (*FTWLogLines, error) {
	ll := &FTWLogLines{
		logFilePath:         cfg.LogFilePath,
		runMode:             cfg.RunMode,
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}

	if err := ll.openLogFile(); err != nil {
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
	if ll != nil && ll.logFile != nil {
		return ll.logFile.Close()
	}
	return nil
}

func (ll *FTWLogLines) openLogFile() error {
	// Using a log file is not required in cloud mode
	if ll.runMode == config.DefaultRunMode {
		if ll.logFilePath != "" && ll.logFile == nil {
			var err error
			ll.logFile, err = os.Open(ll.logFilePath)
			return err
		}
	}
	return nil
}
