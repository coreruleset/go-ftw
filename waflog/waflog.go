// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/coreruleset/go-ftw/v2/config"
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

// TruncateLogFile truncates the log file to zero bytes.
// After truncation the file position is reset to the beginning of the file.
// This is useful when only failed test logs need to be kept.
func (ll *FTWLogLines) TruncateLogFile() error {
	if ll == nil || ll.logFile == nil {
		return nil
	}
	if err := ll.logFile.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate log file: %w", err)
	}
	if _, err := ll.logFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start of log file after truncation: %w", err)
	}
	return nil
}

// GetMarkedLines returns the log lines found between the start and end markers.
// Returns nil if either marker has not been set.
func (ll *FTWLogLines) GetMarkedLines() [][]byte {
	if len(ll.startMarker) == 0 || len(ll.endMarker) == 0 {
		return nil
	}
	return ll.getMarkedLines()
}

func (ll *FTWLogLines) openLogFile() error {
	// Using a log file is not required in cloud mode
	if ll.runMode == config.DefaultRunMode {
		if ll.logFilePath != "" && ll.logFile == nil {
			var err error
			// Open with read+write permissions so the file can be truncated after each test
			// when running with --show-failures-only. os.O_CREATE is intentionally omitted:
			// the WAF log file must already exist before go-ftw starts.
			ll.logFile, err = os.OpenFile(ll.logFilePath, os.O_RDWR, 0600)
			return err
		}
	}
	return nil
}
