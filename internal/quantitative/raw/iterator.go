// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"bufio"

	"github.com/coreruleset/go-ftw/internal/corpus"
)

// RawIterator implements the Iterator interface for raw corpus files.
// It reads one payload per line and automatically generates line numbers.
type RawIterator struct {
	scanner *bufio.Scanner
	line    int
}

// NewIterator creates a new RawIterator from a scanner
func NewIterator(scanner *bufio.Scanner) corpus.Iterator {
	return &RawIterator{
		scanner: scanner,
		line:    0,
	}
}

// HasNext returns true if there is another line in the corpus
func (r *RawIterator) HasNext() bool {
	return r.scanner.Scan()
}

// Next returns the next payload from the corpus
func (r *RawIterator) Next() corpus.Payload {
	content := r.scanner.Text()
	r.line++
	return NewPayload(r.line, content)
}
