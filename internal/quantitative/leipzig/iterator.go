// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"bufio"

	"github.com/coreruleset/go-ftw/internal/corpus"
)

// Implements the Iterator interface.
type LeipzigIterator struct {
	scanner *bufio.Scanner
	line    int
}

// HasNext returns true if there is another sentence in the corpus
func (c *LeipzigIterator) HasNext() bool {
	return c.scanner.Scan()
}

// Next returns the next sentence from the corpus
func (c *LeipzigIterator) Next() corpus.Payload {
	p := c.scanner.Text()
	c.line++
	return NewPayload(p)
}
