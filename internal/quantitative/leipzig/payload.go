// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"strconv"
	"strings"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
)

// Payload implements the corpus.Payload interface.
type Payload struct {
	line    int
	payload string
}

// NewPayload returns a new Payload from a line in the corpus.
func NewPayload(line string) corpus.Payload {
	split := strings.Split(line, "\t")
	// convert to int
	num, err := strconv.Atoi(split[0])
	if err != nil {
		num = -1
	}
	p := strings.Join(split[1:], " ")
	return &Payload{
		line:    num,
		payload: p,
	}
}

// LineNumber returns the payload given a line from the Corpus Iterator
// If the line number is not a number, it will return -1
func (p *Payload) LineNumber() int {
	return p.line
}

// SetLineNumber sets the line number of the payload
func (p *Payload) SetLineNumber(line int) {
	p.line = line
}

// Content returns the payload given a line from the Corpus Iterator
func (p *Payload) Content() string {
	return p.payload
}

// SetContent sets the content of the payload
func (p *Payload) SetContent(content string) {
	p.payload = content
}
