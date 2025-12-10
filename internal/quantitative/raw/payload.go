// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"github.com/coreruleset/go-ftw/v2/internal/corpus"
)

// Payload implements the corpus.Payload interface for raw corpus files.
// Raw corpus files contain one payload per line without line numbers.
type Payload struct {
	line    int
	payload string
}

// NewPayload returns a new Payload from a line in the raw corpus.
// Since raw corpus files don't include line numbers, the line number
// must be provided separately.
func NewPayload(line int, content string) corpus.Payload {
	return &Payload{
		line:    line,
		payload: content,
	}
}

// LineNumber returns the line number of the payload
func (p *Payload) LineNumber() int {
	return p.line
}

// SetLineNumber sets the line number of the payload
func (p *Payload) SetLineNumber(line int) {
	p.line = line
}

// Content returns the payload content
func (p *Payload) Content() string {
	return p.payload
}

// SetContent sets the content of the payload
func (p *Payload) SetContent(content string) {
	p.payload = content
}
