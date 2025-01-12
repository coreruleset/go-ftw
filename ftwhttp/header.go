// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"bufio"
	"io"
	"net/textproto"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	// HeaderSeparator is used to separate header name and value
	HeaderSeparator = ": "
	// HeaderDelimiter marks then end of a header (CRLF)
	HeaderDelimiter = "\r\n"
)

// Header is a representation of the HTTP header section.
// It holds an ordered list of HeaderTuples.
type Header struct {
	canonicalNames map[string]uint
	entries        []HeaderTuple
}

// HeaderTuple is a representation of an HTTP header. It consists
// of a name and value.
type HeaderTuple struct {
	Name  string
	Value string
}

// Creates an empty Header. You should not initialize the struct directly.
func NewHeader() *Header {
	return &Header{
		canonicalNames: map[string]uint{},
		entries:        []HeaderTuple{},
	}
}

// Creates a new Header from a map of HTTP header names and values.
//
// This is a convenience and legacy fallback method. In the future,
// headers should be specified as a list, in order to guarantee order
// and to allow requests to contain the same header multiple times,
// potentially with different values.
func NewHeaderFromMap(headerMap map[string]string) *Header {
	header := NewHeader()
	keys := make([]string, 0, len(headerMap))
	for key := range headerMap {
		keys = append(keys, key)
	}
	// Sort keys so that header constructed from a map has a
	// deterministic output.
	slices.Sort(keys)

	for _, key := range keys {
		header.Add(key, headerMap[key])
	}
	return header
}

// Add a new HTTP header to the Header.
func (h *Header) Add(name string, value string) {
	key := canonicalKey(name)
	count, ok := h.canonicalNames[key]
	if !ok {
		count = 0
	}
	h.canonicalNames[key] = count + 1
	h.entries = append(h.entries, HeaderTuple{name, value})
}

// Set replaces any existing HTTP headers of the same canonical
// name with this new entry.
func (h *Header) Set(name string, value string) {
	key := canonicalKey(name)
	retainees := []HeaderTuple{}
	for _, tuple := range h.entries {
		if canonicalKey(tuple.Name) != key {
			retainees = append(retainees, tuple)
		}
	}
	h.entries = retainees
	h.Add(name, value)
}

// Returns true if the Header contains any HTTP header that
// matches the canonical name.
func (h *Header) HasAny(name string) bool {
	key := canonicalKey(name)
	_, ok := h.canonicalNames[key]
	return ok
}

// Returns true if the Header contains any HTTP header that
// matches the canonical name and canoncial value.
// Values are compared using strings.EqualFold.
func (h *Header) HasAnyValue(name string, value string) bool {
	identity := func(a string) string { return a }
	return h.hasAnyValue(name, value, identity, identity, strings.EqualFold)
}

// Returns true if the Header contains any HTTP header that
// matches the canonical name and has a value containing the
// specified substring.
// Both, the header value and the search string are lower-cased
// before performing the search.
func (h *Header) HasAnyValueContaining(name string, value string) bool {
	return h.hasAnyValue(name, value, strings.ToLower, strings.ToLower, strings.Contains)
}

// Returns all HeaderTuples that match the canonical header name.
// If no matches are found the returned array will be empty.
func (h *Header) GetAll(name string) []HeaderTuple {
	return h.getAll(canonicalKey(name), canonicalKey)
}

// Write writes the header to the provided writer
func (h *Header) Write(writer io.Writer) error {
	buf := bufio.NewWriter(writer)
	for index, tuple := range h.entries {
		if log.Trace().Enabled() {
			log.Trace().Msgf("Writing header %d: %s: %s", index, tuple.Name, tuple.Value)
		}
		if _, err := buf.WriteString(tuple.Name + HeaderSeparator + tuple.Value + HeaderDelimiter); err != nil {
			return err
		}

	}
	return buf.Flush()
}

// Creates a clone of the Header.
// If the Header is nil or empty, a non-nil empty Header will be returned.
func (h *Header) Clone() *Header {
	newHeader := NewHeader()
	if h == nil {
		return newHeader
	}
	for _, tuple := range h.entries {
		newHeader.Add(tuple.Name, tuple.Value)
	}
	return newHeader
}

func canonicalKey(key string) string {
	return textproto.CanonicalMIMEHeaderKey(key)
}

func (h *Header) getAll(name string, canonicalizer func(key string) string) []HeaderTuple {
	matches := []HeaderTuple{}
	for _, tuple := range h.entries {
		if canonicalizer(tuple.Name) == name {
			matches = append(matches, tuple)
		}
	}

	return matches
}

func (h *Header) hasAnyValue(name string, value string, valueTransfomer func(a string) string, needleTransformer func(a string) string, comparator func(a string, b string) bool) bool {
	key := canonicalKey(name)
	if _, ok := h.canonicalNames[key]; !ok {
		return ok
	}
	transformedValue := valueTransfomer(value)
	for _, tuple := range h.entries {
		if canonicalKey(tuple.Name) == key && comparator(needleTransformer(tuple.Value), transformedValue) {
			return true
		}
	}
	return false
}
