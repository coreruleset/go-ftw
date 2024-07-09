// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"bytes"
	"io"
	"net/textproto"
	"sort"

	"github.com/rs/zerolog/log"
)

const (
	// ContentTypeHeader gives you the string for content type
	ContentTypeHeader string = "Content-Type"
)

// Based on https://golang.org/src/net/http/header.go

// Header is a simplified version of headers, where there is only one header per key.
// The original golang stdlib uses a proper string slice to map this.
type Header map[string]string

// stringWriter implements WriteString on a Writer.
type stringWriter struct {
	w io.Writer
}

// WriteString writes the string on a Writer
func (w stringWriter) WriteString(s string) (n int, err error) {
	return w.w.Write([]byte(s))
}

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
// The key is case in-sensitive
func (h Header) Add(key, value string) {
	key = canonicalHeaderKey(key)
	if h.Get(key) == "" {
		h.Set(key, value)
	}
}

// Set sets the header entries associated with key to
// the single element value. It replaces any existing
// values associated with key.
// The key is case in-sensitive
func (h Header) Set(key, value string) {
	h[canonicalHeaderKey(key)] = value
}

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns "".
// The key is case in-sensitive
func (h Header) Get(key string) string {
	if h == nil {
		return ""
	}
	v := h[canonicalHeaderKey(key)]

	return v
}

// Value returns the value associated with the given key.
// The key is case in-sensitive
func (h Header) Value(key string) string {
	if h == nil {
		return ""
	}

	return h[canonicalHeaderKey(key)]
}

// Del deletes the value associated with key.
// The key is case in-sensitive
func (h Header) Del(key string) {
	delete(h, canonicalHeaderKey(key))
}

// Write writes a header in wire format.
func (h Header) Write(w io.Writer) error {
	ws, ok := w.(io.StringWriter)
	if !ok {
		ws = stringWriter{w}
	}

	sorted := h.getSortedHeadersByName()

	for _, key := range sorted {
		// we want all headers "as-is"
		s := key + ": " + h[key] + "\r\n"
		if _, err := ws.WriteString(s); err != nil {
			return err
		}
	}

	return nil

}

// WriteBytes writes a header in a ByteWriter.
func (h Header) WriteBytes(b *bytes.Buffer) (int, error) {
	sorted := h.getSortedHeadersByName()
	count := 0
	for _, key := range sorted {
		// we want all headers "as-is"
		s := key + ": " + h[key] + "\r\n"
		log.Trace().Msgf("Writing header: %s", s)
		n, err := b.Write([]byte(s))
		count += n
		if err != nil {
			return count, err
		}
	}

	return count, nil
}

// Clone returns a copy of h or nil if h is nil.
func (h Header) Clone() Header {
	if h == nil {
		return nil
	}
	clone := make(Header)

	for n, v := range h {
		clone[n] = v
	}

	return clone
}

// sortHeadersByName gets headers sorted by name
// This way the output is predictable, for tests
func (h Header) getSortedHeadersByName() []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

// canonicalHeaderKey transforms given to the canonical form
func canonicalHeaderKey(key string) string {
	return textproto.CanonicalMIMEHeaderKey(key)
}
