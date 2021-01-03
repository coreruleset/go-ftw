package http

import (
	"bytes"
	"io"
	"strconv"
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
func (h Header) Add(key, value string) {
	if h.Get(key) == "" {
		h.Set(key, value)
	}
}

// Set sets the header entries associated with key to
// the single element value. It replaces any existing
// values associated with key.
func (h Header) Set(key, value string) {
	h[key] = value
}

// Get gets the first value associated with the given key.
// It is case insensitive;
// If there are no values associated with the key, Get returns "".
func (h Header) Get(key string) string {
	if h == nil {
		return ""
	}
	v := h[key]

	return v
}

// Value returns the value associated with the given key.
// It is case insensitive;
func (h Header) Value(key string) string {
	if h == nil {
		return ""
	}

	return h[key]
}

// Del deletes the value associated with key.
func (h Header) Del(key string) {
	delete(h, key)
}

// AddStandard adds standard headers
func (h Header) AddStandard(dataSize int) {
	// For better performance, we always close the connection (unless otherwise)
	h.Add("Connection", "close")
	// If there is data, we add the length also
	if dataSize > 0 {
		h.Add("Content-Length", strconv.Itoa(dataSize))
	}
}

// Write writes a header in wire format.
func (h Header) Write(w io.Writer) error {
	ws, ok := w.(io.StringWriter)
	if !ok {
		ws = stringWriter{w}
	}

	for key, value := range h {
		// we want all headers "as-is"
		s := key + ": " + value + "\r\n"
		if _, err := ws.WriteString(s); err != nil {
			return err
		}
	}

	return nil

}

// WriteBytes writes a header in a ByteWriter.
func (h Header) WriteBytes(b *bytes.Buffer) error {
	for key, value := range h {
		// we want all headers "as-is"
		s := key + ": " + value + "\r\n"
		if _, err := b.Write([]byte(s)); err != nil {
			return err
		}
	}

	return nil

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
