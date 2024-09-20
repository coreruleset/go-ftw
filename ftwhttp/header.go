// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"bytes"
	"github.com/coreruleset/go-ftw/utils"
	"github.com/rs/zerolog/log"
	"maps"
	"net/textproto"
)

const (
	// ContentTypeHeader gives you the string for content type
	ContentTypeHeader string = "Content-Type"
)

// Header exhibits the following structure
// Headers:
//
//	  Content-Type:
//	    content-type:
//		   - application/json
//		   - application/json
//		ConTent-tyPE:
//		   - application/json
type Header struct {
	headers map[string]map[string][]string
}

func NewHeader(headers map[string][]string) *Header {
	h := &Header{headers: make(map[string]map[string][]string)}
	for k, v := range headers {
		h.Add(k, v)
	}

	return h
}

// Get returns a collection of headers for the given raw key
// The key is case-sensitive
func (h *Header) Get(key string) map[string][]string {
	return h.getRawHeaders(key)
}

// Add adds the value to the collection for the given key
// The key is case-insensitive
func (h *Header) Add(key string, values []string) {
	rawHeaders := h.getRawHeaders(key)
	if rawHeaders == nil || len(rawHeaders) == 0 {
		h.Set(key, values)
		return
	}

	rawHeaders[key] = append(rawHeaders[key], values...)
}

// HasAny checks if the canonicalised version of given key has been already set
// The key is case-insensitive
func (h *Header) HasAny(key string) bool {
	if h.getRawHeaders(key) != nil {
		return true
	}

	return false
}

// First returns the first values associated with the canonicalised version of given key.
// If it does not exist returns an empty string ""
func (h *Header) First(key string) string {
	if !h.HasAny(key) {
		return ""
	}

	rawHeaders := h.getRawHeaders(key)

	for _, rawHeader := range rawHeaders {
		for _, rawValue := range rawHeader {
			if rawValue != "" {
				return rawValue
			}
		}
	}

	return ""
}

// Set sets the value for the given key, clearing all already existing values
// The key is case-insensitive
func (h *Header) Set(key string, values []string) {
	rawHeaders := h.getRawHeaders(key)
	if rawHeaders == nil {
		rawHeaders = h.initRawHeadersMap(key)
	}
	rawHeaders[key] = values
}

// WriteBytes writes a header in a ByteWriter.
func (h *Header) WriteBytes(b *bytes.Buffer) (int, error) {
	count := 0
	sortedCanonicalisedKeys := utils.GetSortedKeys(h.headers)
	for _, key := range sortedCanonicalisedKeys {
		rawHeaders := h.headers[key]
		sortedRawKeys := utils.GetSortedKeys(rawHeaders)
		for _, rawKey := range sortedRawKeys {
			for _, value := range rawHeaders[rawKey] {
				// we want all headers "as-is"
				s := rawKey + ": " + value + "\r\n"
				log.Trace().Msgf("Writing header: %s", s)
				n, err := b.Write([]byte(s))
				count += n
				if err != nil {
					return count, err
				}
			}
		}
	}

	return count, nil
}

// Clone returns a copy of h or nil if h is nil.
func (h *Header) Clone() Header {
	clone := maps.Clone(h.headers)

	return Header{clone}
}

// getRawHeaders returns the map of headers matching canonicalised key
func (h *Header) getRawHeaders(key string) map[string][]string {
	if h == nil || h.headers == nil {
		return nil
	}

	rawHeaders, ok := h.headers[canonicalKey(key)]
	if !ok {
		return nil
	}

	return rawHeaders
}

func (h *Header) initRawHeadersMap(key string) map[string][]string {
	cKey := canonicalKey(key)
	h.headers[cKey] = make(map[string][]string)

	return h.headers[cKey]
}

// canonicalKey transforms given to the canonical form
func canonicalKey(key string) string {
	return textproto.CanonicalMIMEHeaderKey(key)
}
