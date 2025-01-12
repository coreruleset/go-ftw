// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"

	"github.com/rs/zerolog/log"

	header_names "github.com/coreruleset/go-ftw/ftwhttp/header_names"
	header_values "github.com/coreruleset/go-ftw/ftwhttp/header_values"
	"github.com/coreruleset/go-ftw/utils"
)

var methodsWithBodyRegex = regexp.MustCompile(`^POST|PUT|PATCH|DELETE$`)

// ToString converts the request line to string for sending it in the wire
func (rl RequestLine) ToString() string {
	return fmt.Sprintf("%s %s %s\r\n", rl.Method, rl.URI, rl.Version)
}

// NewRequest creates a new request, an initial request line, and headers
func NewRequest(reqLine *RequestLine, h *Header, data []byte, autocompleteHeaders bool) *Request {
	return &Request{
		requestLine:         reqLine,
		headers:             h.Clone(),
		cookies:             nil,
		data:                data,
		autoCompleteHeaders: autocompleteHeaders,
		isRaw:               false,
	}
}

// NewRawRequest creates a new request from raw data
func NewRawRequest(data []byte) *Request {
	return &Request{
		rawRequest: data,
		isRaw:      true,
	}
}

// SetAutoCompleteHeaders sets the value to the corresponding bool
func (r *Request) SetAutoCompleteHeaders(value bool) {
	r.autoCompleteHeaders = value
}

// WithAutoCompleteHeaders returns true when we need to add additional headers to complete the request
func (r Request) WithAutoCompleteHeaders() bool {
	return r.autoCompleteHeaders
}

// SetData sets the data
// You can use only one of encoded or data.
func (r *Request) SetData(data []byte) error {
	r.data = data
	return nil
}

// Data returns the data
func (r Request) Data() []byte {
	return r.data
}

// Headers return request headers
func (r Request) Headers() *Header {
	return r.headers
}

// SetHeaders sets the request headers
func (r *Request) SetHeaders(h *Header) {
	r.headers = h
}

// AddHeader adds a new header to the request
func (r *Request) AddHeader(name string, value string) {
	r.headers.Add(name, value)
}

// AddStandardHeaders adds standard headers to the request, if they don't exist
//
// AddStandardHeaders does the following:
//   - adds `Connection` header with `close` value (if not set) to improve performance
//   - adds `Content-Length` header if payload size > 0 or the request method
//     permits a body (the spec says that the client SHOULD send `Content-Length`
//     in that case)
func (r *Request) AddStandardHeaders() {
	if !r.headers.HasAny(header_names.Connection) {
		r.headers.Add(header_names.Connection, "close")
	}

	if r.headers.HasAny(header_names.ContentLength) {
		return
	}

	if len(r.data) > 0 || methodsWithBodyRegex.MatchString(r.requestLine.Method) {
		r.headers.Add(header_names.ContentLength, strconv.Itoa(len(r.data)))
	}
}

// The request should be created with anything we want. We want to actually break HTTP.
func BuildRequest(r *Request) ([]byte, error) {
	var err error
	var b bytes.Buffer
	var data []byte

	// Request line
	_, err = b.WriteString(r.requestLine.ToString())
	if err != nil {
		return nil, err
	}

	// We need to add the remaining headers, unless "NoDefaults"
	if utils.IsNotEmpty(r.data) && r.WithAutoCompleteHeaders() {
		if !r.Headers().HasAny(header_names.ContentType) {
			// If there is no Content-Type, then we add one
			r.AddHeader(header_names.ContentType, header_values.ApplicationXWwwFormUrlencoded)
		}
		data, err = encodeDataParameters(r.headers, r.data)
		if err != nil {
			log.Info().Msgf("ftw/http: cannot encode data to: %q", r.data)
			return nil, err
		}
		err = r.SetData(data)
		if err != nil {
			log.Info().Msgf("ftw/http: cannot set data to: %q", r.data)
			return nil, err
		}
	}

	// Multipart form data needs to end in \r\n, per RFC (and modsecurity make a scene if not)
	if r.headers.HasAnyValueContaining(header_names.ContentType, "multipart/form-data;") {
		crlf := []byte("\r\n")
		lf := []byte("\n")
		log.Debug().Msgf("ftw/http: with LF only - %d bytes:\n%x\n", len(r.data), r.data)
		data = bytes.ReplaceAll(r.data, lf, crlf)
		log.Debug().Msgf("ftw/http: with CRLF - %d bytes:\n%x\n", len(data), data)
		r.data = data
	}

	if r.WithAutoCompleteHeaders() {
		r.AddStandardHeaders()
	}

	err = r.Headers().Write(&b)
	if err != nil {
		log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
		return nil, err
	}

	// After headers, we need one blank line
	_, err = b.WriteString("\r\n")
	if err != nil {
		log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
		return nil, err
	}
	// Now the body, if anything
	if utils.IsNotEmpty(r.data) {
		_, err = b.Write(r.data)
		if err != nil {
			log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
			return nil, err
		}
	}

	return b.Bytes(), err
}

// encodeDataParameters url encode parameters in data
func encodeDataParameters(h *Header, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var err error

	if h.HasAnyValue(header_names.ContentType, header_values.ApplicationXWwwFormUrlencoded) {
		// Best effort attempt to determine if the data is already escaped by seeing if unescaping has any effect.
		if escapedData, err := url.QueryUnescape(string(data)); escapedData == string(data) {
			if err != nil {
				return nil, errors.New("Failed")
			}

			// CRS tests include form parameters as key=value pairs with unencoded key/values, so we encode them.
			// If we were to encode the entire string, the equals sign would be encoded as well
			escaped := bytes.Buffer{}
			remaining := data
			for len(remaining) > 0 {
				ampIndex := bytes.IndexByte(remaining, '&')
				var token []byte
				if ampIndex == -1 {
					token = remaining
					remaining = nil
				} else {
					token = remaining[:ampIndex]
					remaining = remaining[ampIndex+1:]
				}

				eqIndex := bytes.IndexByte(token, '=')
				if eqIndex == -1 {
					escaped.WriteString(url.QueryEscape(string(token)))
					escaped.WriteByte('&')
					continue
				}

				key := token[:eqIndex]
				value := token[eqIndex+1:]
				escaped.WriteString(url.QueryEscape(string(key)))
				escaped.WriteByte('=')
				escaped.WriteString(url.QueryEscape(string(value)))
				escaped.WriteByte('&')
			}

			// Strip trailing &
			queryString := escaped.Bytes()[:escaped.Len()-1]
			return queryString, nil
		}
	}
	return data, err
}
