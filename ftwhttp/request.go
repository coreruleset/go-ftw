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
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/utils"
)

var methodsWithBodyRegex = regexp.MustCompile(`^POST|PUT|PATCH|DELETE$`)

// ToString converts the request line to string for sending it in the wire
func (rl RequestLine) ToString() string {
	return fmt.Sprintf("%s %s %s\r\n", rl.Method, rl.URI, rl.Version)
}

// NewRequest creates a new request, an initial request line, and headers
func NewRequest(reqLine *RequestLine, h Header, data []byte, autocompleteHeaders bool) *Request {
	r := &Request{
		requestLine:         reqLine,
		headers:             h.Clone(),
		cookies:             nil,
		data:                data,
		raw:                 nil,
		autoCompleteHeaders: autocompleteHeaders,
	}
	return r
}

// NewRawRequest creates a new request, an initial request line, and headers
func NewRawRequest(raw []byte, b bool) *Request {
	r := &Request{
		raw:                 raw,
		autoCompleteHeaders: b,
	}
	return r
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
// You can use only one of raw, encoded or data.
func (r *Request) SetData(data []byte) error {
	if utils.IsNotEmpty(r.raw) {
		return errors.New("ftw/http: raw field is already present in this request")
	}
	r.data = data
	return nil
}

// SetRawData sets the data using raw bytes
//
// When using raw data, no other checks will be done.
// You are responsible of creating the request line, all the headers, and body.
// You can use only one of raw or data.
func (r *Request) SetRawData(raw []byte) error {
	if utils.IsNotEmpty(r.data) {
		return errors.New("ftw/http: data field is already present in this request")
	}
	r.raw = raw
	return nil
}

// Data returns the data
func (r Request) Data() []byte {
	return r.data
}

// RawData returns the raw data
func (r Request) RawData() []byte {
	return r.raw
}

// Headers return request headers
func (r Request) Headers() Header {
	return r.headers
}

// SetHeaders sets the request headers
func (r *Request) SetHeaders(h Header) {
	r.headers = h
}

// AddHeader adds a new header to the request, if doesn't exist
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
	if r.headers.Get("Connection") == "" {
		r.headers.Add("Connection", "close")
	}

	if len(r.data) > 0 || methodsWithBodyRegex.MatchString(r.requestLine.Method) {
		r.headers.Add("Content-Length", strconv.Itoa(len(r.data)))
	}
}

// isRaw is a helper that returns true if raw or encoded data
func (r Request) isRaw() bool {
	return utils.IsNotEmpty(r.raw)
}

// The request should be created with anything we want. We want to actually break HTTP.
func buildRequest(r *Request) ([]byte, error) {
	var err error
	var b bytes.Buffer
	var data []byte

	// Check if we need to create from all fields
	if !r.isRaw() {
		// Request line
		_, err = fmt.Fprintf(&b, "%s", r.requestLine.ToString())
		if err != nil {
			return nil, err
		}

		// We need to add the remaining headers, unless "NoDefaults"
		if utils.IsNotEmpty(r.data) && r.WithAutoCompleteHeaders() {
			// If there is no Content-Type, then we add one
			r.AddHeader(ContentTypeHeader, "application/x-www-form-urlencoded")
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
		if ct := r.headers.Value(ContentTypeHeader); strings.HasPrefix(ct, "multipart/form-data;") {
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

		_, err := r.Headers().WriteBytes(&b)
		if err != nil {
			log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
			return nil, err
		}

		// TODO: handle cookies
		// if client.Jar != nil {
		// 	for _, cookie := range client.Jar.Cookies(req.URL) {
		// 		req.AddCookie(cookie)
		// 	}
		// }

		// After headers, we need one blank line
		_, err = fmt.Fprintf(&b, "\r\n")
		if err != nil {
			log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
			return nil, err
		}
		// Now the body, if anything
		if utils.IsNotEmpty(r.data) {
			_, err = fmt.Fprintf(&b, "%s", r.data)
			if err != nil {
				log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
				return nil, err
			}
		}
	} else {
		dumpRawData(&b, r.raw)
	}

	return b.Bytes(), err
}

// encodeDataParameters url encode parameters in data
func encodeDataParameters(h Header, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var err error

	if h.Get(ContentTypeHeader) == "application/x-www-form-urlencoded" {
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

func dumpRawData(b *bytes.Buffer, raw []byte) {
	fmt.Fprintf(b, "%s", raw)
}
