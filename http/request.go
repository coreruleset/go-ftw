package http

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/fzipi/go-ftw/utils"

	"github.com/rs/zerolog/log"
)

// Destination is the host, port and protocol to be used when connecting to a remote host
type Destination struct {
	DestAddr string `default:"localhost"`
	Port     int    `default:"80"`
	Protocol string `default:"http"`
}

// RequestLine is the first line in the HTTP request dialog
type RequestLine struct {
	Method  string `default:"GET"`
	Version string `default:"HTTP/1.1"`
	URI     string `default:"/"`
}

// ToString converts the request line to string for sending it in the wire
func (rl RequestLine) ToString() string {
	return fmt.Sprintf("%s %s %s\r\n", rl.Method, rl.URI, rl.Version)
}

// Request represents a request
// No Defaults represents the previous "stop_magic" behavior
type Request struct {
	requestLine         *RequestLine
	headers             Header
	cookies             http.CookieJar
	data                []byte
	raw                 []byte
	autoCompleteHeaders bool
}

// NewRequest creates a new request, an initial request line, and headers
func NewRequest(reqLine *RequestLine, h Header, data []byte, b bool) *Request {
	r := &Request{
		requestLine:         reqLine,
		headers:             h.Clone(),
		cookies:             nil,
		data:                data,
		raw:                 nil,
		autoCompleteHeaders: b,
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
	if r.headers == nil {
		return nil
	}
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
// This will add Content-Length and the proper Content-Type
func (r *Request) AddStandardHeaders(size int) {
	r.headers.AddStandard(size)
}

// Request will use all the inputs and send a raw http request to the destination
func (c *Connection) Request(request *Request) error {
	// Build request first, then connect and send, so timers are accurate
	data, err := buildRequest(request)
	if err != nil {
		log.Fatal().Msgf("ftw/http: fatal error building request: %s", err.Error())
	}

	log.Debug().Msgf("ftw/http: sending data:\n%s\n", data)

	_, err = c.send(data)

	if err != nil {
		log.Error().Msgf("ftw/http: error writing data: %s", err.Error())
	}

	return err
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

		log.Trace().Msgf("ftw/http: this is data: %q, of len %d", r.data, len(r.data))

		// We need to add the remaining headers, unless "NoDefaults"
		if utils.IsNotEmpty(r.data) && r.WithAutoCompleteHeaders() {
			// If there is no Content-Type, then we add one
			r.AddHeader("Content-Type", "application/x-www-form-urlencoded")
			err := r.SetData(encodeDataParameters(r.headers, r.data))
			if err != nil {
				log.Info().Msgf("ftw/http: cannot set data to: %q", r.data)
			}
		}

		// Multipart form data needs to end in \r\n, per RFC (and modsecurity make a scene if not)
		if ct := r.headers.Value("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
			crlf := []byte("\r\n")
			lf := []byte("\n")
			log.Debug().Msgf("ftw/http: with LF only - %d bytes:\n%x\n", len(r.data), r.data)
			data = bytes.ReplaceAll(r.data, lf, crlf)
			log.Debug().Msgf("ftw/http: with CRLF - %d bytes:\n%x\n", len(data), data)
			r.data = data
		}

		if r.WithAutoCompleteHeaders() {
			log.Trace().Msgf("ftw/http: adding standard headers")
			r.AddStandardHeaders(len(r.data))
		}

		err = r.Headers().WriteBytes(&b)
		if err != nil {
			log.Debug().Msgf("ftw/http: error writing to buffer: %s", err.Error())
			return nil, err
		}

		// TODO: handle cookies
		// if c.Jar != nil {
		// 	for _, cookie := range c.Jar.Cookies(req.URL) {
		// 		req.AddCookie(cookie)
		// 	}
		// }

		// After headers, we need one blank line
		_, err = fmt.Fprintf(&b, "\r\n")

		// Now the body, if anything
		if utils.IsNotEmpty(r.data) {
			_, err = fmt.Fprintf(&b, "%s", r.data)
		}
	} else {
		dumpRawData(&b, r.raw)
	}

	return b.Bytes(), err
}

// If the values are empty in the map, then don't encode anythin
// This keeps the compatibility with the python implementation
func emptyQueryValues(values url.Values) bool {
	for _, val := range values {
		if len(val) > 1 {
			return false
		}
	}
	return true
}

// encodeDataParameters url encode parameters in data
func encodeDataParameters(h Header, data []byte) []byte {
	if h.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if escapedData, _ := url.QueryUnescape(string(data)); escapedData == string(data) {
			log.Trace().Msgf("ftw/http: parsing data: %q", data)
			queryString, err := url.ParseQuery(string(data))
			if err != nil || emptyQueryValues(queryString) {
				log.Trace().Msgf("ftw/http: cannot parse or empty values in query string: %s", data)
			} else {
				log.Trace().Msgf("ftw/http: this is the query string parsed: %+v", queryString)
				encodedData := queryString.Encode()
				log.Trace().Msgf("ftw/http: encoded data to: %s", encodedData)
				if encodedData != string(data) {
					// we need to encode data
					return []byte(encodedData)
				}
			}
		}
	}
	return data
}

func dumpRawData(b *bytes.Buffer, raw []byte) {
	log.Trace().Msgf("ftw/http: using RAW data")

	fmt.Fprintf(b, "%s", raw)
}
