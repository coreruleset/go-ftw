package http

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
)

// Response reads the response sent by the WAF and return the corresponding struct
// It leverages the go stdlib for reading and parsing the response
func (f *Connection) Response() (*Response, error) {
	data, err := f.receive()

	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	reader := *bufio.NewReader(r)

	httpResponse, err := http.ReadResponse(&reader, nil)
	if err != nil {
		return nil, err
	}
	response := Response{
		RAW:    data,
		Parsed: *httpResponse,
	}
	return &response, err
}

// GetBodyAsString gives the response body as string, or nil if there was some error
func (r *Response) GetBodyAsString() string {
	body, err := io.ReadAll(r.Parsed.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
