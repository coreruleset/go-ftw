package http

import (
	"bufio"
	"bytes"
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
