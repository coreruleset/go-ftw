package http

import (
	"bufio"
	"bytes"
	"net/http"
)

// Response should compare and return a boolean based on the received response
func (f *FTWHTTPConnection) Response() (*FTWHTTPResponse, error) {
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
	response := FTWHTTPResponse{
		RAW:    data,
		Parsed: *httpResponse,
	}
	return &response, err
}
