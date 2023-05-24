package ftwhttp

import (
	"io"
)

// GetFullResponse gives the full response as string, or nil if there was some error
func (r *Response) GetFullResponse() string {
	return string(r.RAW)
}

// GetBodyAsString gives the response body as string, or nil if there was some error
func (r *Response) GetBodyAsString() string {
	body, err := io.ReadAll(r.Parsed.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
