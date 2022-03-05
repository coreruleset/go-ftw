package ftwhttp

import (
	"io"
)

// GetBodyAsString gives the response body as string, or nil if there was some error
func (r *Response) GetBodyAsString() string {
	body, err := io.ReadAll(r.Parsed.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
