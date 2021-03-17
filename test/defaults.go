package test

import (
	"encoding/base64"

	"github.com/fzipi/go-ftw/utils"
)

// GetMethod returns the proper semantic when the field is empty
func (i *Input) GetMethod() string {
	if i.Method == nil {
		return "GET"
	}
	return *i.Method
}

// GetURI returns the proper semantic when the field is empty
func (i *Input) GetURI() string {
	if i.URI == nil {
		return "/"
	}
	return *i.URI
}

// GetVersion returns the proper semantic when the field is empty
func (i *Input) GetVersion() string {
	if i.Version == nil {
		return "HTTP/1.1"
	}
	return *i.Version
}

// GetProtocol returns the proper semantic when the field is empty
func (i *Input) GetProtocol() string {
	if i.Protocol == nil {
		return "http"
	}
	return *i.Protocol
}

// GetDestAddr returns the proper semantic when the field is empty
func (i *Input) GetDestAddr() string {
	if i.DestAddr == nil {
		return "localhost"
	}
	return *i.DestAddr
}

// GetPort returns the proper semantic when the field is empty
func (i *Input) GetPort() int {
	if i.Port == nil {
		return 80
	}
	return *i.Port
}

// GetRawRequest returns the proper raw data, and error if there was none
func (i *Input) GetRawRequest() ([]byte, error) {
	if utils.IsNotEmpty(i.EncodedRequest) {
		// if Encoded, first base64 decode, then dump
		return base64.StdEncoding.DecodeString(i.EncodedRequest)
	}
	if utils.IsNotEmpty(i.RAWRequest) {
		return []byte(i.RAWRequest), nil
	}
	return nil, nil
}
