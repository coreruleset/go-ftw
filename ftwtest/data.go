package ftwtest

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// GetDataFromTest reads the test input data and return a byte array with the correct data set.
// If you passed more than one data field, e.g. Data AND Encoded Request, will return an error
func GetDataFromTest(f *Input) (data []byte, err error) {
	var b bytes.Buffer

	if f.Data != "" {
		fmt.Fprintf(&b, "%s", f.Data)
	}

	if f.EncodedRequest != "" {
		decodedString, err := base64.StdEncoding.DecodeString(f.EncodedRequest)
		if err == nil {
			fmt.Fprintf(&b, "%s", decodedString)
		}
	}

	if f.RAWRequest != "" {
		fmt.Fprintf(&b, "%s", f.RAWRequest)
	}

	return b.Bytes(), nil
}
