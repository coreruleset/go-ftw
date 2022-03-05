package ftwhttp

import "testing"

func TestDestinationFromString(t *testing.T) {

}
func TestMultipleRequestTypes(t *testing.T) {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/path",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two`)
	req = NewRequest(rl, h, data, true)

	if !req.WithAutoCompleteHeaders() {
		t.Error("Set Autocomplete headers error ")
	}
}
