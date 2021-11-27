package http

import (
	"bytes"
	"strings"
	"testing"
)

func generateBaseRequestForTesting() *Request {
	var req *Request

	rl := &RequestLine{
		Method:  "UNEXISTENT",
		URI:     "/this/path",
		Version: "1.4",
	}

	h := Header{"This": "Header", "Connection": "Not-Closed"}

	req = NewRequest(rl, h, []byte("Data"), true)

	return req
}

func TestMultipartFormDataRequest(t *testing.T) {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{
		"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost",
		"Content-Type": "multipart/form-data; boundary=--------397236876",
	}

	data := []byte(`----------397236876
Content-Disposition: form-data; name="fileRap"; filename="te;st.txt"
Content-Type: text/plain

Some-file-test-here
----------397236876--`)
	req = NewRequest(rl, h, data, true)

	if req.isRaw() {
		t.Error()
	}
}

func generateBaseRawRequestForTesting() *Request {
	var req *Request

	raw := []byte(`POST / HTTP/1.1
Connection: close
Content-Length: 123x
Content-Type: application/x-www-form-urlencoded
Host: localhost
User-Agent: ModSecurity CRS 3 Tests
`)
	req = NewRawRequest(raw, true)

	return req
}

func TestGenerateBaseRawRequestForTesting(t *testing.T) {
	var req *Request

	raw := []byte(`POST / HTTP/1.1
Connection: close
Content-Length: 123x
Content-Type: application/x-www-form-urlencoded
Host: localhost
User-Agent: ModSecurity CRS 3 Tests
`)
	req = NewRawRequest(raw, false)

	if req.autoCompleteHeaders {
		t.Fatalf("asdasd")
	}
}
func TestRequestLine(t *testing.T) {
	rl := &RequestLine{
		Method:  "UNEXISTENT",
		URI:     "/this/path",
		Version: "1.4",
	}

	s := rl.ToString()

	if s != "UNEXISTENT /this/path 1.4\r\n" {
		t.Fatalf("Failed!")
	}
}

func TestDestination(t *testing.T) {
	d := &Destination{
		DestAddr: "192.168.1.1",
		Port:     443,
		Protocol: "https",
	}

	if d.DestAddr == "192.168.1.1" && d.Port == 443 && d.Protocol == "https" {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestRequestNew(t *testing.T) {
	req := generateBaseRequestForTesting()

	head := req.Headers()
	if head.Get("This") == "Header" {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}

	if !bytes.Equal(req.Data(), []byte("Data")) {
		t.Error("Failed to set data")
	}
}

func TestWithAutocompleteRequest(t *testing.T) {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two`)
	req = NewRequest(rl, h, data, true)

	if !req.WithAutoCompleteHeaders() {
		t.Error("Set Autocomplete headers error ")
	}
}

func TestWithoutAutocompleteRequest(t *testing.T) {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/path",
		Version: "1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two`)
	req = NewRequest(rl, h, data, false)

	if req.WithAutoCompleteHeaders() {
		t.Error("Set Autocomplete headers error ")
	}
}

func TestRequestHeadersSet(t *testing.T) {
	req := generateBaseRequestForTesting()

	newH := Header{"X-New-Header": "Value"}
	req.SetHeaders(newH)

	if req.headers.Get("X-New-Header") == "Value" {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}

	req.AddHeader("X-New-Header2", "Value")

	if req.headers.Get("X-New-Header2") != "Value" {
		t.Errorf("Failed !")
	}

	req.AddStandardHeaders(5)

}

func TestRequestAutoCompleteHeaders(t *testing.T) {
	req := generateBaseRequestForTesting()

	req.SetAutoCompleteHeaders(true)

	if req.WithAutoCompleteHeaders() == true {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestRequestData(t *testing.T) {
	req := generateBaseRequestForTesting()

	err := req.SetData([]byte("This is the data now"))

	if err != nil && !bytes.Equal(req.Data(), []byte("This is the data now")) {
		t.Errorf("Failed !")
	}
}

func TestRequestSettingRawDataWhenThereIsData(t *testing.T) {
	req := generateBaseRequestForTesting()

	err := req.SetRawData([]byte("This is the data now"))

	if err != nil && strings.Contains(err.Error(), "data field is already present in this request") {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed %s !", err.Error())
	}
}

func TestRequestRawData(t *testing.T) {
	req := generateBaseRawRequestForTesting()

	if err := req.SetRawData([]byte("This is the RAW data now")); err != nil {
		t.Errorf("Failed !")
	}

	if bytes.Equal(req.RawData(), []byte("This is the RAW data now")) {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}

func TestRequesSettingDataaWhenThereIsRawData(t *testing.T) {
	req := generateBaseRawRequestForTesting()

	err := req.SetData([]byte("This is the data now"))

	if err != nil && strings.Contains(err.Error(), "raw field is already present in this request") {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}
