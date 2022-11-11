package ftwhttp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
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

	assert.False(t, req.isRaw())
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

	assert.False(t, req.autoCompleteHeaders)
}
func TestRequestLine(t *testing.T) {
	rl := &RequestLine{
		Method:  "UNEXISTENT",
		URI:     "/this/path",
		Version: "1.4",
	}

	s := rl.ToString()

	assert.Equal(t, "UNEXISTENT /this/path 1.4\r\n", s)
}

func TestDestination(t *testing.T) {
	d := &Destination{
		DestAddr: "192.168.1.1",
		Port:     443,
		Protocol: "https",
	}

	assert.Equal(t, "192.168.1.1", d.DestAddr)
	assert.Equal(t, 443, d.Port)
	assert.Equal(t, "https", d.Protocol)
}

func TestRequestNew(t *testing.T) {
	req := generateBaseRequestForTesting()

	head := req.Headers()
	assert.Equal(t, "Header", head.Get("This"))
	assert.Equal(t, []byte("Data"), req.Data(), "Failed to set data")
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

	assert.True(t, req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
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

	assert.False(t, req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
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
	head := req.Headers()
	assert.Equal(t, "Value", head.Get("X-New-Header2"))

	req.AddStandardHeaders(5)
}

func TestRequestAutoCompleteHeaders(t *testing.T) {
	req := generateBaseRequestForTesting()

	req.SetAutoCompleteHeaders(true)

	assert.True(t, req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
}

func TestRequestData(t *testing.T) {
	req := generateBaseRequestForTesting()

	err := req.SetData([]byte("This is the data now"))

	assert.NoError(t, err)
	assert.Equal(t, []byte("This is the data now"), req.Data(), "failed to set data")
}

func TestRequestSettingRawDataWhenThereIsData(t *testing.T) {
	req := generateBaseRequestForTesting()

	err := req.SetRawData([]byte("This is the data now"))

	expectedError := errors.New("ftw/http: data field is already present in this request")
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestRequestRawData(t *testing.T) {
	req := generateBaseRawRequestForTesting()

	err := req.SetRawData([]byte("This is the RAW data now"))
	assert.NoError(t, err)

	assert.Equal(t, []byte("This is the RAW data now"), req.RawData())
}

func TestRequestSettingDataaWhenThereIsRawData(t *testing.T) {
	req := generateBaseRawRequestForTesting()

	err := req.SetData([]byte("This is the data now"))
	expectedError := errors.New("ftw/http: raw field is already present in this request")
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestRequestURLParse(t *testing.T) {
	req := generateBaseRequestForTesting()

	h := req.Headers()
	h.Add(ContentTypeHeader, "application/x-www-form-urlencoded")
	// Test adding semicolons to test parse
	err := req.SetData([]byte("test=This&test=nothing"))
	assert.NoError(t, err)
}

func TestRequestURLParseFail(t *testing.T) {
	req := generateBaseRequestForTesting()

	h := req.Headers()
	h.Add(ContentTypeHeader, "application/x-www-form-urlencoded")
	// Test adding semicolons to test parse
	err := req.SetData([]byte("test=This&that=but with;;;;;; data now"))
	assert.NoError(t, err)
}

func TestRequestEncodesPostData(t *testing.T) {
	tests := []struct {
		raw     string
		encoded string
	}{
		{
			raw:     "",
			encoded: "",
		},
		{
			raw:     "hello=world",
			encoded: "hello=world",
		},
		{
			raw:     "foo bar",
			encoded: "foo+bar",
		},
		{
			// Test adding semicolons to test parse
			raw:     `c4= ;c3=t;c2=a;c1=c;a1=/;a2=e;a3=t;a4=c;a5=/;a6=p;a7=a;a8=s;a9=s;a10=w;a11=d;$c1$c2$c3$c4$a1$a2$a3$a4$a5$a6$a7$a8$a9$a10$a11`,
			encoded: "c4=+%3Bc3%3Dt%3Bc2%3Da%3Bc1%3Dc%3Ba1%3D%2F%3Ba2%3De%3Ba3%3Dt%3Ba4%3Dc%3Ba5%3D%2F%3Ba6%3Dp%3Ba7%3Da%3Ba8%3Ds%3Ba9%3Ds%3Ba10%3Dw%3Ba11%3Dd%3B%24c1%24c2%24c3%24c4%24a1%24a2%24a3%24a4%24a5%24a6%24a7%24a8%24a9%24a10%24a11",
		},
		{
			// Already encoded
			raw:     "foo+bar",
			encoded: "foo+bar",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.raw, func(t *testing.T) {
			req := generateBaseRequestForTesting()

			h := req.Headers()
			h.Add(ContentTypeHeader, "application/x-www-form-urlencoded")
			err := req.SetData([]byte(tt.raw))
			if err != nil {
				t.Errorf("Failed !")
			}
			result, err := encodeDataParameters(h, req.Data())
			if err != nil {
				t.Errorf("Failed to encode %s", req.Data())
			}

			expected := tt.encoded
			actual := string(result)
			if actual != expected {
				t.Errorf("Unexpected URL encoded payload, expected %s, got %s", expected, actual)
			}
		})
	}
}
