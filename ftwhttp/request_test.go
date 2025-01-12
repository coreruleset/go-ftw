// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type requestTestSuite struct {
	suite.Suite
}

func (s *requestTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestRequestTestSuite(t *testing.T) {
	suite.Run(t, new(requestTestSuite))
}

func generateBaseRequestForTesting() *Request {
	var req *Request

	rl := &RequestLine{
		Method:  "UNEXISTENT",
		URI:     "/this/path",
		Version: "HTTP/1.4",
	}

	h := Header{"Host": "localhost", "This": "Header", "Connection": "Not-Closed"}

	req = NewRequest(rl, h, []byte("Data"), true)

	return req
}

func (s *requestTestSuite) TestAddStandardHeadersWhenConnectionHeaderIsPresent() {
	req := NewRequest(&RequestLine{}, Header{"Connection": "Not-Closed"}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Connection"), "Not-Closed")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenConnectionHeaderIsEmpty() {
	req := NewRequest(&RequestLine{}, Header{}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Connection"), "close")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenNoData() {
	req := NewRequest(&RequestLine{Method: "GET"}, Header{}, []byte(""), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Content-Length"), "")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenGetMethod() {
	req := NewRequest(&RequestLine{Method: "GET"}, Header{}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Content-Length"), "4")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenPostMethod() {
	req := NewRequest(&RequestLine{Method: "POST"}, Header{}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Content-Length"), "4")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenPutMethod() {
	req := NewRequest(&RequestLine{Method: "PUT"}, Header{}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Content-Length"), "4")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenPatchMethod() {
	req := NewRequest(&RequestLine{Method: "PATCH"}, Header{}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Content-Length"), "4")
}

func (s *requestTestSuite) TestAddStandardHeadersWhenDeleteMethod() {
	req := NewRequest(&RequestLine{Method: "DELETE"}, Header{}, []byte("Data"), true)

	req.AddStandardHeaders()

	s.Equal(req.headers.Get("Content-Length"), "4")
}

func (s *requestTestSuite) TestMultipartFormDataRequest() {
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
	// assert that the request is multipart/form-data
	s.Require().Contains(string(req.Data()), "--397236876")

}

func (s *requestTestSuite) TestRequestLine() {
	rl := &RequestLine{
		Method:  "UNEXISTENT",
		URI:     "/this/path",
		Version: "1.4",
	}

	str := rl.ToString()

	s.Equal("UNEXISTENT /this/path 1.4\r\n", str)
}

func (s *requestTestSuite) TestDestination() {
	d := &Destination{
		DestAddr: "192.168.1.1",
		Port:     443,
		Protocol: "https",
	}

	s.Equal("192.168.1.1", d.DestAddr)
	s.Equal(443, d.Port)
	s.Equal("https", d.Protocol)
}

func (s *requestTestSuite) TestRequestNew() {
	req := generateBaseRequestForTesting()

	head := req.Headers()
	s.Equal("Header", head.Get("This"))
	s.Equal([]byte("Data"), req.Data(), "Failed to set data")
}

func (s *requestTestSuite) TestWithAutocompleteRequest() {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two`)
	req = NewRequest(rl, h, data, true)

	s.True(req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
}

func (s *requestTestSuite) TestWithoutAutocompleteRequest() {
	var req *Request

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/path",
		Version: "1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two`)
	req = NewRequest(rl, h, data, false)

	s.False(req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
}

func (s *requestTestSuite) TestRequestHeadersSet() {
	req := generateBaseRequestForTesting()

	newH := Header{"X-New-Header": "Value"}
	req.SetHeaders(newH)

	s.Equal("Value", req.headers.Get("X-New-Header"), "Failed to set headers")
	req.AddHeader("X-New-Header2", "Value")
	head := req.Headers()
	s.Equal("Value", head.Get("X-New-Header2"))
}

func (s *requestTestSuite) TestRequestAutoCompleteHeaders() {
	req := generateBaseRequestForTesting()

	req.SetAutoCompleteHeaders(true)

	s.True(req.WithAutoCompleteHeaders(), "Set Autocomplete headers error ")
}

func (s *requestTestSuite) TestRequestData() {
	req := generateBaseRequestForTesting()

	err := req.SetData([]byte("This is the data now"))

	s.Require().NoError(err)
	s.Equal([]byte("This is the data now"), req.Data(), "failed to set data")
}

func (s *requestTestSuite) TestRequestURLParse() {
	req := generateBaseRequestForTesting()

	h := req.Headers()
	h.Add(ContentTypeHeader, "application/x-www-form-urlencoded")
	// Test adding semicolons to test parse
	err := req.SetData([]byte("test=This&test=nothing"))
	s.Require().NoError(err)
}

func (s *requestTestSuite) TestRequestURLParseFail() {
	req := generateBaseRequestForTesting()

	h := req.Headers()
	h.Add(ContentTypeHeader, "application/x-www-form-urlencoded")
	// Test adding semicolons to test parse
	err := req.SetData([]byte("test=This&that=but with;;;;;; data now"))
	s.Require().NoError(err)
}

func (s *requestTestSuite) TestRequestEncodesPostData() {
	tests := []struct {
		original string
		encoded  string
	}{
		{
			original: "",
			encoded:  "",
		},
		{
			original: "hello=world",
			encoded:  "hello=world",
		},
		{
			original: "foo bar",
			encoded:  "foo+bar",
		},
		{
			original: "name=panda&food=bamboo",
			encoded:  "name=panda&food=bamboo",
		},
		{
			// Test adding semicolons to test parse
			original: `c4= ;c3=t;c2=a;c1=client;a1=/;a2=e;a3=t;a4=client;a5=/;a6=p;a7=a;a8=s;a9=s;a10=w;a11=d;$c1$c2$c3$c4$a1$a2$a3$a4$a5$a6$a7$a8$a9$a10$a11`,
			encoded:  `c4=+%3Bc3%3Dt%3Bc2%3Da%3Bc1%3Dclient%3Ba1%3D%2F%3Ba2%3De%3Ba3%3Dt%3Ba4%3Dclient%3Ba5%3D%2F%3Ba6%3Dp%3Ba7%3Da%3Ba8%3Ds%3Ba9%3Ds%3Ba10%3Dw%3Ba11%3Dd%3B%24c1%24c2%24c3%24c4%24a1%24a2%24a3%24a4%24a5%24a6%24a7%24a8%24a9%24a10%24a11`,
		},
		{
			// Already encoded
			original: "foo+bar",
			encoded:  "foo+bar",
		},
	}

	for _, tc := range tests {
		tt := tc
		s.Run(tt.original, func() {
			req := generateBaseRequestForTesting()

			h := req.Headers()
			h.Add(ContentTypeHeader, "application/x-www-form-urlencoded")
			err := req.SetData([]byte(tt.original))
			s.Require().NoError(err)
			result, err := encodeDataParameters(h, req.Data())
			s.Require().NoError(err, "Failed to encode %s", req.Data())

			expected := tt.encoded
			actual := string(result)
			s.Equal(expected, actual, "Unexpected URL encoded payload")
		})
	}
}

func (s *requestTestSuite) TestNewRequest_EmptyHeaders() {
	rl := &RequestLine{
		Method:  "POST",
		URI:     "/path",
		Version: "1.1",
	}

	req := NewRequest(rl, nil, []byte{}, false)

	headers := req.Headers()
	s.NotNil(headers)
	s.Empty(headers)
}
