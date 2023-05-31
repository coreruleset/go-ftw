package test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/ftwhttp"
)

type defaultsTestSuite struct {
	suite.Suite
}

func TestDefaultsTestSuite(t *testing.T) {
	suite.Run(t, new(defaultsTestSuite))
}

func getTestInputDefaults() *Input {
	data := "My Data"

	inputDefaults := Input{
		Headers:    make(ftwhttp.Header),
		Data:       &data,
		SaveCookie: false,
		StopMagic:  false,
	}
	return &inputDefaults
}

func getTestExampleInput() *Input {
	destaddr := "192.168.0.1"
	port := 8080
	protocol := "http"
	uri := "/test"
	method := "REPORT"
	version := "HTTP/1.1"

	inputTest := Input{
		DestAddr:       &destaddr,
		Port:           &port,
		Protocol:       &protocol,
		URI:            &uri,
		Version:        &version,
		Headers:        make(ftwhttp.Header),
		Method:         &method,
		Data:           nil,
		EncodedRequest: "TXkgRGF0YQo=",
		SaveCookie:     false,
		StopMagic:      false,
	}

	return &inputTest
}

func getRawInput() *Input {
	destaddr := "192.168.0.1"
	port := 8080
	protocol := "http"

	inputTest := Input{
		DestAddr: &destaddr,
		Port:     &port,
		Protocol: &protocol,
		RAWRequest: `GET / HTTP/1.0
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Accept-Encoding: gzip,deflate
Accept-Language: en-us,en;q=0.5
Acunetix-Product: WVS/5.0 (Acunetix Web Vulnerability Scanner - EVALUATION)
Connection: close
Host: localhost
Keep-Alive: 300
Proxy-Connection: keep-alive
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)
		`,
		SaveCookie: false,
		StopMagic:  true,
	}

	return &inputTest
}

func (s *defaultsTestSuite) TestBasicGetters() {
	input := getTestExampleInput()

	dest := input.GetDestAddr()
	s.Equal("192.168.0.1", dest)
	method := input.GetMethod()
	s.Equal("REPORT", method)
	version := input.GetVersion()
	s.Equal("HTTP/1.1", version)
	port := input.GetPort()
	s.Equal(8080, port)
	proto := input.GetProtocol()
	s.Equal("http", proto)
	uri := input.GetURI()
	s.Equal("/test", uri)
	request, _ := input.GetRawRequest()
	s.Equal([]byte("My Data\n"), request)
}

func (s *defaultsTestSuite) TestDefaultGetters() {
	inputDefaults := getTestInputDefaults()

	val := inputDefaults.GetDestAddr()
	s.Equal("localhost", val)

	val = inputDefaults.GetMethod()
	s.Equal("GET", val)

	val = inputDefaults.GetVersion()
	s.Equal("HTTP/1.1", val)

	port := inputDefaults.GetPort()
	s.Equal(80, port)

	val = inputDefaults.GetProtocol()
	s.Equal("http", val)

	val = inputDefaults.GetURI()
	s.Equal("/", val)

	s.Equal([]byte("My Data"), []byte(*inputDefaults.Data))
}

func (s *defaultsTestSuite) TestRaw() {
	raw := getRawInput()

	s.True(raw.StopMagic)

	request, _ := raw.GetRawRequest()
	s.NotEqual(2, bytes.Index(request, []byte("Acunetix")))
}
