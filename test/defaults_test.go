package test

import (
	"bytes"
	"testing"

	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/stretchr/testify/assert"
)

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

func TestBasicGetters(t *testing.T) {
	input := getTestExampleInput()

	dest := input.GetDestAddr()
	assert.Equal(t, "192.168.0.1", dest)
	method := input.GetMethod()
	assert.Equal(t, "REPORT", method)
	version := input.GetVersion()
	assert.Equal(t, "HTTP/1.1", version)
	port := input.GetPort()
	assert.Equal(t, 8080, port)
	proto := input.GetProtocol()
	assert.Equal(t, "http", proto)
	uri := input.GetURI()
	assert.Equal(t, "/test", uri)
	request, _ := input.GetRawRequest()
	assert.Equal(t, []byte("My Data\n"), request)
}

func TestDefaultGetters(t *testing.T) {
	inputDefaults := getTestInputDefaults()

	val := inputDefaults.GetDestAddr()
	assert.Equal(t, "localhost", val)

	val = inputDefaults.GetMethod()
	assert.Equal(t, "GET", val)

	val = inputDefaults.GetVersion()
	assert.Equal(t, "HTTP/1.1", val)

	port := inputDefaults.GetPort()
	assert.Equal(t, 80, port)

	val = inputDefaults.GetProtocol()
	assert.Equal(t, "http", val)

	val = inputDefaults.GetURI()
	assert.Equal(t, "/", val)

	assert.Equal(t, []byte("My Data"), []byte(*inputDefaults.Data))
}

func TestRaw(t *testing.T) {
	raw := getRawInput()

	assert.True(t, raw.StopMagic)

	request, _ := raw.GetRawRequest()
	assert.NotEqual(t, 2, bytes.Index(request, []byte("Acunetix")))
}
