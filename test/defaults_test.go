package test

import (
	"bytes"
	"testing"

	"github.com/coreruleset/go-ftw/ftwhttp"
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

	if dest := input.GetDestAddr(); dest != "192.168.0.1" {
		t.Fatalf("Error!")
	}

	if method := input.GetMethod(); method != "REPORT" {
		t.Fatalf("Error!")
	}

	if version := input.GetVersion(); version != "HTTP/1.1" {
		t.Fatalf("Error!")
	}

	if port := input.GetPort(); port != 8080 {
		t.Fatalf("Error!")
	}

	if val := input.GetProtocol(); val != "http" {
		t.Fatalf("Error!")
	}

	if val := input.GetURI(); val != "/test" {
		t.Fatalf("Error!")
	}

	if request, _ := input.GetRawRequest(); !bytes.Equal(request, []byte("My Data\n")) {
		t.Fatalf("Error!")
	}
}

func TestDefaultGetters(t *testing.T) {
	inputDefaults := getTestInputDefaults()

	if val := inputDefaults.GetDestAddr(); val != "localhost" {
		t.Fatalf("Error!")
	}

	if val := inputDefaults.GetMethod(); val != "GET" {
		t.Fatalf("Error!")
	}

	if val := inputDefaults.GetVersion(); val != "HTTP/1.1" {
		t.Fatalf("Error!")
	}

	if val := inputDefaults.GetPort(); val != 80 {
		t.Fatalf("Error!")
	}

	if val := inputDefaults.GetProtocol(); val != "http" {
		t.Fatalf("Error!")
	}

	if val := inputDefaults.GetURI(); val != "/" {
		t.Fatalf("Error!")
	}

	if !bytes.Equal([]byte(*inputDefaults.Data), []byte("My Data")) {
		t.Fatalf("Error!")
	}
}

func TestRaw(t *testing.T) {
	raw := getRawInput()

	if raw.StopMagic != true {
		t.Fatalf("Error!")
	}

	if request, _ := raw.GetRawRequest(); bytes.Index(request, []byte("Acunetix")) == 2 {
		t.Fatalf("Error!")
	}
}
