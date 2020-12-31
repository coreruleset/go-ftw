package ftwtest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestGetDataFromTestMultiple1(t *testing.T) {
	input := Input{
		DestAddr:       "127.0.0.1",
		Port:           80,
		Protocol:       "http",
		URI:            "/test.html",
		Version:        "1.0",
		Data:           "test=me",
		EncodedRequest: "anythin",
	}

	_, err := GetDataFromTest(&input)

	if strings.Contains(err.Error(), "choose between data, encoded_request, or raw_request") {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed ! got %v want %s", err.Error(), "choose between data, encoded_request, or raw_request")
	}
}

func TestGetDataFromTestMultiple2(t *testing.T) {
	input := Input{
		DestAddr:       "127.0.0.1",
		Port:           80,
		Protocol:       "http",
		URI:            "/test.html",
		Version:        "1.0",
		EncodedRequest: "anythin",
		RAWRequest:     " this is a raw request",
	}

	_, err := GetDataFromTest(&input)

	if strings.Contains(err.Error(), "choose between data, encoded_request, or raw_request") {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed ! got %v want %s", err.Error(), "choose between data, encoded_request, or raw_request")
	}
}

func TestGetDataFromTestMultiple3(t *testing.T) {
	input := Input{
		DestAddr:   "127.0.0.1",
		Port:       80,
		Protocol:   "http",
		URI:        "/test.html",
		Version:    "1.0",
		Data:       "anythin",
		RAWRequest: " this is a raw request",
	}

	_, err := GetDataFromTest(&input)

	if strings.Contains(err.Error(), "choose between data, encoded_request, or raw_request") {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed ! got %v want %s", err.Error(), "choose between data, encoded_request, or raw_request")
	}
}

func TestGetDataFromTestUsingData(t *testing.T) {
	input := Input{
		DestAddr: "127.0.0.1",
		Port:     80,
		Protocol: "http",
		URI:      "/test.html",
		Version:  "1.0",
		Data:     "test=me",
	}

	expectedData := []byte{'t', 'e', 's', 't', '=', 'm', 'e'}

	// Comparing slice
	// Using Compare function

	data, _ := GetDataFromTest(&input)

	if bytes.Compare(expectedData, data) == 0 {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed ! got %v want %s", data, expectedData)
	}
}

func TestGetDataFromTestUsingEncoded(t *testing.T) {
	input := Input{
		DestAddr:       "127.0.0.1",
		Port:           80,
		Protocol:       "http",
		URI:            "/test.html",
		Version:        "1.0",
		EncodedRequest: "dGVzdD1tZQ==", // encoded "test=me"
	}

	expectedData := []byte{'t', 'e', 's', 't', '=', 'm', 'e'}

	// Comparing slice
	// Using Compare function

	data, _ := GetDataFromTest(&input)

	if bytes.Compare(expectedData, data) == 0 {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed ! got %v want %v", data, expectedData)
	}
}

// POST / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ModSecurity CRS 3 Tests\r\nAccept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nAccept-Encoding: gzip,deflate\r\nAccept-Language: en-us,en;q=0.5\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\ntest=\xac\xed\x00\x05\r\n\r\n

func TestGetDataFromTestUsingRawRequest(t *testing.T) {
	input := Input{
		DestAddr:   "127.0.0.1",
		Port:       80,
		Protocol:   "http",
		URI:        "/test.html",
		RAWRequest: "POST / HTTP/1.0\r\nContent-Length: 9\r\n\r\ntest=\xac\xed\x00\x05\r\n\r\n",
	}

	expectedData := []byte{'P', 'O', 'S', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '0', '\r', '\n',
		'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '9', '\r', '\n', '\r', '\n',
		't', 'e', 's', 't', '=', '\xac', '\xed', '\x00', '\x05', '\r', '\n', '\r', '\n'}

	// Comparing slice
	// Using Compare function

	data, _ := GetDataFromTest(&input)

	if bytes.Compare(expectedData, data) == 0 {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed ! \n got %v\nwant %v", data, expectedData)
	}
}

func TestGetDataFromYAML(t *testing.T) {
	yamlString := `
dest_addr: "127.0.0.1"
method: "POST"
port: 80
headers:
User-Agent: "ModSecurity CRS 3 Tests"
Host: "localhost"
Content-Type: "application/x-www-form-urlencoded"
data: "hi=test"
protocol: "http"
stop_magic: true
uri: "/"
`
	input := Input{}
	err := yaml.Unmarshal([]byte(yamlString), &input)
	fmt.Printf("%v", input)

	if err == nil && input.StopMagic == true {
		t.Logf("Success !")
	} else {
		t.Errorf("Failed !")
	}
}
