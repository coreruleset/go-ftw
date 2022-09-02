package ftwhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func generateRequestForTesting(keepalive bool) *Request {
	var req *Request
	var connection string

	rl := &RequestLine{
		Method:  "GET",
		URI:     "/",
		Version: "HTTP/1.1",
	}

	if keepalive {
		connection = "keep-alive"
	} else {
		connection = "close"
	}
	h := Header{
		"Host":       "localhost",
		"User-Agent": "Go Tests",
		"Connection": connection,
	}

	req = NewRequest(rl, h, nil, true)

	return req
}

func generateRequestWithCookiesForTesting() *Request {
	var req *Request

	rl := &RequestLine{
		Method:  "GET",
		URI:     "/",
		Version: "HTTP/1.1",
	}

	h := Header{
		"Host":       "localhost",
		"User-Agent": "Go Tests",
		"Cookie":     "THISISACOOKIE",
		"Connection": "Keep-Alive",
	}

	req = NewRequest(rl, h, nil, true)

	return req
}

// Error checking omitted for brevity
func testServer() (server *httptest.Server) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))

	return ts
}

func testServerWithCookies() (server *httptest.Server) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expiration := time.Now().Add(365 * 24 * time.Hour)
		cookie := http.Cookie{Name: "username", Value: "go-ftw", Expires: expiration}
		http.SetCookie(w, &cookie)
		fmt.Fprintln(w, "Setting Cookies!")
	}))

	return ts
}

func TestResponse(t *testing.T) {
	server := testServer()

	defer server.Close()

	d, err := DestinationFromString(server.URL)

	if err != nil {
		t.Error(err)
	}
	req := generateRequestForTesting(true)

	client := NewClient(NewClientConfig())
	err = client.NewConnection(*d)

	if err != nil {
		t.Fatalf("Error! %s", err.Error())
	}

	response, err := client.Do(*req)

	if err != nil {
		t.Fatal(err)
	}

	if response.GetBodyAsString() != "Hello, client\n" {
		t.Errorf("Error!")
	}

}

func TestResponseWithCookies(t *testing.T) {
	server := testServerWithCookies()

	defer server.Close()

	d, err := DestinationFromString(server.URL)
	if err != nil {
		t.Fatalf("Error! %s", err.Error())
	}
	req := generateRequestForTesting(true)

	client := NewClient(NewClientConfig())
	err = client.NewConnection(*d)

	if err != nil {
		t.Fatalf("Error! %s", err.Error())
	}

	response, err := client.Do(*req)

	if err != nil {
		t.Logf("Failed !")
	}

	if response.GetBodyAsString() != "Setting Cookies!\n" {
		t.Errorf("Error!")
	}

	cookiereq := generateRequestWithCookiesForTesting()

	_, err = client.Do(*cookiereq)

	if err != nil {
		t.Logf("Failed !")
	}
}
