package ftwhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)

	req := generateRequestForTesting(true)

	client := NewClient(NewClientConfig())
	err = client.NewConnection(*d)
	assert.NoError(t, err)

	response, err := client.Do(*req)
	assert.NoError(t, err)

	assert.Equal(t, "Hello, client\n", response.GetBodyAsString())
}

func TestResponseWithCookies(t *testing.T) {
	server := testServerWithCookies()

	defer server.Close()

	d, err := DestinationFromString(server.URL)
	assert.NoError(t, err)
	req := generateRequestForTesting(true)

	client := NewClient(NewClientConfig())
	err = client.NewConnection(*d)

	assert.NoError(t, err)

	response, err := client.Do(*req)

	assert.NoError(t, err)

	assert.Equal(t, "Setting Cookies!\n", response.GetBodyAsString())

	cookiereq := generateRequestWithCookiesForTesting()

	_, err = client.Do(*cookiereq)

	assert.NoError(t, err)
}
