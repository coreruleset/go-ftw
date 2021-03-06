package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func generateRequestForTesting() *Request {
	var req *Request

	rl := &RequestLine{
		Method:  "GET",
		URI:     "/",
		Version: "HTTP/1.1",
	}

	h := Header{"Host": "localhost", "User-Agent": "Go Tests"}

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

func TestResponse(t *testing.T) {
	server := testServer()

	defer server.Close()

	d := DestinationFromString(server.URL)

	req := generateRequestForTesting()

	fmt.Printf("%+v\n", d)
	client, err := NewConnection(*d)

	if err != nil {
		t.Fatalf("Error! %s", err.Error())
	}
	client, err = client.Request(req)

	if err != nil {
		t.Logf("Failed !")
	}

	response, err := client.Response()

	if err != nil {
		t.Logf("Failed !")
	}

	if response.GetBodyAsString() != "Hello, client\n" {
		t.Errorf("Error!")
	}

}
