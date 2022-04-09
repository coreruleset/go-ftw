package ftwhttp

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient()

	if c.Jar == nil {
		t.Logf("Error creating Client")
	}
}

func TestConnectDestinationHTTPS(t *testing.T) {
	d := &Destination{
		DestAddr: "example.com",
		Port:     443,
		Protocol: "https",
	}

	c := NewClient()

	err := c.NewConnection(*d)
	if err != nil {
		t.Logf("This should not error")
	}

	if c.Transport.protocol != "https" {
		t.Logf("Error connecting to example.com using https")
	}
}

func TestDoRequest(t *testing.T) {
	d := &Destination{
		DestAddr: "httpbin.org",
		Port:     443,
		Protocol: "https",
	}

	c := NewClient()

	req := generateBaseRequestForTesting()

	err := c.NewConnection(*d)
	if err != nil {
		t.Logf("This should not error")
	}

	_, err = c.Do(*req)

	if err == nil {
		t.Logf("This should return error")
	}
}

func TestGetTrackedTime(t *testing.T) {
	d := &Destination{
		DestAddr: "httpbin.org",
		Port:     443,
		Protocol: "https",
	}

	c := NewClient()

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two&one=twice`)
	req := NewRequest(rl, h, data, true)

	err := c.NewConnection(*d)
	if err != nil {
		t.Logf("This should not error")
	}

	c.StartTrackingTime()

	resp, err := c.Do(*req)

	c.StopTrackingTime()

	if err != nil {
		t.Logf("This should not error")
	}

	if resp.Parsed.StatusCode != 200 {
		t.Logf("Error in calling website")
	}

	rtt := c.GetRoundTripTime()

	if rtt.RoundTripDuration() < 0 {
		t.Logf("Error getting RTT")
	}
}

func TestClientMultipartFormDataRequest(t *testing.T) {
	d := &Destination{
		DestAddr: "httpbin.org",
		Port:     443,
		Protocol: "https",
	}

	c := NewClient()

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
Content-Disposition: form-data; name="fileRap"; filename="test.txt"
Content-Type: text/plain

Some-file-test-here
----------397236876--`)

	req := NewRequest(rl, h, data, true)

	err := c.NewConnection(*d)

	if err != nil {
		t.Logf("This should not error")
	}

	c.StartTrackingTime()

	resp, err := c.Do(*req)

	c.StopTrackingTime()

	if err != nil {
		t.Logf("This should not error")
	}

	if resp.Parsed.StatusCode != 200 {
		t.Logf("Error in calling website")
	}

}
