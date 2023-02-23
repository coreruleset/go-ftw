package ftwhttp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)

	assert.NotNil(t, c.Jar, "Error creating Client")
}

func TestConnectDestinationHTTPS(t *testing.T) {
	d := &Destination{
		DestAddr: "example.com",
		Port:     443,
		Protocol: "https",
	}

	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)

	err = c.NewConnection(*d)
	assert.NoError(t, err, "This should not error")
	assert.Equal(t, "https", c.Transport.protocol, "Error connecting to example.com using https")
}

func TestDoRequest(t *testing.T) {
	d := &Destination{
		DestAddr: "httpbin.org",
		Port:     443,
		Protocol: "https",
	}

	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)

	req := generateBaseRequestForTesting()

	err = c.NewConnection(*d)
	assert.NoError(t, err, "This should not error")

	_, err = c.Do(*req)

	assert.Error(t, err, "This should return error")
}

func TestGetTrackedTime(t *testing.T) {
	d := &Destination{
		DestAddr: "httpbin.org",
		Port:     443,
		Protocol: "https",
	}

	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two&one=twice`)
	req := NewRequest(rl, h, data, true)

	err = c.NewConnection(*d)
	assert.NoError(t, err, "This should not error")

	c.StartTrackingTime()

	resp, err := c.Do(*req)

	c.StopTrackingTime()

	assert.NoError(t, err, "This should not error")

	assert.Equal(t, 200, resp.Parsed.StatusCode, "Error in calling website")

	rtt := c.GetRoundTripTime()

	assert.GreaterOrEqual(t, int(rtt.RoundTripDuration()), 0, "Error getting RTT")
}

func TestClientMultipartFormDataRequest(t *testing.T) {
	d := &Destination{
		DestAddr: "httpbin.org",
		Port:     443,
		Protocol: "https",
	}

	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{
		"Accept": "*/*", "User-Agent": "ftw test agent", "Host": "localhost",
		"Content-Type": "multipart/form-data; boundary=--------397236876",
	}

	data := []byte(`----------397236876
Content-Disposition: form-data; name="fileRap"; filename="test.txt"
Content-Type: text/plain

Some-file-test-here
----------397236876--`)

	req := NewRequest(rl, h, data, true)

	err = c.NewConnection(*d)
	assert.NoError(t, err, "This should not error")

	c.StartTrackingTime()

	resp, err := c.Do(*req)

	c.StopTrackingTime()

	assert.NoError(t, err, "This should not error")
	assert.Equal(t, 200, resp.Parsed.StatusCode, "Error in calling website")

}

func TestNewConnectionCreatesTransport(t *testing.T) {
	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)
	assert.Nil(t, c.Transport, "Transport not expected to initialized yet")

	server := testServer()
	d, err := DestinationFromString(server.URL)
	assert.NoError(t, err, "Failed to construct destination from test server")

	err = c.NewConnection(*d)
	assert.NoError(t, err, "Failed to create new connection")
	assert.NotNil(t, c.Transport, "Transport expected to be initialized")
	assert.NotNil(t, c.Transport.connection, "Connection expected to be initialized")
}

func TestNewOrReusedConnectionCreatesTransport(t *testing.T) {
	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)
	assert.Nil(t, c.Transport, "Transport not expected to initialized yet")

	server := testServer()
	d, err := DestinationFromString(server.URL)
	assert.NoError(t, err, "Failed to construct destination from test server")

	err = c.NewOrReusedConnection(*d)
	assert.NoError(t, err, "Failed to create new or to reuse connection")
	assert.NotNil(t, c.Transport, "Transport expected to be initialized")
	assert.NotNil(t, c.Transport.connection, "Connection expected to be initialized")
}

func TestNewOrReusedConnectionReusesTransport(t *testing.T) {
	c, err := NewClient(NewClientConfig())
	assert.NoError(t, err)
	assert.Nil(t, c.Transport, "Transport not expected to initialized yet")

	server := testServer()
	d, err := DestinationFromString(server.URL)
	assert.NoError(t, err, "Failed to construct destination from test server")

	err = c.NewOrReusedConnection(*d)
	assert.NoError(t, err, "Failed to create new or to reuse connection")
	assert.NotNil(t, c.Transport, "Transport expected to be initialized")
	assert.NotNil(t, c.Transport.connection, "Connection expected to be initialized")

	begin := c.Transport.duration.begin
	err = c.NewOrReusedConnection(*d)
	assert.NoError(t, err, "Failed to reuse connection")

	assert.Equal(t, begin, c.Transport.duration.begin, "Transport must not be reinitialized when reusing connection")
}
