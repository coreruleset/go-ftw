package ftwhttp

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

type clientTestSuite struct {
	suite.Suite
	client *Client
	ts     *httptest.Server
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, new(clientTestSuite))
}

func (s *clientTestSuite) SetupTest() {
	var err error
	s.client, err = NewClient(NewClientConfig())
	s.NoError(err)
	s.Nil(s.client.Transport, "Transport not expected to initialized yet")
}

func (s *clientTestSuite) TearDownTest() {
	if s.ts != nil {
		s.ts.Close()
	}
}

func (s *clientTestSuite) httpTestServer() {
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := new(bytes.Buffer)
		for key, value := range r.Header {
			_, err := fmt.Fprintf(resp, "%s=%s,", key, value)
			s.NoError(err)
		}

		_, err := w.Write(resp.Bytes())
		s.NoError(err)
	}))
}

func (s *clientTestSuite) httpsTestServer() {
	s.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := new(bytes.Buffer)
		for key, value := range r.Header {
			_, err := fmt.Fprintf(resp, "%s=%s,", key, value)
			s.NoError(err)
		}

		_, err := w.Write(resp.Bytes())
		s.NoError(err)
	}))
}

func (s *clientTestSuite) TestNewClient() {
	s.NotNil(s.client.Jar, "Error creating Client")
}

func (s *clientTestSuite) TestConnectDestinationHTTPS() {
	s.httpsTestServer()
	d, err := DestinationFromString(s.ts.URL)
	s.NoError(err, "This should not error")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	err = s.client.NewConnection(*d)
	s.NoError(err, "This should not error")
	s.Equal("https", s.client.Transport.protocol, "Error connecting to example.com using https")
}

func (s *clientTestSuite) TestDoRequest() {
	s.httpsTestServer()
	d, err := DestinationFromString(s.ts.URL)
	s.NoError(err, "This should not error")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	req := generateBaseRequestForTesting()
	err = s.client.NewConnection(*d)
	s.NoError(err, "This should not error")

	response, err := s.client.Do(*req)

	// I'm getting consistently 400 Bad Request from the server, so I'm commenting this out for now.
	// Example:
	// nc httpbin.org 80
	// UNEXISTENT /bad/path HTTP/1.4
	// Host: httpbin.org
	// User-Agent: curl/7.88.1
	// Accept: */*
	s.NoError(err, "This should not error")
	s.Equal(response.Parsed.StatusCode, http.StatusBadRequest, "Error in calling website")
}

func (s *clientTestSuite) TestGetTrackedTime() {
	d := &Destination{
		DestAddr: "httpbingo.org",
		Port:     443,
		Protocol: "https",
	}

	rl := &RequestLine{
		Method:  "POST",
		URI:     "/post",
		Version: "HTTP/1.1",
	}

	h := Header{"Accept": "*/*", "User-Agent": "go-ftw test agent", "Host": "localhost"}

	data := []byte(`test=me&one=two&one=twice`)
	req := NewRequest(rl, h, data, true)

	err := s.client.NewConnection(*d)
	s.NoError(err, "This should not error")

	s.client.StartTrackingTime()

	resp, err := s.client.Do(*req)

	s.client.StopTrackingTime()

	s.NoError(err, "This should not error")
	s.Equal(http.StatusOK, resp.Parsed.StatusCode, "Error in calling website")

	rtt := s.client.GetRoundTripTime()
	s.GreaterOrEqual(int(rtt.RoundTripDuration()), 0, "Error getting RTT")
}

func (s *clientTestSuite) TestClientMultipartFormDataRequest() {
	s.httpsTestServer()
	d, err := DestinationFromString(s.ts.URL)
	s.NoError(err, "This should not error")

	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)

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

	err = s.client.NewConnection(*d)
	s.NoError(err, "This should not error")

	s.client.StartTrackingTime()

	resp, err := s.client.Do(*req)

	s.client.StopTrackingTime()

	s.NoError(err, "This should not error")
	s.Equal(http.StatusOK, resp.Parsed.StatusCode, "Error in calling website")

}

func (s *clientTestSuite) TestNewConnectionCreatesTransport() {
	s.httpsTestServer()
	d, err := DestinationFromString(s.ts.URL)
	s.NoError(err, "Failed to construct destination from test server")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	err = s.client.NewConnection(*d)
	s.NoError(err, "Failed to create new connection")
	s.NotNil(s.client.Transport, "Transport expected to be initialized")
	s.NotNil(s.client.Transport.connection, "Connection expected to be initialized")
}

func (s *clientTestSuite) TestNewOrReusedConnectionCreatesTransport() {
	s.httpsTestServer()
	d, err := DestinationFromString(s.ts.URL)
	s.NoError(err, "Failed to construct destination from test server")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	err = s.client.NewOrReusedConnection(*d)
	s.NoError(err, "Failed to create new or to reuse connection")
	s.NotNil(s.client.Transport, "Transport expected to be initialized")
	s.NotNil(s.client.Transport.connection, "Connection expected to be initialized")
}

func (s *clientTestSuite) TestNewOrReusedConnectionReusesTransport() {
	s.httpTestServer()
	d, err := DestinationFromString(s.ts.URL)
	s.NoError(err, "Failed to construct destination from test server")

	err = s.client.NewOrReusedConnection(*d)
	s.NoError(err, "Failed to create new or to reuse connection")
	s.NotNil(s.client.Transport, "Transport expected to be initialized")
	s.NotNil(s.client.Transport.connection, "Connection expected to be initialized")

	begin := s.client.Transport.duration.begin
	err = s.client.NewOrReusedConnection(*d)
	s.NoError(err, "Failed to reuse connection")

	s.Equal(begin, s.client.Transport.duration.begin, "Transport must not be reinitialized when reusing connection")
}
