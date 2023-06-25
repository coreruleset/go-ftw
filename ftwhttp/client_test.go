package ftwhttp

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (
	secureServer   = true
	insecureServer = false
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
	s.Require().NoError(err)
	s.Nil(s.client.Transport, "Transport not expected to be initialized yet")
}

func (s *clientTestSuite) TearDownTest() {
	if s.ts != nil {
		s.ts.Close()
	}
}

func (s *clientTestSuite) httpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/not-found" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		resp := new(bytes.Buffer)
		for key, value := range r.Header {
			_, err := fmt.Fprintf(resp, "%s=%s,", key, value)
			s.Require().NoError(err)
		}

		_, err := w.Write(resp.Bytes())
		s.Require().NoError(err)
	}
}

func (s *clientTestSuite) httpTestServer(secure bool) {
	s.HTTPStatusCode(s.httpHandler(), http.MethodGet, "/", nil, http.StatusOK)
	s.HTTPStatusCode(s.httpHandler(), http.MethodGet, "/not-found", nil, http.StatusNotFound)

	if secure {
		s.ts = httptest.NewTLSServer(s.httpHandler())
	} else {
		s.ts = httptest.NewServer(s.httpHandler())
	}
}

func (s *clientTestSuite) TestNewClient() {
	s.NotNil(s.client.Jar, "Error creating Client")
}

func (s *clientTestSuite) TestConnectDestinationHTTPS() {
	s.httpTestServer(secureServer)
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err, "This should not error")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	err = s.client.NewConnection(*d)
	s.Require().NoError(err, "This should not error")
	s.Equal("https", s.client.Transport.protocol, "Error connecting to example.com using https")
}

func (s *clientTestSuite) TestDoRequest() {
	s.httpTestServer(secureServer)
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err, "This should not error")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	req := generateBaseRequestForTesting()
	req.requestLine.URI = "/not-found"
	err = s.client.NewConnection(*d)
	s.Require().NoError(err, "This should not error")
	response, err := s.client.Do(*req)
	s.Require().NoError(err, "This should error")
	s.Equal(http.StatusNotFound, response.Parsed.StatusCode, "Error in calling website")
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
	s.Require().NoError(err, "This should not error")

	s.client.StartTrackingTime()

	resp, err := s.client.Do(*req)

	s.client.StopTrackingTime()

	s.Require().NoError(err, "This should not error")
	s.Equal(http.StatusOK, resp.Parsed.StatusCode, "Error in calling website")

	rtt := s.client.GetRoundTripTime()
	s.GreaterOrEqual(int(rtt.RoundTripDuration()), 0, "Error getting RTT")
}

func (s *clientTestSuite) TestClientMultipartFormDataRequest() {
	s.httpTestServer(secureServer)
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err, "This should not error")

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
	s.Require().NoError(err, "This should not error")

	s.client.StartTrackingTime()

	resp, err := s.client.Do(*req)

	s.client.StopTrackingTime()

	s.Require().NoError(err, "This should not error")
	s.Equal(http.StatusOK, resp.Parsed.StatusCode, "Error in calling website")

}

func (s *clientTestSuite) TestNewConnectionCreatesTransport() {
	s.httpTestServer(secureServer)
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err, "Failed to construct destination from test server")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	err = s.client.NewConnection(*d)
	s.Require().NoError(err, "Failed to create new connection")
	s.NotNil(s.client.Transport, "Transport expected to be initialized")
	s.NotNil(s.client.Transport.connection, "Connection expected to be initialized")
}

func (s *clientTestSuite) TestNewOrReusedConnectionCreatesTransport() {
	s.httpTestServer(secureServer)
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err, "Failed to construct destination from test server")
	s.client.SetRootCAs(s.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	err = s.client.NewOrReusedConnection(*d)
	s.Require().NoError(err, "Failed to create new or to reuse connection")
	s.NotNil(s.client.Transport, "Transport expected to be initialized")
	s.NotNil(s.client.Transport.connection, "Connection expected to be initialized")
}

func (s *clientTestSuite) TestNewOrReusedConnectionReusesTransport() {
	s.httpTestServer(insecureServer)
	d, err := DestinationFromString(s.ts.URL)
	s.Require().NoError(err, "Failed to construct destination from test server")

	err = s.client.NewOrReusedConnection(*d)
	s.Require().NoError(err, "Failed to create new or to reuse connection")
	s.NotNil(s.client.Transport, "Transport expected to be initialized")
	s.NotNil(s.client.Transport.connection, "Connection expected to be initialized")

	begin := s.client.Transport.duration.begin
	err = s.client.NewOrReusedConnection(*d)
	s.Require().NoError(err, "Failed to reuse connection")

	s.Equal(begin, s.client.Transport.duration.begin, "Transport must not be reinitialized when reusing connection")
}
