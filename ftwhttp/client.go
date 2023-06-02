package ftwhttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

// NewClientConfig returns a new ClientConfig with reasonable defaults.
func NewClientConfig() ClientConfig {
	return ClientConfig{
		ConnectTimeout: 3 * time.Second,
		ReadTimeout:    1 * time.Second,
	}
}

// NewClient initializes the http client, creating the cookiejar
func NewClient(config ClientConfig) (*Client, error) {
	// All users of cookiejar should import "golang.org/x/net/publicsuffix"
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	c := &Client{
		Jar:    jar,
		config: config,
	}
	return c, nil
}

// SetRootCAs sets the root CAs for the client.
// This can be used if you are using internal certificates and for testing purposes.
func (c *Client) SetRootCAs(cas *x509.CertPool) {
	c.config.RootCAs = cas
}

// NewConnection creates a new Connection based on a Destination
func (c *Client) NewConnection(d Destination) error {
	if c.Transport != nil && c.Transport.connection != nil {
		if err := c.Transport.connection.Close(); err != nil {
			return err
		}
	}

	c.Transport = &Connection{
		protocol:    d.Protocol,
		readTimeout: c.config.ReadTimeout,
		duration:    NewRoundTripTime(),
	}

	netConn, err := c.dial(d)
	if err == nil {
		c.Transport.connection = netConn
	}

	return err
}

// NewOrReusedConnection reuses an existing connection, or creates a new one
// if no connection has been set up yet
func (c *Client) NewOrReusedConnection(d Destination) error {
	if c.Transport == nil {
		return c.NewConnection(d)
	}
	if err := c.Transport.connection.Close(); err != nil {
		return err
	}

	netConn, err := c.dial(d)
	if err == nil {
		c.Transport.connection = netConn
	}

	return err
}

// dial tries to establish a connection
func (c *Client) dial(d Destination) (net.Conn, error) {
	hostPort := fmt.Sprintf("%s:%d", d.DestAddr, d.Port)

	// Fatal error: dial tcp 127.0.0.1:80: connect: connection refused
	// strings.HasSuffix(err.String(), "connection refused") {
	if strings.ToLower(d.Protocol) == "https" {
		// Commenting InsecureSkipVerify: true.
		return tls.DialWithDialer(
			&net.Dialer{
				Timeout: c.config.ConnectTimeout,
			},
			"tcp", hostPort,
			&tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    c.config.RootCAs,
			})
	}

	return net.DialTimeout("tcp", hostPort, c.config.ConnectTimeout)
}

// Do perform the http request round trip.
func (c *Client) Do(req Request) (*Response, error) {
	var response *Response

	err := c.Transport.Request(&req)

	if err != nil {
		log.Error().Msgf("http/client: error sending request: %s\n", err.Error())
	} else {
		response, err = c.Transport.Response()
		if err != nil {
			log.Debug().Msgf("ftw/run: error receiving response: %s\n", err.Error())
			// This error might be expected. Let's continue
		}
	}

	return response, err
}

// GetRoundTripTime returns the time taken from the initial send till receiving the full response
func (c *Client) GetRoundTripTime() *RoundTripTime {
	return c.Transport.GetTrackedTime()
}

// StartTrackingTime sets the timer to start transactions. This will be the starting time in logs.
func (c *Client) StartTrackingTime() {
	c.Transport.StartTrackingTime()
}

// StopTrackingTime stops the timer. When looking at logs, we will read up to this one.
func (c *Client) StopTrackingTime() {
	c.Transport.StopTrackingTime()
}
