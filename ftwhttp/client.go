package ftwhttp

import (
	"crypto/tls"
	"fmt"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/http/cookiejar"
	"strings"
	"time"
)

// NewClientConfig returns a new ClientConfig with reasonable defaults.
func NewClientConfig() ClientConfig {
	return ClientConfig{
		ConnectTimeout: 3 * time.Second,
		ReadTimeout:    1 * time.Second,
	}
}

// NewClient initializes the http client, creating the cookiejar
func NewClient(config ClientConfig) *Client {
	// All users of cookiejar should import "golang.org/x/net/publicsuffix"
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal().Err(err)
	}
	c := &Client{
		Jar:    jar,
		config: config,
	}
	return c
}

// NewConnection creates a new Connection based on a Destination
func (c *Client) NewConnection(d Destination) error {
	var err error
	var netConn net.Conn

	hostPort := fmt.Sprintf("%s:%d", d.DestAddr, d.Port)

	// Fatal error: dial tcp 127.0.0.1:80: connect: connection refused
	// strings.HasSuffix(err.String(), "connection refused") {
	if strings.ToLower(d.Protocol) == "https" {
		// Commenting InsecureSkipVerify: true.
		netConn, err = tls.DialWithDialer(&net.Dialer{Timeout: c.config.ConnectTimeout}, "tcp", hostPort, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		netConn, err = net.DialTimeout("tcp", hostPort, c.config.ConnectTimeout)
	}

	if err == nil {
		c.Transport = &Connection{
			connection:  netConn,
			protocol:    d.Protocol,
			readTimeout: c.config.ReadTimeout,
			duration:    NewRoundTripTime(),
		}
	}

	return err
}

// Do performs the http request roundtrip
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
