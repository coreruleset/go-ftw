package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

// NewClient initializes the http client, creating the cookiejar
func NewClient() *Client {
	// All users of cookiejar should import "golang.org/x/net/publicsuffix"
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal().Err(err)
	}
	c := &Client{
		Jar: jar,
		// default Timeout
		Timeout: 3 * time.Second,
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
		netConn, err = tls.DialWithDialer(&net.Dialer{Timeout: c.Timeout}, "tcp", hostPort, &tls.Config{})
	} else {
		netConn, err = net.DialTimeout("tcp", hostPort, c.Timeout)
	}

	if err == nil {
		c.Transport = &Connection{
			connection: netConn,
			protocol:   d.Protocol,
			duration:   NewRoundTripTime(),
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
	return c.Transport.GetRoundTripTime()
}
