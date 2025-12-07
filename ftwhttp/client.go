// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/cookiejar"
	"strings"
	"time"

	"fmt"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

func NewClientConfig() *ClientConfig {
	return &ClientConfig{
		ConnectTimeout:      3 * time.Second,
		ReadTimeout:         1 * time.Second,
		RateLimiter:         rate.NewLimiter(rate.Inf, 1),
		SkipTlsVerification: false,
	}
}

// NewClientConfig returns a new ClientConfig with reasonable defaults.
func NewClientConfigFromConfig(runnerConfig *config.RunnerConfig) *ClientConfig {
	config := NewClientConfig()
	if runnerConfig.ConnectTimeout != 0 {
		config.ConnectTimeout = runnerConfig.ConnectTimeout
	}
	if runnerConfig.ReadTimeout != 0 {
		config.ReadTimeout = runnerConfig.ReadTimeout
	}
	if runnerConfig.RateLimit != 0 {
		config.RateLimiter = rate.NewLimiter(rate.Every(runnerConfig.RateLimit), 1)
	}
	config.SkipTlsVerification = runnerConfig.SkipTlsVerification

	return config
}

// NewClient initializes the http client, creating the cookiejar
func NewClientWithConfig(config *ClientConfig) (*Client, error) {
	// All users of cookiejar should import "golang.org/x/net/publicsuffix"
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	c := &Client{
		Jar:    jar,
		config: *config,
	}
	return c, nil
}

// NewClient initializes the http client, creating the cookiejar
func NewClient(runnerConfig *config.RunnerConfig) (*Client, error) {
	return NewClientWithConfig(NewClientConfigFromConfig(runnerConfig))
}

// SetRootCAs sets the root CAs for the client.
// This can be used if you are using internal certificates and for testing purposes.
func (c *Client) SetRootCAs(cas *x509.CertPool) {
	c.config.RootCAs = cas
}

// SetRateLimiter sets the rate limiter for the client.
func (c *Client) SetRateLimiter(limiter *rate.Limiter) {
	c.config.RateLimiter = limiter
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
	hostPort := net.JoinHostPort(d.DestAddr, fmt.Sprint(d.Port))

	if strings.ToLower(d.Protocol) == "https" {
		return tls.DialWithDialer(
			&net.Dialer{
				Timeout: c.config.ConnectTimeout,
			},
			"tcp", hostPort,
			&tls.Config{
				MinVersion:         tls.VersionTLS12,
				RootCAs:            c.config.RootCAs,
				InsecureSkipVerify: c.config.SkipTlsVerification,
			})
	}

	return net.DialTimeout("tcp", hostPort, c.config.ConnectTimeout)
}

// Do perform the http request round trip.
func (c *Client) Do(req Request) (*Response, error) {
	var response *Response

	err := c.config.RateLimiter.Wait(context.Background()) // This is a blocking call. Honors the rate limit
	if err != nil {
		log.Error().Msgf("http/client: error waiting on rate limiter: %s\n", err.Error())
		return response, err
	}
	err = c.Transport.Request(&req)

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
