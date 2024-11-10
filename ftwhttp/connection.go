// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package ftwhttp provides low level abstractions for sending/receiving raw http messages
package ftwhttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// DestinationFromString create a Destination from String
func DestinationFromString(urlString string) (*Destination, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)

	d := &Destination{
		Port:     p,
		DestAddr: host,
		Protocol: u.Scheme,
	}

	return d, nil
}

// StartTrackingTime initializes timer
func (c *Connection) StartTrackingTime() {
	c.duration.StartTracking()
}

// StopTrackingTime stops timer
func (c *Connection) StopTrackingTime() {
	c.duration.StopTracking()
}

// GetTrackedTime will return the time since the request started and the response was parsed
func (c *Connection) GetTrackedTime() *RoundTripTime {
	return c.duration
}

func (c *Connection) send(data []byte) (int, error) {
	var err error
	var sent int

	log.Trace().Msg("ftw/http: sending data")
	// Store times for searching in logs, if necessary

	if c.connection != nil {
		sent, err = c.connection.Write(data)
	} else {
		err = errors.New("ftw/http/send: not connected to server")
	}

	return sent, err

}

func (c *Connection) receive() (io.Reader, error) {
	log.Trace().Msg("ftw/http: receiving data")

	// We assume the response body can be handled in memory without problems
	// That's why we use io.ReadAll
	if err := c.connection.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
		return nil, err
	}

	return c.connection, nil
}

// Request will use all the inputs and send a raw http request to the destination
func (c *Connection) Request(request *Request) error {
	// Build request first, then connect and send, so timers are accurate
	data, err := BuildRequest(request)
	if err != nil {
		return fmt.Errorf("ftw/http: fatal error building request: %w", err)
	}

	log.Debug().Msgf("ftw/http: sending data:\n%s\n", data)

	_, err = c.send(data)

	if err != nil {
		log.Error().Msgf("ftw/http: error writing data: %s", err.Error())
	}

	return err
}

// Response reads the response sent by the WAF and return the corresponding struct
// It leverages the go stdlib for reading and parsing the response
func (c *Connection) Response() (*Response, error) {
	r, err := c.receive()

	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}

	reader := *bufio.NewReader(io.TeeReader(r, buf))

	httpResponse, err := http.ReadResponse(&reader, nil)
	if err != nil {
		return nil, err
	}

	data := buf.Bytes()
	log.Debug().Msgf("ftw/http: received data - %q", data)

	response := Response{
		RAW:    data,
		Parsed: *httpResponse,
	}
	return &response, err
}
