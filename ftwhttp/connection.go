// Package ftwhttp provides low level abstractions for sending/receiving raw http messages
package ftwhttp

import (
	"bufio"
	"bytes"
	"errors"
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

func (c *Connection) receive() ([]byte, error) {
	log.Trace().Msg("ftw/http: receiving data")
	var err error
	var buf []byte

	// Set a deadline for reading. Read operation will fail if no data
	// is received after deadline.
	timeoutDuration := 1000 * time.Millisecond

	// We assume the response body can be handled in memory without problems
	// That's why we use io.ReadAll
	if err = c.connection.SetReadDeadline(time.Now().Add(timeoutDuration)); err == nil {
		buf, err = io.ReadAll(c.connection)
	}

	if neterr, ok := err.(net.Error); ok && !neterr.Timeout() {
		log.Error().Msgf("ftw/http: %s\n", err.Error())
	} else {
		err = nil
	}
	log.Trace().Msgf("ftw/http: received data - %q", buf)

	return buf, err
}

// Request will use all the inputs and send a raw http request to the destination
func (c *Connection) Request(request *Request) error {
	// Build request first, then connect and send, so timers are accurate
	data, err := buildRequest(request)
	if err != nil {
		log.Fatal().Msgf("ftw/http: fatal error building request: %s", err.Error())
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
	data, err := c.receive()

	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	reader := *bufio.NewReader(r)

	httpResponse, err := http.ReadResponse(&reader, nil)
	if err != nil {
		return nil, err
	}
	response := Response{
		RAW:    data,
		Parsed: *httpResponse,
	}
	return &response, err
}
