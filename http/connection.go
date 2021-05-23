// Package http provides low level abstractions for sending/receiving raw http messages
package http

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// NewConnection creates a new Connection based on a Destination
func NewConnection(d Destination) (*Connection, error) {
	var netConn net.Conn
	var tlsConn *tls.Conn
	var err error
	var timeout time.Duration

	hostPort := fmt.Sprintf("%s:%d", d.DestAddr, d.Port)
	timeout = 3 * time.Second

	// Fatal error: dial tcp 127.0.0.1:80: connect: connection refused
	// strings.HasSuffix(err.String(), "connection refused") {
	if strings.ToLower(d.Protocol) == "https" {
		// Commenting InsecureSkipVerify: true.
		tlsConn, err = tls.Dial("tcp", hostPort, &tls.Config{})
	} else {
		netConn, err = net.DialTimeout("tcp", hostPort, timeout)
	}
	c := &Connection{
		netConn:  netConn,
		tlsConn:  tlsConn,
		protocol: d.Protocol,
		duration: NewRoundTripTime(),
	}

	return c, err
}

// DestinationFromString create a Destination from String
func DestinationFromString(urlString string) *Destination {
	u, _ := url.Parse(urlString)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)

	d := &Destination{
		Port:     p,
		DestAddr: host,
		Protocol: u.Scheme,
	}

	return d
}

func (c *Connection) startTracking() {
	c.duration.StartTracking()
}

func (c *Connection) stopTracking() {
	c.duration.StopTracking()
}

// GetRoundTripTime will return the time since the request started and the response was parsed
func (c *Connection) GetRoundTripTime() *RoundTripTime {
	return c.duration
}

func (c *Connection) send(data []byte) (int, error) {
	var err error
	var sent int

	log.Debug().Msg("ftw/http: sending data")
	// Store times for searching in logs, if necessary
	c.startTracking()

	switch c.protocol {
	case "http":
		if c.netConn != nil {
			sent, err = c.netConn.Write(data)
		} else {
			err = errors.New("ftw/http: http selected but not connected to http")
		}
	case "https":
		if c.tlsConn != nil {
			sent, err = c.tlsConn.Write(data)
		} else {
			err = errors.New("ftw/http: https selected but not connected to https")
		}
	default:
		err = fmt.Errorf("ftw/http: unsupported protocol %s", c.protocol)
	}

	return sent, err

}

func (c *Connection) receive() ([]byte, error) {
	log.Debug().Msg("ftw/http: receiving data")
	var err error
	var buf []byte

	// Set a deadline for reading. Read operation will fail if no data
	// is received after deadline.
	timeoutDuration := 1000 * time.Millisecond

	// We assume the response body can be handled in memory without problems
	// That's why we use ioutil.ReadAll
	switch c.protocol {
	case "https":
		defer c.tlsConn.Close()
		if err = c.tlsConn.SetReadDeadline(time.Now().Add(timeoutDuration)); err == nil {
			buf, err = ioutil.ReadAll(c.tlsConn)
		}
	default:
		defer c.netConn.Close()
		if err = c.netConn.SetReadDeadline(time.Now().Add(timeoutDuration)); err == nil {
			buf, err = ioutil.ReadAll(c.netConn)
		}
	}
	if neterr, ok := err.(net.Error); ok && !neterr.Timeout() {
		log.Error().Msgf("ftw/http: %s\n", err.Error())
	} else {
		err = nil
	}
	log.Trace().Msgf("ftw/http: received data - %q", buf)
	c.stopTracking()

	return buf, err
}

// All users of cookiejar should import "golang.org/x/net/publicsuffix"
// jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
// if err != nil {
// 	log.Fatal(err)
// }
