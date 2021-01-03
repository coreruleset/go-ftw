package http

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Connection is the type used for sending/receiving data
type Connection struct {
	netConn  net.Conn
	tlsConn  *tls.Conn
	protocol string
	duration *TransactionTime
	err      error
}

// TransactionTime abstracts the time a transaction takes
type TransactionTime struct {
	Begin time.Time
	End   time.Time
}

// FTWConnection is the interface method implement to send and receive data
type FTWConnection interface {
	Request(*Request)
	Response(*Response)
	GetTrackedTime() *TransactionTime
	send([]byte) (int, error)
	receive() ([]byte, error)
}

// Response represents the http response received from the server/waf
type Response struct {
	RAW    []byte
	Parsed http.Response
}

func (c *Connection) startTracking() {
	c.duration = &TransactionTime{
		Begin: time.Now(),
		End:   time.Now(),
	}
}

func (c *Connection) stopTracking() {
	c.duration.End = time.Now()
}

// GetTrackedTime will return the time since the request started and the response was parsed
func (c *Connection) GetTrackedTime() *TransactionTime {
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
	timeoutDuration := 100 * time.Millisecond

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
	if err != nil && !strings.Contains(err.Error(), "i/o timeout") {
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
