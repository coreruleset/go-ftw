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

// FTWHTTPConnection is the type used for sending/receiving data
type FTWHTTPConnection struct {
	netConn  net.Conn
	tlsConn  *tls.Conn
	protocol string
	duration *FTWHTTPTransactionTime
	request  *FTWHTTPRequest
	response *FTWHTTPResponse
	err      error
}

//FTWHTTPTransactionTime abstracts the time a transaction takes
type FTWHTTPTransactionTime struct {
	Begin time.Time
	End   time.Time
}

// FTWConnection is the interface method implement to send and receive data
type FTWConnection interface {
	send([]byte) (int, error)
	receive() ([]byte, error)
	getTrackedTime() *FTWHTTPTransactionTime
}

// FTWHTTPRequest represents a request
// No Defaults represents the previous "stop_magic" behavior
type FTWHTTPRequest struct {
	NoDefaults bool   `default:"false"`
	DestAddr   string `default:"localhost"`
	Port       int    `default:"80"`
	Method     string `default:"GET"`
	Protocol   string `default:"http"`
	Version    string `default:"HTTP/1.1"`
	URI        string `default:"/"`
	Headers    map[string]string
	Cookies    http.CookieJar
	Data       []byte
	Raw        []byte
	Encoded    string
}

// FTWHTTPResponse represents the http response received from the server/waf
type FTWHTTPResponse struct {
	RAW    []byte
	Parsed http.Response
}

func (f *FTWHTTPConnection) startTracking() {
	f.duration = &FTWHTTPTransactionTime{
		Begin: time.Now(),
		End:   time.Now(),
	}
}

func (f *FTWHTTPConnection) stopTracking() {
	f.duration.End = time.Now()
}

// GetTrackedTime will return the time since the request started and the response was parsed
func (f *FTWHTTPConnection) GetTrackedTime() *FTWHTTPTransactionTime {
	return f.duration
}

func (f *FTWHTTPConnection) send(data []byte) (int, error) {
	var err error
	var sent int

	log.Debug().Msg("ftw/http: sending data")
	// Store times for searching in logs, if necessary
	f.startTracking()

	switch f.protocol {
	case "http":
		if f.netConn != nil {
			sent, err = f.netConn.Write(data)
		} else {
			err = errors.New("ftw/http: http selected but not connected to http")
		}
	case "https":
		if f.tlsConn != nil {
			sent, err = f.tlsConn.Write(data)
		} else {
			err = errors.New("ftw/http: https selected but not connected to https")
		}
	default:
		err = fmt.Errorf("ftw/http: unsupported protocol %s", f.protocol)
	}

	return sent, err

}

func (f *FTWHTTPConnection) receive() ([]byte, error) {
	log.Debug().Msg("ftw/http: receiving data")
	var err error
	var buf []byte

	// Set a deadline for reading. Read operation will fail if no data
	// is received after deadline.
	timeoutDuration := 100 * time.Millisecond

	// We assume the response body can be handled in memory without problems
	// That's why we use ioutil.ReadAll
	switch f.protocol {
	case "https":
		defer f.tlsConn.Close()
		buf, err = ioutil.ReadAll(f.tlsConn)
	default:
		defer f.netConn.Close()
		f.netConn.SetReadDeadline(time.Now().Add(timeoutDuration))
		buf, err = ioutil.ReadAll(f.netConn)
	}
	if err != nil && !strings.Contains(err.Error(), "i/o timeout") {
		log.Fatal().Msgf("ftw/http: %s\n", err.Error())
	}
	log.Debug().Msgf("ftw/http: received data - %q", buf)
	f.stopTracking()

	return buf, nil
}

// All users of cookiejar should import "golang.org/x/net/publicsuffix"
// jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
// if err != nil {
// 	log.Fatal(err)
// }
