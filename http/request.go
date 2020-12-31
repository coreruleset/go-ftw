package http

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func connect(destination string, port int, protocol string) FTWHTTPConnection {
	var netConn net.Conn
	var tlsConn *tls.Conn
	var err error
	var conn *FTWHTTPConnection
	var timeout time.Duration

	hostPort := fmt.Sprintf("%s:%d", destination, port)
	timeout = 3 * time.Second

	// Fatal error: dial tcp 127.0.0.1:80: connect: connection refused
	// strings.HasSuffix(err.String(), "connection refused") {
	if strings.ToLower(protocol) == "https" {
		tlsConn, err = tls.Dial("tcp", hostPort, &tls.Config{InsecureSkipVerify: true})
		conn = &FTWHTTPConnection{netConn: netConn, tlsConn: tlsConn, protocol: "https", err: err}
	} else {
		netConn, err = net.DialTimeout("tcp", hostPort, timeout)
		conn = &FTWHTTPConnection{netConn: netConn, tlsConn: tlsConn, protocol: "http", err: err}
	}

	return *conn
}

// Request will use all the inputs and send a raw http request to the destination
func Request(request *FTWHTTPRequest) (FTWHTTPConnection, error) {
	// Build request first, then connect and send, so timers are accurate
	data, err := buildRequest(request)
	if err != nil {
		log.Fatal().Msgf("ftw/http: fatal error building request: %s", err.Error())
	}

	req := connect(request.DestAddr, request.Port, request.Protocol)

	if req.err != nil {
		log.Fatal().Msgf("ftw/http: fatal error connecting to %s:%d using %s -> %s", request.DestAddr, request.Port, request.Protocol, req.err.Error())
	}

	log.Debug().Msgf("ftw/http: sending data:\n%s", data)

	_, err = req.send(data)

	if err != nil {
		log.Fatal().Msgf("ftw/http: fatal error writing data: %s", err.Error())
	}

	return req, err
}

// The request should be created with anything we want. We want to actually break HTTP.
func buildRequest(request *FTWHTTPRequest) ([]byte, error) {
	var err error
	var b bytes.Buffer

	// Check if we need to create from all fields
	if len(request.Raw) == 0 && request.Encoded == "" {
		// Request line
		_, err = fmt.Fprintf(&b, "%s %s %s\r\n", request.Method, request.URI, request.Version)
		if err != nil {
			return nil, err
		}

		log.Debug().Msgf("ftw/http: this is data: %q, of len %d", request.Data, len(request.Data))
		// We need to add the remaining headers, unless "NoDefaults"
		if len(request.Data) > 0 && request.NoDefaults == false {
			// If there is no Content-Type, then we add one
			if _, found := request.Headers["Content-Type"]; !found {
				request.Headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
			// We need to url encode parameters in data
			if contentType, _ := request.Headers["Content-Type"]; contentType == "application/x-www-form-urlencoded" {
				if escapedData, _ := url.QueryUnescape(string(request.Data)); escapedData == string(request.Data) {
					log.Debug().Msgf("ftw/http: parsing data: %q", request.Data)
					queryString, err := url.ParseQuery(string(request.Data))
					if err != nil || emptyQueryValues(queryString) {
						log.Debug().Msgf("ftw/http: cannot parse or empty values in query string: %s", request.Data)
					} else {
						log.Debug().Msgf("ftw/http: this is the query string parsed: %+v", queryString)
						data := queryString.Encode()
						log.Debug().Msgf("ftw/http: encoded data to: %s", data)
						if data != string(request.Data) {
							// we need to encode data
							request.Data = []byte(data)
						}
					}
				}
			}
			if _, found := request.Headers["Content-Length"]; !found {
				request.Headers["Content-Length"] = fmt.Sprintf("%d", len(request.Data))
			}
		}

		// For better performance, we always close the connection (unless otherwise)
		if _, found := request.Headers["Connection"]; !found {
			request.Headers["Connection"] = "close"
		}

		// Write header lines now
		for name, value := range request.Headers {
			_, err = fmt.Fprintf(&b, "%s: %s\r\n", name, value)
			if err != nil {
				return nil, err
			}
		}

		// TODO: handle cookies
		// if c.Jar != nil {
		// 	for _, cookie := range c.Jar.Cookies(req.URL) {
		// 		req.AddCookie(cookie)
		// 	}
		// }

		// After headers, we need one blank line
		_, err = fmt.Fprintf(&b, "\r\n")

		// Now the body, if anything
		if len(request.Data) > 0 {
			_, err = fmt.Fprintf(&b, "%s", request.Data)
		}
	}

	// If Raw, just dump it
	if len(request.Raw) > 0 {
		log.Debug().Msgf("ftw/http: using RAW data")
		fmt.Fprintf(&b, "%s", request.Raw)
	}

	// if Encoded, first base64 decode, then dump
	if len(request.Encoded) > 0 {
		data, err := base64.StdEncoding.DecodeString(request.Encoded)
		if err != nil {
			return nil, err
		}
		log.Debug().Msgf("ftw/http: using Base64 Encoded data")
		fmt.Fprintf(&b, "%s", data)
	}

	return b.Bytes(), err
}

// If the values are empty in the map, then don't encode anythin
// This keeps the compatibility with the python implementation
func emptyQueryValues(values url.Values) bool {
	for _, val := range values {
		if len(val) > 1 {
			return false
		}
	}
	return true
}
