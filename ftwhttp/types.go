// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

import (
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// ClientConfig provides configuration options for the HTTP client.
type ClientConfig struct {
	// ConnectTimeout is the timeout for connecting to a server.
	ConnectTimeout time.Duration
	// ReadTimeout is the timeout for reading a response.
	ReadTimeout time.Duration
	// RootCAs is the set of root CA certificates that is used to verify server
	RootCAs *x509.CertPool
	// RateLimiter is the rate limiter to use for requests.
	RateLimiter *rate.Limiter
}

// Client is the top level abstraction in http
type Client struct {
	Transport *Connection
	Jar       http.CookieJar
	config    ClientConfig
}

// Connection is the type used for sending/receiving data
type Connection struct {
	connection  net.Conn
	protocol    string
	readTimeout time.Duration
	duration    *RoundTripTime
}

// RoundTripTime abstracts the time a transaction takes
type RoundTripTime struct {
	begin time.Time
	end   time.Time
}

// FTWConnection is the interface method implement to send and receive data
type FTWConnection interface {
	Request(*Request)
	Response(*Response)
	GetTrackedTime() *RoundTripTime
	send([]byte) (int, error)
	receive() ([]byte, error)
}

// Destination is the host, port and protocol to be used when connecting to a remote host
type Destination struct {
	DestAddr string `default:"localhost"`
	Port     int    `default:"80"`
	Protocol string `default:"http"`
}

// RequestLine is the first line in the HTTP request dialog
type RequestLine struct {
	Method  string `default:"GET"`
	Version string `default:"HTTP/1.1"`
	URI     string `default:"/"`
}

// Request represents a request
// This struct without defaults represents the previous "autocomplete headers" behavior
type Request struct {
	requestLine         *RequestLine
	headers             *Header
	cookies             http.CookieJar
	data                []byte
	autoCompleteHeaders bool
	isRaw               bool
	rawRequest          []byte
}

// Response represents the http response received from the server/waf
type Response struct {
	RAW    []byte
	Parsed http.Response
}
