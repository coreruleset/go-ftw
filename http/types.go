package http

import (
	"net"
	"net/http"
	"time"
)

// Client is the top level abstraction in http
type Client struct {
	Transport *Connection
	Jar       http.CookieJar
	Timeout   time.Duration
}

// Connection is the type used for sending/receiving data
type Connection struct {
	connection net.Conn
	protocol   string
	duration   *RoundTripTime
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

// Response represents the http response received from the server/waf
type Response struct {
	RAW    []byte
	Parsed http.Response
}
