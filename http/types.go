package http

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Connection is the type used for sending/receiving data
type Connection struct {
	netConn  net.Conn
	tlsConn  *tls.Conn
	protocol string
	duration *RoundTripTime
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
