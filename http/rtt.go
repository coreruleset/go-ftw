package http

import "time"

// NewRoundTripTime initializes a roundtriptime struct
func NewRoundTripTime() *RoundTripTime {
	rtt := &RoundTripTime{
		begin: time.Now(),
		end:   time.Now(),
	}

	return rtt
}

// StartTracking sets the initial time to Now
func (rtt *RoundTripTime) StartTracking() {
	rtt.begin = time.Now()
}

// StopTracking sets the finish time to Now
func (rtt *RoundTripTime) StopTracking() {
	rtt.end = time.Now()
}

// StartTime returns the time when this round trip started
func (rtt *RoundTripTime) StartTime() time.Time {
	return rtt.begin
}

// StopTime returns the time when this round trip was stopped
func (rtt *RoundTripTime) StopTime() time.Time {
	return rtt.end
}

// RoundTripDuration gives the total time spent in this roundtrip
func (rtt *RoundTripTime) RoundTripDuration() time.Duration {
	return rtt.end.Sub(rtt.begin)
}
