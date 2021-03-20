// Package waflog is responsible for getting logs from a WAF to compare with expected results
package waflog

import (
	"time"
)

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	FileName  string
	TimeRegex string
	// Gostradamus time format, e.g. 'ddd MMM DD HH:mm:ss.S YYYY'
	TimeFormat string
	// Truncate time to this time.Duration. Example is nginx logs will be up to the second,
	// so you want to truncate using '1s'.
	TimeTruncate time.Duration
	Since        time.Time
	Until        time.Time
}
