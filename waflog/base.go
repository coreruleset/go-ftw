package waflog

import (
	"time"
)

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	FileName string
	Since    time.Time
	Until    time.Time
}
