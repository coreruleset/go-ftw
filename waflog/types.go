// Package waflog is responsible for getting logs from a WAF to compare with expected results
package waflog

// FTWLogLines represents the filename to search for logs in a certain timespan
type FTWLogLines struct {
	FileName    string
	StartMarker []byte
	EndMarker   []byte
}
