package check

import (
	"time"

	config "github.com/fzipi/go-ftw/config"
	waflog "github.com/fzipi/go-ftw/waflog"
)

// NoLogContains asd
func NoLogContains(notfound string, since time.Time, until time.Time) bool {
	return !LogContains(notfound, since, until)
}

// LogContains is the text in the log or not?
func LogContains(contains string, since time.Time, until time.Time) bool {
	logFile := waflog.FTWLogLines{
		FileName: config.FTWConfig.LogFile,
		Since:    since,
		Until:    until,
	}
	return waflog.SearchLogContains(contains, &logFile)
}
