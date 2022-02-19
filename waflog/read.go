package waflog

import (
	"io"
	"os"
	"regexp"
	"time"

	"github.com/bykof/gostradamus"
	"github.com/icza/backscanner"
	"github.com/rs/zerolog/log"
)

// Contains looks in logfile for regex
func (ll *FTWLogLines) Contains(match string) bool {
	// this should be a flag
	lines := ll.getLinesSinceUntil()
	// if we need to truncate file
	if ll.LogTruncate {
		ll.truncateLogFile()
	}
	log.Trace().Msgf("ftw/waflog: got %d lines", len(lines))

	result := false
	for _, line := range lines {
		log.Trace().Msgf("ftw/waflog: Matching %s in %s", match, line)
		got, err := regexp.Match(match, line)
		if err != nil {
			log.Fatal().Msgf("ftw/waflog: bad regexp %s", err.Error())
		}
		if got {
			log.Trace().Msgf("ftw/waflog: Found %s at %s", match, line)
			result = true
			break
		}
	}
	return result
}

func isBetweenOrEqual(dt gostradamus.DateTime, start gostradamus.DateTime, end gostradamus.DateTime, duration time.Duration) bool {
	// First check if we need to truncate times
	dtTime := dt.Time().Truncate(duration)
	startTime := start.Time().Truncate(duration)
	endTime := end.Time().Truncate(duration)

	isBetween := dtTime.After(startTime) && dtTime.Before(endTime)

	isEqualStart := dtTime.Equal(startTime)

	isEqualEnd := dtTime.Equal(endTime)

	return isBetween || isEqualStart || isEqualEnd
}

func (ll *FTWLogLines) getLinesSinceUntil() [][]byte {
	var found [][]byte
	logfile, err := os.Open(ll.FileName)

	if err != nil {
		log.Fatal().Msgf("cannot open file %s", ll.FileName)
	}
	defer logfile.Close()

	fi, err := logfile.Stat()
	if err != nil {
		log.Error().Msgf("cannot read file's size")
		return found
	}

	compiledRegex := regexp.MustCompile(ll.TimeRegex)

	// Lines in modsec logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(logfile, int(fi.Size()), backscannerOptions)
	tzonename := time.Now().Location()
	tzone := gostradamus.Timezone(tzonename.String())
	for {
		line, _, err := scanner.LineBytes()
		if err != nil {
			if err != io.EOF {
				log.Trace().Err(err)
			}
			break
		}
		if matchedLine := compiledRegex.FindSubmatch(line); matchedLine != nil {
			date := matchedLine[1]
			// well, go doesn't want to have a proper time format, so we need to use gostradamus
			t, err := gostradamus.ParseInTimezone(string(date), ll.TimeFormat, tzone)
			if err != nil {
				log.Error().Msgf("ftw/waflog: error parsing date %s", err.Error())
				// return with what we got up to now
				break
			}
			// compare dates now
			// use the same timezone for all
			dt := t.InTimezone(gostradamus.Local())
			since := gostradamus.DateTimeFromTime(ll.Since).InTimezone(gostradamus.Local())
			until := gostradamus.DateTimeFromTime(ll.Until).InTimezone(gostradamus.Local())
			// Comparision will need to truncate
			if isBetweenOrEqual(dt, since, until, ll.TimeTruncate) {
				saneCopy := make([]byte, len(line))
				copy(saneCopy, line)
				found = append(found, saneCopy)
				continue
			}
			// if we are before since, we need to stop searching
			if dt.IsBetween(gostradamus.DateTimeFromTime(time.Time{}).InTimezone(gostradamus.Local()),
				since) {
				break
			}
		}

	}
	return found
}

// truncateLogFile
func (ll *FTWLogLines) truncateLogFile() {
	err := os.Truncate(ll.FileName, 0)

	if err != nil {
		log.Fatal().Msgf("ftw/waflong: cannot truncate file %s. Check if you have permissions!", ll.FileName)
	}
}
