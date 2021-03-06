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
	log.Debug().Msgf("ftw/waflog: Looking at file %s, between %s and %s", ll.FileName, ll.Since, ll.Until)
	// this should be a flag
	lines := ll.getLinesSinceUntil()
	log.Debug().Msgf("ftw/waflog: got %d lines", len(lines))

	result := false
	for _, line := range lines {
		log.Debug().Msgf("ftw/waflog: Matching %s in %s", match, line)
		got, err := regexp.Match(match, line)
		if err != nil {
			log.Fatal().Msgf("ftw/waflog: bad regexp %s", err.Error())
		}
		if got {
			log.Debug().Msgf("ftw/waflog: Found %s at %s", match, line)
			result = true
			break
		}
	}
	return result
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
	for {
		line, _, err := scanner.LineBytes()
		if err != nil {
			if err == io.EOF {
				log.Debug().Msgf("got to the beginning of file")
			} else {
				log.Debug().Err(err)
			}
			break
		}
		if matchedLine := compiledRegex.FindSubmatch(line); matchedLine != nil {
			date := matchedLine[1]
			// well, go doesn't want to have a proper time format, so we need to use gostradamus
			t, err := gostradamus.Parse(string(date), ll.TimeFormat)
			if err != nil {
				log.Error().Msgf("ftw/waflog: %s", err.Error())
				// return with what we got up to now
				break
			}
			// compare dates now
			if t.IsBetween(gostradamus.DateTimeFromTime(ll.Since), gostradamus.DateTimeFromTime(ll.Until)) {
				saneCopy := make([]byte, len(line))
				copy(saneCopy, line)
				found = append(found, saneCopy)
				continue
			}
			// if we are before since, we need to stop searching
			if t.IsBetween(gostradamus.DateTimeFromTime(time.Time{}), gostradamus.DateTimeFromTime(ll.Since)) {
				break
			}
		}

	}
	return found
}
