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

// SearchLogContains looks in logfile for regex
func SearchLogContains(match string, ll *FTWLogLines) bool {
	log.Debug().Msgf("ftw/waflog: Looking at file %s, between %s and %s", ll.FileName, ll.Since, ll.Until)
	// this should be a flag
	lines := getLinesSinceUntil(ll)
	log.Debug().Msgf("ftw/waflog: got %d lines", len(lines))

	result := false
	for _, line := range lines {
		log.Debug().Msgf("ftw/waflog: Matching %s in %s", match, line)
		got, err := regexp.Match(match, line)
		if err != nil {
			log.Fatal().Msgf("ftw/waflog: %s", err.Error())
		}
		if got {
			result = true
			break
		}
	}
	return result
}

func getLinesSinceUntil(f *FTWLogLines) [][]byte {
	var found [][]byte
	logfile, err := os.Open(f.FileName)

	if err != nil {
		log.Fatal().Msgf("cannot open file %s", f.FileName)
	}
	defer logfile.Close()

	fi, err := logfile.Stat()
	if err != nil {
		log.Error().Msgf("cannot read file's size")
		return found
	}

	compiledRegex := regexp.MustCompile(f.TimeRegex)

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
			t, err := gostradamus.Parse(string(date), f.TimeFormat)
			if err != nil {
				log.Error().Msgf("ftw/waflog: %s", err.Error())
				// return with what we got up to now
				break
			}
			// compare dates now
			if t.IsBetween(gostradamus.DateTimeFromTime(f.Since), gostradamus.DateTimeFromTime(f.Until)) {
				saneCopy := make([]byte, len(line))
				copy(saneCopy, line)
				found = append(found, saneCopy)
				continue
			}
			// if we are before since, we need to stop searching
			if t.IsBetween(gostradamus.DateTimeFromTime(time.Time{}), gostradamus.DateTimeFromTime(f.Since)) {
				break
			}
		}

	}
	return found
}
