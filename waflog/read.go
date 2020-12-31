package waflog

import (
	"io"
	"os"
	"regexp"
	"time"

	config "ftw/config"

	"github.com/bykof/gostradamus"
	"github.com/icza/backscanner"
	"github.com/rs/zerolog/log"
)

// SearchLogContains looks in logfile for regex
func SearchLogContains(match string, ll *FTWLogLines) bool {
	log.Debug().Msgf("ftw/waflog: Looking at file %s, between %s and %s", ll.FileName, ll.Since, ll.Until)
	// this should be a flag
	lines := getLinesSinceUntil(ll, config.FTWConfig.LogType.TimeRegex)
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

func getLinesSinceUntil(f *FTWLogLines, timeRegex string) [][]byte {
	var found [][]byte
	logfile, err := os.Open(f.FileName)

	if err != nil {
		log.Fatal().Msgf("cannot open file %s", f.FileName)
	}
	defer logfile.Close()

	fi, err := logfile.Stat()
	if err != nil {
		log.Fatal().Msgf("cannot read file's size")
	}

	compiledRegex := regexp.MustCompile(timeRegex)

	// Lines in modsec logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(logfile, int(fi.Size()), backscannerOptions)
	for {
		line, _, err := scanner.LineBytes()
		if err != nil {
			if err == io.EOF {
				log.Debug().Msgf("got to the beggining of file")
			} else {
				log.Debug().Err(err)
			}
			break
		}
		if matchedLine := compiledRegex.FindSubmatch(line); matchedLine != nil {
			date := matchedLine[1]
			//log.Debug().Msgf("ftw/waflog: found line with date %q", date)
			// well, go doesn't want to have a proper time format, so we need to use gostradamus
			t, err := gostradamus.Parse(string(date), "ddd MMM DD HH:mm:ss.S YYYY")
			if err != nil {
				log.Fatal().Msgf("ftw/waflog: %s", err.Error())
			}
			//log.Debug().Msgf("ftw/waflog: parsed line with time %s", t)
			// compare dates now
			if t.IsBetween(gostradamus.DateTimeFromTime(f.Since), gostradamus.DateTimeFromTime(f.Until)) {
				//log.Debug().Msgf("ftw/waflog: found match at line position: %d, line: %s\n", pos, line)
				saneCopy := make([]byte, len(line))
				copy(saneCopy, line)
				found = append(found, saneCopy)
				continue
			}
			// if we are before since, we need to stop searching
			if t.IsBetween(gostradamus.DateTimeFromTime(time.Time{}), gostradamus.DateTimeFromTime(f.Since)) {
				//log.Debug().Msgf("ftw/waflog: no more lines found and we before the time since the request started")
				break
			}
		}

	}
	// for _, l := range found {
	// 	log.Debug().Msgf("ftw/waflog: \n<<<<<<\n<<<<<<\n%s\n<<<<<<\n<<<<<<\n", l)
	// }
	return found
}
