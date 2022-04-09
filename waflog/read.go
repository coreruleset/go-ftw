package waflog

import (
	"bytes"
	"io"
	"os"
	"regexp"

	"github.com/fzipi/go-ftw/config"
	"github.com/icza/backscanner"
	"github.com/rs/zerolog/log"
)

// Contains looks in logfile for regex
func (ll *FTWLogLines) Contains(match string) bool {
	// this should be a flag
	lines := ll.getMarkedLines()
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

func (ll *FTWLogLines) getMarkedLines() [][]byte {
	var found [][]byte
	logfile, err := os.Open(ll.FileName)

	if err != nil {
		log.Fatal().Caller().Msgf("cannot open file %s", ll.FileName)
	}
	defer logfile.Close()

	fi, err := logfile.Stat()
	if err != nil {
		log.Error().Caller().Msgf("cannot read file's size")
		return found
	}

	// Lines in modsec logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(logfile, int(fi.Size()), backscannerOptions)
	endFound := false
	// end marker is the *first* marker when reading backwards,
	// start marker is the *last* marker
	for {
		line, _, err := scanner.LineBytes()
		if err != nil {
			if err != io.EOF {
				log.Trace().Err(err)
			}
			break
		}
		lineLower := bytes.ToLower(line)
		if !endFound && bytes.Equal(lineLower, ll.EndMarker) {
			endFound = true
			continue
		}
		if endFound && bytes.Equal(lineLower, ll.StartMarker) {
			break
		}

		saneCopy := make([]byte, len(line))
		copy(saneCopy, line)
		found = append(found, saneCopy)
	}
	return found
}

func (ll *FTWLogLines) CheckLogForMarker(stageId string) []byte {
	logfile, err := os.Open(ll.FileName)

	if err != nil {
		log.Error().Caller().Err(err).Msg("failed to open file")
		return nil
	}
	defer logfile.Close()

	fi, err := logfile.Stat()
	if err != nil {
		log.Error().Caller().Err(err).Msgf("cannot read file's size")
		return nil
	}

	// Lines in modsec logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(logfile, int(fi.Size()), backscannerOptions)
	stageIdBytes := []byte(stageId)
	crsHeaderBytes := bytes.ToLower([]byte(config.FTWConfig.LogMarkerHeaderName))

	line := []byte{}
	// find the last non-empty line
	for err == nil && len(line) == 0 {
		line, _, err = scanner.LineBytes()
	}
	if err != nil {
		if err == io.EOF {
			return nil
		} else {
			log.Trace().Err(err)
		}
	}
	line = bytes.ToLower(line)
	if bytes.Contains(line, crsHeaderBytes) && bytes.Contains(line, stageIdBytes) {
		return line
	}

	return nil
}
