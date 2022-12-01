package waflog

import (
	"bytes"
	"errors"
	"io"
	"regexp"

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

	fi, err := ll.logFile.Stat()
	if err != nil {
		log.Error().Caller().Msgf("cannot read file's size")
		return found
	}

	// Lines in modsec logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(ll.logFile, int(fi.Size()), backscannerOptions)
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

// CheckLogForMarker reads the log file and searches for a marker line.
// stageID is the ID of the current stage, which is part of the marker line
// readLimit is the maximum numbers of lines to check
func (ll *FTWLogLines) CheckLogForMarker(stageID string, readLimit int) []byte {
	offset, err := ll.logFile.Seek(0, io.SeekEnd)
	if err != nil {
		log.Error().Caller().Err(err).Msgf("failed to seek end of log file")
		return nil
	}

	// Lines in logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(ll.logFile, int(offset), backscannerOptions)
	stageIDBytes := []byte(stageID)
	crsHeaderBytes := bytes.ToLower([]byte(ll.LogMarkerHeaderName))

	var line []byte
	lineCounter := 0
	// Look for the header until EOF or `readLimit` lines at most
	for {
		if lineCounter > readLimit {
			log.Debug().Msg("aborting search for marker")
			return nil
		}
		lineCounter++

		line, _, err = scanner.LineBytes()
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Trace().Err(err).Msg("found EOF while looking for log marker")
				return nil
			} else {
				log.Error().Err(err).Msg("failed to inspect next log line for marker")
				return nil
			}
		}

		line = bytes.ToLower(line)
		if bytes.Contains(line, crsHeaderBytes) {
			break
		}
	}

	// Found the header, now the line should also match the stage ID
	if bytes.Contains(line, stageIDBytes) {
		return line
	}

	log.Debug().Msgf("found unexpected marker line while looking for %s: %s", stageID, line)
	return nil
}
