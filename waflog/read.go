// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"slices"

	"github.com/icza/backscanner"
	"github.com/rs/zerolog/log"
)

const maxRuleIdsEstimate = 15

var ruleIdsSet = make(map[uint]struct{}, maxRuleIdsEstimate)

// These regexes provide flexibility in parsing how the rule ID is logged.
//   - [id "999999"]
//   - [id \"999999\"] (escaped quotes)
//   - ["id":"999999"]
//   - [\"id\":\"999999\"] (escaped quotes)
var stdLogIdRegex = regexp.MustCompile(`\[(?:id |\\?"id\\?":)\\?"(\d+)\\?"\]`)

// - {"id":4}
// - {..., "id":4,..}
// - {"ruleId":"4"}
// - {..., "ruleId":"4",...}
var jsonLogIdRegex = regexp.MustCompile(`(?:\{|,)\s*"(?:id|ruleId)":\s*"?(\d+)"?`)

// TriggeredRules returns the IDs of all the rules found in the log for the current test
func (ll *FTWLogLines) TriggeredRules() ([]uint, error) {
	if ll.triggeredRulesInitialized {
		return ll.triggeredRules, nil
	}

	lines, err := ll.GetMarkedLines()
	if err != nil {
		return nil, err
	}
	if err := ll.computeTriggeredRules(lines); err != nil {
		return nil, err
	}

	ll.triggeredRulesInitialized = true
	return ll.triggeredRules, nil
}

func (ll *FTWLogLines) computeTriggeredRules(lines [][]byte) error {
	lineMatcher := ll.matchLine
	if ll.customLogIdRegex != nil {
		lineMatcher = ll.matchLineCustom
	}
	for _, line := range lines {
		log.Trace().Msgf("ftw/waflog: Looking for any rule in '%s'", line)
		match := lineMatcher(line)
		for _, nextMatch := range match {
			submatchBytes := nextMatch[1]
			if len(submatchBytes) == 0 {
				continue
			}
			submatch := string(submatchBytes)
			ruleId, err := strconv.ParseUint(submatch, 10, 0)
			if err != nil {
				log.Error().Caller().Msgf("Failed to parse uint from %s", submatch)
				continue
			}
			log.Trace().Msgf("ftw/waflog: Found '%d' at '%s'", ruleId, line)
			ruleIdsSet[uint(ruleId)] = struct{}{}
		}
	}
	ruleIds := make([]uint, 0, len(ruleIdsSet))
	for ruleId := range ruleIdsSet {
		ruleIds = append(ruleIds, ruleId)
	}
	slices.Sort(ruleIds)
	ll.triggeredRules = ruleIds
	// Reset map for next use
	for key := range ruleIdsSet {
		delete(ruleIdsSet, key)
	}

	return nil
}

func (ll *FTWLogLines) matchLine(line []byte) [][][]byte {
	match := stdLogIdRegex.FindAllSubmatch(line, -1)
	if match == nil {
		match = jsonLogIdRegex.FindAllSubmatch(line, -1)
	}

	return match
}

func (ll *FTWLogLines) matchLineCustom(line []byte) [][][]byte {
	return ll.customLogIdRegex.FindAllSubmatch(line, -1)
}

// ContainsAllIds returns true if all of the specified rule IDs appear in the log for the current test.
// The IDs of all the IDs that were *not* found will be the second return value.
func (ll *FTWLogLines) ContainsAllIds(ids []uint) (bool, []uint, error) {
	foundRuleIds, err := ll.TriggeredRules()
	if err != nil {
		return false, nil, err
	}
	missedRules := []uint{}
	for _, id := range ids {
		if !slices.Contains(foundRuleIds, id) {
			missedRules = append(missedRules, id)
		}
	}
	if len(missedRules) > 0 {
		return false, missedRules, nil
	}
	return true, missedRules, nil
}

// ContainsAnyId returns true if at least one of the specified IDs appears in the log for the current test.
// The IDs of all the IDs that were found will be the second return value.
func (ll *FTWLogLines) ContainsAnyId(ids []uint) (bool, []uint, error) {
	foundRuleIds, err := ll.TriggeredRules()
	if err != nil {
		return false, nil, err
	}
	foundAndExpected := []uint{}
	found := false
	for _, id := range ids {
		if slices.Contains(foundRuleIds, id) {
			log.Trace().Msgf("Found rule ID %d in log", id)
			found = true
			foundAndExpected = append(foundAndExpected, id)
		}
	}
	return found, foundAndExpected, nil
}

// MatchesRegex returns true if the regular expression pattern matches any of the lines in the log
// for the current test
func (ll *FTWLogLines) MatchesRegex(pattern string) (bool, error) {
	lines, err := ll.GetMarkedLines()
	if err != nil {
		return false, err
	}
	log.Trace().Msgf("ftw/waflog: got %d lines", len(lines))

	result := false
	for _, line := range lines {
		log.Trace().Msgf("ftw/waflog: Matching '%s' in '%s'", pattern, line)
		found, err := regexp.Match(pattern, line)
		if err != nil {
			return false, fmt.Errorf("ftw/waflog: bad regexp %s", err.Error())
		}
		if found {
			log.Trace().Msgf("ftw/waflog: Found '%s' at '%s'", pattern, line)
			result = true
			break
		}
	}
	return result, nil
}

func (ll *FTWLogLines) GetMarkedLines() ([][]byte, error) {
	if ll.markedLinesInitialized {
		return ll.markedLines, nil
	}
	log.Trace().Msg("Collecting marked lines")

	if len(ll.startMarker) == 0 || len(ll.endMarker) == 0 {
		return nil, errors.New("both start and end marker must be set before the log can be inspected")
	}

	if bytes.Equal(ll.startMarker, ll.endMarker) {
		return nil, fmt.Errorf("start and end markers must be different. %q", ll.startMarker)
	}

	if err := ll.computeMarkedLines(); err != nil {
		return nil, err
	}
	ll.markedLinesInitialized = true
	return ll.markedLines, nil
}

func (ll *FTWLogLines) computeMarkedLines() error {
	fileInfo, err := ll.logFile.Stat()
	if err != nil {
		log.Error().Caller().Msg("cannot read file's size")
		return err
	}

	// Lines in modsec logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(ll.logFile, int(fileInfo.Size()), backscannerOptions)
	startFound := false
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

		if !endFound {
			// Skip lines until we find the end marker. Reading backwards, the lines we are looking for are
			// between the end and start markers.
			if bytes.Equal(lineLower, ll.endMarker) {
				endFound = true
			}
			continue
		}
		if endFound && bytes.Equal(lineLower, ll.endMarker) {
			// Found a duplicate end marker. This can happen when we force log
			// flushing through `markAndFlush()`, where we resend the end marker until
			// we see it in the log.

			// As we pretty much control the log, we don't need to clear any
			// log lines that could, technically, occur between two consecutive
			// end markers.
			log.Trace().Msg("Skipping duplicate end marker")
			continue
		} else if endFound && bytes.Equal(lineLower, ll.startMarker) {
			startFound = true
			break
		}

		saneCopy := make([]byte, len(line))
		copy(saneCopy, line)
		ll.markedLines = append(ll.markedLines, saneCopy)
	}
	if !startFound {
		log.Debug().Msg("start marker not found while collecting marked lines")
	}

	// Reverse the order to restore original log order
	slices.Reverse(ll.markedLines)

	log.Trace().Msgf("Found %d log lines: %s\n", len(ll.markedLines), bytes.Join(ll.markedLines, []byte{'\n'}))
	return nil
}

// CheckLogForMarker reads the log file and searches for a marker line.
// markerId is the ID of the current stage + suffix (for start / end), which is part of the marker line
// readLimit is the maximum numbers of lines to check
func (ll *FTWLogLines) CheckLogForMarker(markerId string, readLimit uint) []byte {
	offset, err := ll.logFile.Seek(0, io.SeekEnd)
	if err != nil {
		log.Error().Caller().Err(err).Msg("failed to seek end of log file")
		return nil
	}

	// Lines in logging can be quite large
	backscannerOptions := &backscanner.Options{
		ChunkSize: 4096,
	}
	scanner := backscanner.NewOptions(ll.logFile, int(offset), backscannerOptions)
	stageIDBytes := []byte(markerId)
	crsHeaderBytes := bytes.ToLower([]byte(ll.LogMarkerHeaderName))

	var line []byte
	lineCounter := uint(0)
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
	log.Debug().Msgf("found unexpected marker line while looking for %s: %s", markerId, line)
	return nil
}
