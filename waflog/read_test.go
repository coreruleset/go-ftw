// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

type readTestSuite struct {
	suite.Suite
	filename string
}

func (s *readTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestReadTestSuite(t *testing.T) {
	suite.Run(t, new(readTestSuite))
}

func (s *readTestSuite) TearDownSuite() {
	os.Remove(s.filename)
}

func generateLogMarkers(ruleId uint, testId uint) (string, string) {
	utils.GenerateStageId(ruleId, testId)
	stageId := fmt.Sprintf("%d-%d-%s", ruleId, testId, uuid.NewString())
	return utils.CreateStartMarker(stageId), utils.CreateEndMarker(stageId)
}

func (s *readTestSuite) TestReadCheckLogForMarkerNoMarkerAtEnd() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMaker, endMarker := generateLogMarkers(10000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMaker
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + startMarkerLine + `
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
`
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	ll.WithStartMarker([]byte(startMarkerLine))
	marker := ll.CheckLogForMarker(startMaker, 100)
	s.Equal(string(marker), strings.ToLower(startMarkerLine), "unexpectedly missing start marker")
	marker = ll.CheckLogForMarker(endMarker, 100)
	s.Nil(marker, "unexpectedly found end marker")
}

func (s *readTestSuite) TestReadCheckLogForMarkerWithMarkerAtEnd() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(10000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + endMarkerLine
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	ll.WithStartMarker([]byte(startMarkerLine))
	s.Require().NoError(err)

	marker := ll.CheckLogForMarker(endMarker, 100)
	s.NotNil(marker, "no marker found")

	s.Equal(marker, bytes.ToLower([]byte(endMarkerLine)), "found unexpected marker")
}

// This test checks that the log lines are read correctly when the end marker is repeated multiple times.
// It can happen when the log is not flushed immediately, the end marker is not found in the first iteration, and therefore
// the end marker is produced multiple times in the log.
// Prior to using start and end markers, it might have been possible to use as log lines only the lines between the last two end markers.
func (s *readTestSuite) TestReadCheckLogForMarkerWithMultipleMarkersAtEnd() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
	[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
	[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s\n%s", startMarkerLine, logLinesOnly, endMarkerLine, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	ll.WithStartMarker(bytes.ToLower([]byte(startMarkerLine)))
	ll.WithEndMarker(bytes.ToLower([]byte(endMarkerLine)))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards, we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}
	// 4 lines are expected, 3 are the meaningful log lines (logLinesOnly), and the 4th is the repeat end marker.
	s.Len(foundLines, 4, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		s.Equalf(foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func (s *readTestSuite) TestReadGetMarkedLines() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s", startMarkerLine, logLinesOnly, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	ll.WithStartMarker(bytes.ToLower([]byte(startMarkerLine)))
	ll.WithEndMarker(bytes.ToLower([]byte(endMarkerLine)))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	s.Equal(len(foundLines), 3, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		s.Equalf(string(foundLines[index]), line, "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func (s *readTestSuite) TestReadGetMarkedLinesWithTrailingEmptyLines() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s\n\n\n", startMarkerLine, logLinesOnly, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	ll.WithStartMarker(bytes.ToLower([]byte(startMarkerLine)))
	ll.WithEndMarker(bytes.ToLower([]byte(endMarkerLine)))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	s.Len(foundLines, 3, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		s.Equalf(foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func (s *readTestSuite) TestReadGetMarkedLinesWithPrecedingLines() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	precedingLines :=
		`[Tue Jan 04 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
	[Tue Jan 04 02:22:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s\n%s\n", precedingLines, startMarkerLine, logLinesOnly, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	runnerConfig := config.NewRunnerConfiguration(cfg)

	ll, err := NewFTWLogLines(runnerConfig)
	s.Require().NoError(err)
	ll.WithStartMarker(bytes.ToLower([]byte(startMarkerLine)))
	ll.WithEndMarker(bytes.ToLower([]byte(endMarkerLine)))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	s.Len(foundLines, 3, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		s.Equalf(foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func (s *readTestSuite) TestFTWLogLines_Contains() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLines :=
		startMarkerLine +
			`
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + endMarkerLine
	s.filename, err = utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename
	log, err := os.Open(s.filename)
	s.Require().NoError(err)

	type fields struct {
		logFile             *os.File
		LogMarkerHeaderName []byte
		StartMarker         []byte
		EndMarker           []byte
	}
	f := fields{
		logFile:             log,
		LogMarkerHeaderName: []byte(cfg.LogMarkerHeaderName),
		StartMarker:         []byte(startMarkerLine),
		EndMarker:           []byte(endMarkerLine),
	}

	type args struct {
		match string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "Test contains element",
			fields: f,
			args: args{
				match: "AppleWebKit",
			},
			want: true,
		},
		{
			name:   "Test does not contain element",
			fields: f,
			args: args{
				match: "Something that does not exist",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			ll := &FTWLogLines{
				logFile:             tt.fields.logFile,
				LogMarkerHeaderName: bytes.ToLower(tt.fields.LogMarkerHeaderName),
			}
			ll.WithStartMarker(tt.fields.StartMarker)
			ll.WithEndMarker(tt.fields.EndMarker)
			got := ll.MatchesRegex(tt.args.match)
			s.Equalf(tt.want, got, "MatchesRegex() = %v, want %v", got, tt.want)
		})
	}
}

func (s *readTestSuite) TestFTWLogLines_ContainsIn404() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	markerLineStart := fmt.Sprint(`[2022-11-12 23:08:18.012572] [-:error] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 [client 127.0.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/apache/conf/httpd.conf_pod_2022-11-12_22:23"] [line "265"] [id "999999"] [msg "`,
		"X-cRs-TeSt ", startMarker,
		`"] [hostname "localhost"] [uri "/status/200"] [unique_id "Y3AZUo3Gja4gB-tPE9uasgAAAA4"]`)
	markerLineEnd := fmt.Sprint(`[2022-11-12 23:08:18.012580] [-:error] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 [client 127.0.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/apache/conf/httpd.conf_pod_2022-11-12_22:23"] [line "265"] [id "999999"] [msg "`,
		"X-cRs-TeSt ", endMarker,
		`"] [hostname "localhost"] [uri "/status/200"] [unique_id "Y3AZUo3Gja4gB-tPE9uasgBBBB4"]`)
	logLines := fmt.Sprint("\n", markerLineStart,
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`,
		`[2022-11-12 23:08:18.013007] [core:info] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 AH00128: File does not exist: /apache/htdocs/status/200`,
		"\n", markerLineEnd)
	filename, err := utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = filename
	log, err := os.Open(filename)
	s.Require().NoError(err)

	type fields struct {
		logFile             *os.File
		LogMarkerHeaderName []byte
		StartMarker         []byte
		EndMarker           []byte
	}
	f := fields{
		logFile:             log,
		LogMarkerHeaderName: []byte(cfg.LogMarkerHeaderName),
		StartMarker:         []byte(markerLineStart),
		EndMarker:           []byte(markerLineEnd),
	}

	type args struct {
		match string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "Test contains element",
			fields: f,
			args: args{
				match: "999999",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			ll := &FTWLogLines{
				logFile:             tt.fields.logFile,
				LogMarkerHeaderName: bytes.ToLower(tt.fields.LogMarkerHeaderName),
			}
			ll.WithStartMarker(tt.fields.StartMarker)
			ll.WithEndMarker(tt.fields.EndMarker)
			got := ll.MatchesRegex(tt.args.match)
			s.Equalf(tt.want, got, "Contains() = %v, want %v", got, tt.want)
		})
	}
}

func (s *readTestSuite) TestFTWLogLines_CheckForLogMarkerIn404() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)
	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := fmt.Sprint(`[2022-11-12 23:08:18.012572] [-:error] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 [client 127.0.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/apache/conf/httpd.conf_pod_2022-11-12_22:23"] [line "265"] [id "999999"] [msg "`,
		"X-cRs-TeSt ", startMarker,
		`"] [hostname "localhost"] [uri "/status/200"] [unique_id "Y3AZUo3Gja4gB-tPE9uasgAAAA4"]`)
	endMarkerLine := fmt.Sprint(`[2022-11-12 23:08:18.012572] [-:error] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 [client 127.0.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/apache/conf/httpd.conf_pod_2022-11-12_22:23"] [line "265"] [id "999999"] [msg "`,
		"X-cRs-TeSt ", endMarker,
		`"] [hostname "localhost"] [uri "/status/200"] [unique_id "Y3AZUo3Gja4gB-tPE9uasgAAAA4"]`)
	logLines := fmt.Sprint("\n", startMarkerLine,
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`,
		`[2022-11-12 23:08:18.013007] [core:info] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 AH00128: File does not exist: /apache/htdocs/status/200`,
		"\n", endMarkerLine)
	filename, err := utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = filename
	log, err := os.Open(filename)
	s.Require().NoError(err)

	ll := &FTWLogLines{
		logFile:             log,
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}
	ll.WithStartMarker([]byte(startMarkerLine))
	ll.WithEndMarker([]byte(endMarkerLine))
	foundMarker := ll.CheckLogForMarker(endMarker, 100)
	s.Equal(strings.ToLower(endMarkerLine), strings.ToLower(string(foundMarker)))
}

func (s *readTestSuite) TestFindAllIdsInLogs() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLines := fmt.Sprint("\n", startMarkerLine, "\n",
		`other stuff [id "1"] something else [id "2"]`, "\n",
		`other stuff {"blah": "bort,"id": 3}, something else {"id":5},`, "\n",
		`other stuff {"id": 6}, something else ["id":7],`, "\n",
		`other stuff something else [id \"8\"]`, "\n",
		"\n", endMarkerLine)
	filename, err := utils.CreateTempFileWithContent("", logLines, "test-errorlog-")

	s.Require().NoError(err)
	cfg.LogFile = filename
	log, err := os.Open(filename)
	s.Require().NoError(err)

	ll := &FTWLogLines{
		logFile:             log,
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}
	ll.WithStartMarker([]byte(startMarkerLine))
	ll.WithEndMarker([]byte(endMarkerLine))

	foundRuleIds := ll.TriggeredRules()
	s.Len(foundRuleIds, 6)
	s.Contains(foundRuleIds, uint(1))
	s.Contains(foundRuleIds, uint(2))
	s.Contains(foundRuleIds, uint(3))
	s.Contains(foundRuleIds, uint(5))
	s.Contains(foundRuleIds, uint(6))
	s.Contains(foundRuleIds, uint(8))
}

func (s *readTestSuite) TestFalsePositiveIds() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	startMarker, endMarker := generateLogMarkers(100000, 1)
	startMarkerLine := "X-cRs-TeSt: " + startMarker
	endMarkerLine := "X-cRs-TeSt: " + endMarker
	logLines := fmt.Sprint("\n", startMarkerLine, "\n",
		`2025/01/02 12:19:00 [info] 117#117: *16117 ModSecurity: Warning. Matched "Operator `,
		"`Rx' + with parameter `%u[4e00-9fa5]{3,}' against variable `TX:matched' (Value: `",
		`{"anonym":0,"key":"","sn":"","id":"168838233072272454","from":4,"token":"bridge"}' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "973"] [id "942370"] [rev ""] [msg "Detects classic SQL injection probings 2/3"] [data "Matched Data: \x22:\x22\x22,\x22 found within TX:matched: {\x22anonym\x22:0,\x22key\x22:\x22\x22,\x22sn\x22:\x22\x22,\x22id\x22:\x22168838233072272454\x22,\x22from\x22:4,\x22token\x22:\x22bridge\x22}"] [severity "2"] [ver "OWASP_CRS/3.3.2"] [maturity "0"] [accuracy "0"] [tag "modsecurity"] [tag "modsecurity"] [tag "modsecurity"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/66"] [tag "PCI/6.5.2"] [tag "paranoia-level/2"] [tag "CVE-2018-2380"] [tag "APP/SAP CRM"] [hostname "172.18.0.3"] [uri "/cps5/site/aust"] [unique_id "173582034044.678876"] [ref "o1,38v79,261t:urlDecodeUnio16,6v1542,81t:urlDecodeUnit:utf8toUnicode"], client: 172.18.0.1, server: localhost, request: "GET /cps5/site/aust?cb=jsonp_bridge_1688382331340_2474076564328216&op=0&s_info=%7B%22lang%22%3A%22zh-CN%22%2C%22cbit%22%3A24%2C%22rsl%22%3A%221920*1080%22%2C%22tz%22%3A%22UTC%2B8%3A0%22%2C%22xst%22%3A%22%22%2C%22referrer%22%3A%22https%253A%252F%252Fwww.baidu.com%252Flink%253Furl%253DPukzFxKXUAPWz2bGom-5-N5FroXNtyu0tc9pzXJz8ma%2526wd%253D%2526eqid%253Df68a4a19000c43c70000000464a2ab71%22%2C%22xstlink%22%3A%22http%253A%252F%252Fwww.authing.co%252F%22%7D&url=http%3A%2F%2Fwww.authing.co%2F&siteToken=fa8cc78cf376a0ce56fe3eeed5c06e5f&dev=0&ser=3&bst=1688382327210&AFDbiz=%7B%22ev%22%3A%22page_enter%22%2C%22customer%22%3A%2230208105%22%2C%22bid%22%3A%22168838233072272454%22%2C%22length%22%3A0%7D&AFDjt=31%24eyJrIj4iNyI0Iix5IkciQEZJSkZMR0lKSUxNUyJJIkFqIjwiNTs%2BPztBPD4%2FPkFCSCI%2BIjYzIlEiSlBTVFBWUTM0MzM3OCIzIit5IkYiQz9AIj4iOCJQIktHTklUIkoiaiI8IlQ%2Bd3VJS`,
		"\n",
		"\n", endMarkerLine)
	filename, err := utils.CreateTempFileWithContent("", logLines, "test-errorlog-")
	s.Require().NoError(err)
	cfg.LogFile = filename
	log, err := os.Open(filename)
	s.T().Cleanup(func() { _ = log.Close })
	s.Require().NoError(err)

	ll := &FTWLogLines{
		logFile:             log,
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}
	ll.WithStartMarker([]byte(startMarkerLine))
	ll.WithEndMarker([]byte(endMarkerLine))

	foundRuleIds := ll.TriggeredRules()
	s.Len(foundRuleIds, 1)
	s.Contains(foundRuleIds, uint(942370))
}
