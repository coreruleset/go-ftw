// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package waflog

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

type readTestSuite struct {
	suite.Suite
	filename string
}

func TestReadTestSuite(t *testing.T) {
	suite.Run(t, new(readTestSuite))
}

func (s *readTestSuite) TearDownSuite() {
	os.Remove(s.filename)
}

func (s *readTestSuite) TestReadCheckLogForMarkerNoMarkerAtEnd() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerLine + `
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
`
	s.filename, err = utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename

	ll, err := NewFTWLogLines(cfg)
	s.Require().NoError(err)
	ll.WithStartMarker([]byte(markerLine))
	marker := ll.CheckLogForMarker(stageID, 100)
	s.Equal(string(marker), strings.ToLower(markerLine), "unexpectedly found marker")
}

func (s *readTestSuite) TestReadCheckLogForMarkerWithMarkerAtEnd() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerLine
	s.filename, err = utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename

	ll, err := NewFTWLogLines(cfg)
	ll.WithStartMarker([]byte(markerLine))
	s.Require().NoError(err)

	marker := ll.CheckLogForMarker(stageID, 100)
	s.NotNil(marker, "no marker found")

	s.Equal(marker, bytes.ToLower([]byte(markerLine)), "found unexpected marker")
}

func (s *readTestSuite) TestReadGetMarkedLines() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	startMarkerLine := "X-cRs-TeSt: " + stageID + " -start"
	endMarkerLine := "X-cRs-TeSt: " + stageID + " -end"
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s", startMarkerLine, logLinesOnly, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename

	ll, err := NewFTWLogLines(cfg)
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

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	startMarkerLine := "X-cRs-TeSt: " + stageID + " -start"
	endMarkerLine := "X-cRs-TeSt: " + stageID + " -end"
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s\n\n\n", startMarkerLine, logLinesOnly, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename

	ll, err := NewFTWLogLines(cfg)
	s.Require().NoError(err)
	ll.WithStartMarker(bytes.ToLower([]byte(startMarkerLine)))
	ll.WithEndMarker(bytes.ToLower([]byte(endMarkerLine)))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	s.Len(foundLines, 6, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		s.Equalf(foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func (s *readTestSuite) TestReadGetMarkedLinesWithPrecedingLines() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	startMarkerLine := "X-cRs-TeSt: " + stageID + " -start"
	endMarkerLine := "X-cRs-TeSt: " + stageID + " -end"
	precedingLines :=
		`[Tue Jan 04 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
	[Tue Jan 04 02:22:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s\n%s\n", precedingLines, startMarkerLine, logLinesOnly, endMarkerLine)
	s.filename, err = utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = s.filename

	ll, err := NewFTWLogLines(cfg)
	s.Require().NoError(err)
	ll.WithStartMarker(bytes.ToLower([]byte(startMarkerLine)))
	ll.WithEndMarker(bytes.ToLower([]byte(endMarkerLine)))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	s.Len(foundLines, 4, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		s.Equalf(foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func (s *readTestSuite) TestFTWLogLines_Contains() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerLine
	s.filename, err = utils.CreateTempFileWithContent(logLines, "test-errorlog-")
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
		StartMarker:         []byte(markerLine),
		EndMarker:           []byte(markerLine),
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

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := fmt.Sprint(`[2022-11-12 23:08:18.012572] [-:error] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 [client 127.0.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/apache/conf/httpd.conf_pod_2022-11-12_22:23"] [line "265"] [id "999999"] [msg "`,
		"X-cRs-TeSt ", stageID,
		`"] [hostname "localhost"] [uri "/status/200"] [unique_id "Y3AZUo3Gja4gB-tPE9uasgAAAA4"]`)
	logLines := fmt.Sprint("\n", markerLine,
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`,
		`[2022-11-12 23:08:18.013007] [core:info] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 AH00128: File does not exist: /apache/htdocs/status/200`,
		"\n", markerLine)
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
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
		StartMarker:         []byte(markerLine),
		EndMarker:           []byte(markerLine),
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

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := fmt.Sprint(`[2022-11-12 23:08:18.012572] [-:error] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 [client 127.0.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/apache/conf/httpd.conf_pod_2022-11-12_22:23"] [line "265"] [id "999999"] [msg "`,
		"X-cRs-TeSt ", stageID,
		`"] [hostname "localhost"] [uri "/status/200"] [unique_id "Y3AZUo3Gja4gB-tPE9uasgAAAA4"]`)
	logLines := fmt.Sprint("\n", markerLine,
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`,
		`[2022-11-12 23:08:18.013007] [core:info] 127.0.0.1:36126 Y3AZUo3Gja4gB-tPE9uasgAAAA4 AH00128: File does not exist: /apache/htdocs/status/200`,
		"\n", markerLine)
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)

	cfg.LogFile = filename
	log, err := os.Open(filename)
	s.Require().NoError(err)

	ll := &FTWLogLines{
		logFile:             log,
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}
	ll.WithStartMarker([]byte(markerLine))
	ll.WithEndMarker([]byte(markerLine))
	foundMarker := ll.CheckLogForMarker(stageID, 100)
	s.Equal(strings.ToLower(markerLine), strings.ToLower(string(foundMarker)))
}

func (s *readTestSuite) TestFindAllIdsInLogs() {
	cfg, err := config.NewConfigFromEnv()
	s.Require().NoError(err)
	s.NotNil(cfg)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := fmt.Sprint("\n", markerLine,
		`[id "1"] something else [id "2"]`,
		`"id": 3, something else {"id":4},`,
		`something else [id \"5\"]`+"\n",
		"\n", markerLine)
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	s.Require().NoError(err)
	cfg.LogFile = filename
	log, err := os.Open(filename)
	s.Require().NoError(err)

	ll := &FTWLogLines{
		logFile:             log,
		LogMarkerHeaderName: bytes.ToLower([]byte(cfg.LogMarkerHeaderName)),
	}
	ll.WithStartMarker([]byte(markerLine))
	ll.WithEndMarker([]byte(markerLine))

	foundRuleIds := ll.TriggeredRules()
	s.Len(foundRuleIds, 5)
	s.Contains(foundRuleIds, uint(1))
	s.Contains(foundRuleIds, uint(2))
	s.Contains(foundRuleIds, uint(3))
	s.Contains(foundRuleIds, uint(4))
	s.Contains(foundRuleIds, uint(5))
}
