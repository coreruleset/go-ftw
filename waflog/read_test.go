package waflog

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

func TestReadCheckLogForMarkerNoMarkerAtEnd(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerLine + `
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
`
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	assert.NoError(t, err)

	config.FTWConfig.LogFile = filename
	t.Cleanup(func() { os.Remove(filename) })

	ll := NewFTWLogLines(WithStartMarker(bytes.ToLower([]byte(markerLine))))

	marker := ll.CheckLogForMarker(stageID)
	assert.Nil(t, marker, "unexpectedly found marker")
}

func TestReadCheckLogForMarkerWithMarkerAtEnd(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerLine
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	assert.NoError(t, err)

	config.FTWConfig.LogFile = filename
	t.Cleanup(func() { os.Remove(filename) })

	ll := NewFTWLogLines(WithStartMarker(bytes.ToLower([]byte(markerLine))))

	marker := ll.CheckLogForMarker(stageID)
	assert.NotNil(t, marker, "no marker found")

	assert.Equal(t, marker, bytes.ToLower([]byte(markerLine)), "found unexpected marker")
}

func TestReadGetMarkedLines(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	startMarkerLine := "X-cRs-TeSt: " + stageID + " -start"
	endMarkerLine := "X-cRs-TeSt: " + stageID + " -end"
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s", startMarkerLine, logLinesOnly, endMarkerLine)
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	assert.NoError(t, err)

	config.FTWConfig.LogFile = filename
	t.Cleanup(func() { os.Remove(filename) })

	ll := NewFTWLogLines(
		WithStartMarker(bytes.ToLower([]byte(startMarkerLine))),
		WithEndMarker(bytes.ToLower([]byte(endMarkerLine))))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	assert.Equal(t, len(foundLines), 3, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		assert.Equalf(t, foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func TestReadGetMarkedLinesWithTrailingEmptyLines(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	startMarkerLine := "X-cRs-TeSt: " + stageID + " -start"
	endMarkerLine := "X-cRs-TeSt: " + stageID + " -end"
	logLinesOnly :=
		`[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	logLines := fmt.Sprintf("%s\n%s\n%s\n\n\n", startMarkerLine, logLinesOnly, endMarkerLine)
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	assert.NoError(t, err)

	config.FTWConfig.LogFile = filename
	t.Cleanup(func() { os.Remove(filename) })

	ll := NewFTWLogLines(
		WithStartMarker(bytes.ToLower([]byte(startMarkerLine))),
		WithEndMarker(bytes.ToLower([]byte(endMarkerLine))))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	assert.Len(t, foundLines, 6, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		assert.Equalf(t, foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func TestReadGetMarkedLinesWithPrecedingLines(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

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
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	assert.NoError(t, err)

	config.FTWConfig.LogFile = filename
	t.Cleanup(func() { os.Remove(filename) })

	ll := NewFTWLogLines(
		WithStartMarker(bytes.ToLower([]byte(startMarkerLine))),
		WithEndMarker(bytes.ToLower([]byte(endMarkerLine))))

	foundLines := ll.getMarkedLines()
	// logs are scanned backwards
	// we need to reverse the order of lines for comparison
	for i, j := 0, len(foundLines)-1; i < j; i, j = i+1, j-1 {
		foundLines[i], foundLines[j] = foundLines[j], foundLines[i]
	}

	assert.Len(t, foundLines, 4, "found unexpected number of log lines")

	for index, line := range strings.Split(logLinesOnly, "\n") {
		assert.Equalf(t, foundLines[index], []byte(line), "log lines don't match: \n%s\n%s", line, string(foundLines[index]))
	}
}

func TestFTWLogLines_Contains(t *testing.T) {
	err := config.NewConfigFromEnv()
	assert.NoError(t, err)

	stageID := "dead-beaf-deadbeef-deadbeef-dead"
	markerLine := "X-cRs-TeSt: " + stageID
	logLines := `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerLine
	filename, err := utils.CreateTempFileWithContent(logLines, "test-errorlog-")
	assert.NoError(t, err)

	config.FTWConfig.LogFile = filename
	log, err := os.Open(filename)
	assert.NoError(t, err)

	t.Cleanup(func() { os.Remove(filename) })

	type fields struct {
		logFile     *os.File
		FileName    string
		StartMarker []byte
		EndMarker   []byte
	}
	f := fields{
		logFile:     log,
		FileName:    filename,
		StartMarker: []byte(markerLine),
		EndMarker:   []byte(markerLine),
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
		t.Run(tt.name, func(t *testing.T) {
			ll := &FTWLogLines{
				logFile:     tt.fields.logFile,
				FileName:    tt.fields.FileName,
				StartMarker: tt.fields.StartMarker,
				EndMarker:   tt.fields.EndMarker,
			}
			got := ll.Contains(tt.args.match)
			assert.Equalf(t, tt.want, got, "Contains() = %v, want %v", got, tt.want)
		})
	}
}
