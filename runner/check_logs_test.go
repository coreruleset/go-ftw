// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

var (
	uuidString  = "8677f1ed-3936-4999-82e4-39daf32ffff5"
	markerStart = uuidString + "-s"
	markerEnd   = uuidString + "-e"
	logText     = markerStart +
		`
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
` + markerEnd
)

type checkLogsTestSuite struct {
	suite.Suite
	cfg     *config.FTWConfiguration
	logName string
	check   *FTWCheck
	context *TestRunContext
}

func TestCheckLogsTestSuite(t *testing.T) {
	suite.Run(t, new(checkLogsTestSuite))
}

func (s *checkLogsTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *checkLogsTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()
	s.context = &TestRunContext{
		Config: s.cfg,
	}

	s.logName, err = utils.CreateTempFileWithContent("", logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(s.logName)

	s.check, err = NewCheck(s.context)
	s.Require().NoError(err)

	s.check.log.WithStartMarker([]byte(markerStart))
	s.check.log.WithEndMarker([]byte(markerEnd))
}

func (s *checkLogsTestSuite) TearDownTest() {
	err := s.check.Close()
	s.Require().NoError(err)
}

func (s *checkLogsTestSuite) TestLogContains() {
	s.check.SetLogContains(`id "920300"`)
	s.True(s.check.AssertLogs(), "did not find expected content 'id \"920300\"'")

	s.check.SetLogContains(`SOMETHING`)
	s.False(s.check.AssertLogs(), "found something that is not there")

	s.check.SetLogContains("")
	s.True(s.check.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestNoLogContains() {
	s.check.SetNoLogContains(`id "920300"`)
	s.False(s.check.AssertLogs(), "did not find expected content")

	s.check.SetNoLogContains("SOMETHING")
	s.True(s.check.AssertLogs(), "found something that is not there")

	s.check.SetNoLogContains("")
	s.True(s.check.AssertLogs(), "should return true when empty string is passed")
}

func (s *checkLogsTestSuite) TestAssertLogMatchRegex() {
	s.check.expected.Log.MatchRegex = `id\s"920300"`
	s.True(s.check.AssertLogs(), `did not find expected content 'id\s"920300"'`)

	s.check.expected.Log.MatchRegex = `SOMETHING`
	s.False(s.check.AssertLogs(), "found something that is not there")

	s.check.expected.Log.MatchRegex = ""
	s.True(s.check.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogNoMatchRegex() {
	s.check.expected.Log.NoMatchRegex = `id\s"920300"`
	s.False(s.check.AssertLogs(), `expected to find 'id\s"920300"'`)

	s.check.expected.Log.NoMatchRegex = `SOMETHING`
	s.True(s.check.AssertLogs(), "expected to _not_ find SOMETHING")

	s.check.expected.Log.NoMatchRegex = ""
	s.True(s.check.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogExpectIds() {
	s.check.expected.Log.ExpectIds = []uint{920300}
	s.True(s.check.AssertLogs(), `did not find expected content 'id\s"920300"'`)

	s.check.expected.Log.ExpectIds = []uint{123456}
	s.False(s.check.AssertLogs(), "found something that is not there")

	s.check.expected.Log.ExpectIds = []uint{}
	s.True(s.check.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogNoExpectId() {
	s.check.expected.Log.NoExpectIds = []uint{920300}
	s.False(s.check.AssertLogs(), `expected to find 'id\s"920300"'`)

	s.check.expected.Log.NoExpectIds = []uint{123456}
	s.True(s.check.AssertLogs(), "expected to _not_ find SOMETHING")

	s.check.expected.Log.NoExpectIds = []uint{}
	s.True(s.check.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogExpectIds_Multiple() {
	s.check.expected.Log.ExpectIds = []uint{920300}
	s.True(s.check.AssertLogs(), "Expected to find '920300'")

	s.check.expected.Log.ExpectIds = []uint{920300, 949110}
	s.True(s.check.AssertLogs(), "Expected to find all IDs")
}

func (s *checkLogsTestSuite) TestAssertLogExpectIds_Subset() {
	s.check.expected.Log.ExpectIds = []uint{920300}
	s.True(s.check.AssertLogs(), "Expected to find '920300'")

	s.check.expected.Log.ExpectIds = []uint{920300, 123}
	s.False(s.check.AssertLogs(), "Did not expect to find '123'")
}

func (s *checkLogsTestSuite) TestAssertLogNoExpectIds_Multiple() {
	s.check.expected.Log.NoExpectIds = []uint{123}
	s.True(s.check.AssertLogs(), "Did not expect to find '123'")

	s.check.expected.Log.NoExpectIds = []uint{123, 456}
	s.True(s.check.AssertLogs(), "Did not expect to find any of the IDs")
}

func (s *checkLogsTestSuite) TestAssertLogNoExpectIds_Subset() {
	s.check.expected.Log.NoExpectIds = []uint{123}
	s.True(s.check.AssertLogs(), "Did not expect to find '123'")

	s.check.expected.Log.NoExpectIds = []uint{123, 920300}
	s.False(s.check.AssertLogs(), "Expected to find '920300'")
}

func (s *checkLogsTestSuite) TestAssertLogIsolated() {
	s.check.expected.Log.ExpectIds = []uint{920300}
	s.False(s.check.expected.Isolated)
	s.True(s.check.AssertLogs(), "Expected to find 920300")

	s.check.expected.Isolated = true
	s.False(s.check.AssertLogs(), "Expected to find multiple IDs")
}
