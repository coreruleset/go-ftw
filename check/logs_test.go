// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/utils"
)

var logText = `[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
`

type checkLogsTestSuite struct {
	suite.Suite
	cfg     *config.FTWConfiguration
	logName string
}

func TestCheckLogsTestSuite(t *testing.T) {
	suite.Run(t, new(checkLogsTestSuite))
}

func (s *checkLogsTestSuite) SetupTest() {
	var err error
	s.cfg = config.NewDefaultConfig()

	s.logName, err = utils.CreateTempFileWithContent(logText, "test-*.log")
	s.Require().NoError(err)
	s.cfg.WithLogfile(s.logName)
}

func (s *checkLogsTestSuite) TearDownTest() {
	err := os.Remove(s.logName)
	s.Require().NoError(err)
}

func (s *checkLogsTestSuite) TestLogContains() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.SetLogContains(`id "920300"`)
	s.True(c.AssertLogs(), "did not find expected content 'id \"920300\"'")

	c.SetLogContains(`SOMETHING`)
	s.False(c.AssertLogs(), "found something that is not there")

	c.SetLogContains("")
	s.True(c.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestNoLogContains() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.SetNoLogContains(`id "920300"`)
	s.False(c.AssertLogs(), "did not find expected content")

	c.SetNoLogContains("SOMETHING")
	s.True(c.AssertLogs(), "found something that is not there")

	c.SetNoLogContains("")
	s.True(c.AssertLogs(), "should return true when empty string is passed")
}

func (s *checkLogsTestSuite) TestAssertLogMatchRegex() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.expected.Log.MatchRegex = `id\s"920300"`
	s.True(c.AssertLogs(), `did not find expected content 'id\s"920300"'`)

	c.expected.Log.MatchRegex = `SOMETHING`
	s.False(c.AssertLogs(), "found something that is not there")

	c.expected.Log.MatchRegex = ""
	s.True(c.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogNoMatchRegex() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.expected.Log.NoMatchRegex = `id\s"920300"`
	s.False(c.AssertLogs(), `expected to find 'id\s"920300"'`)

	c.expected.Log.NoMatchRegex = `SOMETHING`
	s.True(c.AssertLogs(), "expected to _not_ find SOMETHING")

	c.expected.Log.NoMatchRegex = ""
	s.True(c.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogExpectIds() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.expected.Log.ExpectIds = []int{920300}
	s.True(c.AssertLogs(), `did not find expected content 'id\s"920300"'`)

	c.expected.Log.ExpectIds = []int{123456}
	s.False(c.AssertLogs(), "found something that is not there")

	c.expected.Log.ExpectIds = []int{}
	s.True(c.AssertLogs(), "empty LogContains should return true")
}

func (s *checkLogsTestSuite) TestAssertLogNoExpectId() {
	c, err := NewCheck(s.cfg)
	s.Require().NoError(err)

	c.expected.Log.NoExpectIds = []int{920300}
	s.False(c.AssertLogs(), `expected to find 'id\s"920300"'`)

	c.expected.Log.NoExpectIds = []int{123456}
	s.True(c.AssertLogs(), "expected to _not_ find SOMETHING")

	c.expected.Log.NoExpectIds = []int{}
	s.True(c.AssertLogs(), "empty LogContains should return true")
}
