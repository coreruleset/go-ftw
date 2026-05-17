// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"testing"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/coreruleset/go-ftw/v2/utils"
	"github.com/coreruleset/go-ftw/v2/waflog"
)

var configMap = map[string]string{
	"TestNewCheck": `---
logfile: 'tests/logs/modsec3-nginx/nginx/error.log'
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
`, "TestForced": `---
testoverride:
  ignore:
    '942200-1': 'Ignore Me'
  forcepass:
    '1245': 'Forced Pass'
  forcefail:
    '6789': 'Forced Fail'
`, "TestCloudMode": `---
mode: "cloud"`,
}

type checkBaseTestSuite struct {
	suite.Suite
	cfg          *config.FTWConfiguration
	runnerConfig *config.RunnerConfig
	context      *TestRunContext
}

func (s *checkBaseTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *checkBaseTestSuite) BeforeTest(_, name string) {
	logLines := `[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`
	var err error
	s.cfg, err = config.NewConfigFromString(configMap[name])
	s.Require().NoError(err)
	s.cfg.LogFile, err = utils.CreateTempFileWithContent("", logLines, "test-*.log")
	s.Require().NoError(err)
	s.runnerConfig = config.NewRunnerConfiguration(s.cfg)
	s.context = &TestRunContext{
		RunnerConfig: s.runnerConfig,
	}
	s.context.LogLines, err = waflog.NewFTWLogLines(s.runnerConfig)
	s.Require().NoError(err)
}

func TestCheckBaseTestSuite(t *testing.T) {
	suite.Run(t, new(checkBaseTestSuite))
}

func (s *checkBaseTestSuite) TestNewCheck() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)

	for _, text := range c.cfg.TestOverride.Ignore {
		s.Equal(text, "Ignore Me", "Well, didn't match Ignore Me")
	}

	to := test.Output{
		Status:           200,
		ResponseContains: "",
		LogContains:      "nothing",
		NoLogContains:    "",
		ExpectError:      func() *bool { b := true; return &b }(),
	}
	c.SetExpectTestOutput(&to)

	s.True(*c.expected.ExpectError, "Problem setting expected output")

	c.SetNoLogContains("nologcontains")

	//nolint:staticcheck
	s.Equal(c.expected.NoLogContains, "nologcontains", "Problem setting nologcontains")
}

func (s *checkBaseTestSuite) TestForced() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)

	s.True(c.ForcedIgnore(&schema.Test{RuleId: 942200, TestId: 1}), "Can't find ignored value")

	s.False(c.ForcedFail(&schema.Test{RuleId: 12345, TestId: 1}), "Value should not be found")

	s.False(c.ForcedPass(&schema.Test{RuleId: 12345, TestId: 1}), "Value should not be found")

	s.True(c.ForcedPass(&schema.Test{RuleId: 1245, TestId: 1}), "Value should be found")

	s.True(c.ForcedFail(&schema.Test{RuleId: 6789, TestId: 1}), "Value should be found")

	s.cfg.TestOverride.Ignore = make(map[*config.FTWRegexp]string)
	s.Falsef(c.ForcedIgnore(&schema.Test{RuleId: 1234, TestId: 1}), "Should not find ignored value in empty map")

}

func (s *checkBaseTestSuite) TestSetMarkers() {
	c, err := NewCheck(s.context)
	s.Require().NoError(err)

	c.SetStartMarker([]byte("TesTingStArtMarKer"))
	c.SetEndMarker([]byte("TestIngEnDMarkeR"))
	s.Equal("testingstartmarker", string(c.log.StartMarker()), "Couldn't set start marker")
	s.Equal("testingendmarker", string(c.log.EndMarker()), "Couldn't set end marker")
}
