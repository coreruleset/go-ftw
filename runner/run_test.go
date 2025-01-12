// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"text/template"

	"github.com/coreruleset/ftw-tests-schema/v2/types"
	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/check"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/ftwhttp/header_names"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/test"
	"github.com/coreruleset/go-ftw/waflog"
)

var logText = `[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]`

var testConfigMap = map[string]string{
	"BaseConfig": `---
testoverride:
  ignore:
    "920400-1": "This test result must be ignored"
`,
	"TestBrokenOverrideRun": `---
testoverride:
  input:
    dest_addr: "{{ .TestAddr }}"
    port: {{ .TestPort }}
    this_does_not_exist: "test"
`,
	"TestBrokenPortOverrideRun": `---
testoverride:
  input:
    dest_addr: "{{ .TestAddr }}"
    port: {{ .TestPort }}
    protocol: "http"`,
	"TestIgnoredTestsRun": `---
testoverride:
  ignore:
    ".*-2": "This test result must be ignored"
  forcefail:
    ".*-8": "This test should pass, but it is going to fail"
  forcepass:
    ".*-99": "This test failed, but it shall pass!"
`,
	"TestOverrideRun": `---
testoverride:
  input:
    dest_addr: "{{ .TestAddr }}"
    port: {{ .TestPort }}
    protocol: "http"
`,
	"TestApplyInputOverrideMethod": `---
testoverride:
  input:
    method: %s
`,
	"TestApplyInputOverrideData": `---
testoverride:
  input:
    data: %s
`,
	"TestApplyInputOverrideStopMagic": `---
testoverride:
  input:
    stop_magic: %t
`,
	"TestApplyInputOverrideEncodedRequest": `---
testoverride:
  input:
    encoded_request: %s
`,
}

var destinationMap = map[string]string{
	"TestBrokenOverrideRun": "http://example.com:1234",
}

type runTestSuite struct {
	suite.Suite
	cfg          *config.FTWConfiguration
	ftwTests     []*test.FTWTest
	logFilePath  string
	out          *output.Output
	ts           *httptest.Server
	dest         *ftwhttp.Destination
	tempFileName string
}

func (s *runTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *runTestSuite) newTestServer(logLines string) {
	s.newTestServerWithHandlerGenerator(nil, logLines)
}

// Error checking omitted for brevity
func (s *runTestSuite) newTestServerWithHandlerGenerator(serverHandler func(logLines string) http.HandlerFunc, logLines string) {
	var err error
	var handler http.HandlerFunc
	s.setUpLogFileForTestServer()

	if serverHandler == nil {
		handler = s.getDefaultTestServerHandler(logLines)
	} else {
		handler = serverHandler(logLines)
	}
	s.ts = httptest.NewServer(handler)

	s.dest, err = ftwhttp.DestinationFromString((s.ts).URL)
	s.Require().NoError(err, "cannot get destination from string")
}

func (s *runTestSuite) getDefaultTestServerHandler(logLines string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, client"))

		s.writeMarkerOrMessageToTestServerLog(logLines, r)
	}
}

func (s *runTestSuite) setUpLogFileForTestServer() {
	// log to the configured file
	if s.cfg != nil && s.cfg.RunMode == config.DefaultRunMode {
		s.logFilePath = s.cfg.LogFile
	}
	// if no file has been configured, create one and handle cleanup
	if s.logFilePath == "" {
		file, err := os.CreateTemp(s.T().TempDir(), "go-ftw-test-*.log")
		s.Require().NoError(err)
		err = file.Close()
		s.Require().NoError(err)
		s.logFilePath = file.Name()
	}
}

func (s *runTestSuite) writeTestServerLog(logLines string) {
	file, err := os.OpenFile(s.logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	s.Require().NoError(err, "cannot open file")

	defer file.Close()

	n, err := file.WriteString(logLines)
	s.Len(logLines, n, "cannot write log message to file")
	s.Require().NoError(err, "cannot write log message to file")

	if logLines[len(logLines)-1] != '\n' {
		_, err = file.WriteString("\n")
		s.Require().NoError(err)
	}
}

func (s *runTestSuite) writeMarkerOrMessageToTestServerLog(logLines string, r *http.Request) {
	// write supplied log lines, emulating the output of the rule engine
	logMessage := logLines
	// if the request has the special test header, log the request instead
	// this emulates the log marker rule
	if r.Header.Get(s.cfg.LogMarkerHeaderName) != "" {
		logMessage = fmt.Sprintf("request line: %s %s %s, headers: %s\n", r.Method, r.RequestURI, r.Proto, r.Header)
	}
	s.writeTestServerLog(logMessage)
}

func (s *runTestSuite) TearDownTest() {
	s.ts.Close()
}

func (s *runTestSuite) BeforeTest(_ string, name string) {
	s.cfg = config.NewDefaultConfig()
	// setup test webserver (not a waf)
	s.newTestServer(logText)
	if s.logFilePath != "" {
		s.cfg.WithLogfile(s.logFilePath)
	}

	var err error
	var cfg string
	var ok bool

	s.out = output.NewOutput("normal", os.Stdout)

	// if we have a configuration for this test, use it
	// else use the default configuration
	if cfg, ok = testConfigMap[name]; !ok {
		cfg = testConfigMap["BaseConfig"]
	}

	// if we have a destination for this test, use it
	// else use the default destination
	if s.dest == nil {
		s.dest, err = ftwhttp.DestinationFromString(destinationMap[name])
		s.Require().NoError(err)
	}

	log.Info().Msgf("Using port %d and addr '%s'", s.dest.Port, s.dest.DestAddr)

	// set up variables for template
	vars := map[string]interface{}{
		"TestPort": s.dest.Port,
		"TestAddr": s.dest.DestAddr,
	}

	// set up configuration from template
	configTmpl, err := template.New("config-test").Parse(cfg)
	s.Require().NoError(err, "cannot parse template")
	buf := &bytes.Buffer{}
	err = configTmpl.Execute(buf, vars)
	s.Require().NoError(err, "cannot execute template")
	s.cfg, err = config.NewConfigFromString(buf.String())
	s.Require().NoError(err, "cannot get config from string")
	if s.logFilePath != "" {
		s.cfg.WithLogfile(s.logFilePath)
	}
	// get tests template from file
	tmpl, err := template.ParseFiles(fmt.Sprintf("testdata/%s.yaml", name))
	if err != nil {
		log.Info().Msgf("No test data found for test %s, assuming that's ok", name)
		return
	}

	// create a temporary file to hold the test
	testFileContents, err := os.CreateTemp(s.T().TempDir(), "mock-test-*.yaml")
	s.Require().NoError(err, "cannot create temporary file")
	err = tmpl.Execute(testFileContents, vars)
	s.Require().NoError(err, "cannot execute template")
	err = testFileContents.Close()
	s.Require().NoError(err)
	// get tests from file
	s.ftwTests, err = test.GetTestsFromFiles(testFileContents.Name())
	s.Require().NoError(err, "cannot get tests from file")
	// save the name of the temporary file so we can delete it later
	s.tempFileName = testFileContents.Name()
}

func TestRunTestsTestSuite(t *testing.T) {
	suite.Run(t, new(runTestSuite))
}

func (s *runTestSuite) TestRunTests_Run() {
	s.Run("show time and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			ShowTime: true,
			Output:   output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
	})

	s.Run("be verbose and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			Include:  regexp.MustCompile("0*"),
			ShowTime: true,
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 5, "verbose and execute all failed")
		s.Len(res.Stats.Skipped, 0, "verbose and execute all failed")
		s.Equal(res.Stats.TotalFailed(), 0, "verbose and execute all failed")
	})

	s.Run("don't show time and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			Include: regexp.MustCompile("0*"),
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 5, "do not show time and execute all failed")
		s.Len(res.Stats.Skipped, 0, "do not show time and execute all failed")
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("execute only test 8 but exclude all", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			Include: regexp.MustCompile("-8$"), // test ID is matched in format `<ruleId>-<testId>`
			Exclude: regexp.MustCompile("0*"),
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 1, "execute only test 008 but exclude all")
		s.Len(res.Stats.Skipped, 4, "execute only test 008 but exclude all")
		s.Equal(res.Stats.TotalFailed(), 0, "execute only test 008 but exclude all")
	})

	s.Run("exclude test 10", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			Exclude: regexp.MustCompile("-10$"), // test ID is matched in format `<ruleId>-<testId>`
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 4, "failed to exclude test")
		s.Len(res.Stats.Skipped, 1, "failed to exclude test")
		s.Equal(res.Stats.TotalFailed(), 0, "failed to exclude test")
	})

	s.Run("count tests tagged with `tag-10`", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			IncludeTags: regexp.MustCompile("^tag-10$"),
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 1, "failed to incorporate tagged test")
		s.Equal(res.Stats.TotalFailed(), 0, "failed to incorporate tagged test")
	})

	s.Run("count tests tagged with `tag-8` and `tag-10`", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			IncludeTags: regexp.MustCompile("^tag-8$|^tag-10$"),
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 2, "failed to incorporate tagged test")
		s.Equal(res.Stats.TotalFailed(), 0, "failed to incorporate tagged test")
	})

	s.Run("test exceptions 1", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			Include: regexp.MustCompile("-1.*"),
			Exclude: regexp.MustCompile("-0.*"),
			Output:  output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Len(res.Stats.Success, 4, "failed to test exceptions")
		s.Len(res.Stats.Skipped, 1, "failed to test exceptions")
		s.Equal(res.Stats.TotalFailed(), 0, "failed to test exceptions")
	})
}

func (s *runTestSuite) TestRunMultipleMatches() {
	s.Run("execute multiple...test", func() {
		res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
			Output: output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 1, "Oops, %d tests failed to run! Expected 1 failing test", res.Stats.TotalFailed())
	})
}

func (s *runTestSuite) TestOverrideRun() {
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
		Output: output.Quiet,
	}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestBrokenOverrideRun() {
	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestBrokenPortOverrideRun() {
	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestLogsRun() {
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestFailedTestsRun() {
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.Equal(1, res.Stats.TotalFailed())
}

func (s *runTestSuite) TestIgnoredTestsRun() {
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.Equal(1, len(res.Stats.ForcedPass), "Oops, unexpected number of forced pass tests")
	s.Equal(1, len(res.Stats.Failed), "Oops, unexpected number of failed tests")
	s.Equal(1, len(res.Stats.ForcedFail), "Oops, unexpected number of forced failed tests")
	s.Equal(4, len(res.Stats.Ignored), "Oops, unexpected number of ignored tests")
}

func (s *runTestSuite) TestGetRequestFromTestWithAutocompleteHeaders() {
	boolean := true
	method := "POST"
	input := test.NewInput(&schema.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             map[string]string{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
	})
	request, err := getRequestFromTest(input)
	s.Require().NoError(err)

	client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
	s.Require().NoError(err)

	dest := &ftwhttp.Destination{
		DestAddr: input.GetDestAddr(),
		Port:     input.GetPort(),
		Protocol: input.GetProtocol(),
	}
	err = client.NewConnection(*dest)
	s.Require().NoError(err)
	_, err = client.Do(*request)
	s.Require().NoError(err)

	contentLengthHeaders := request.Headers().GetAll(header_names.ContentLength)
	s.Len(contentLengthHeaders, 1)
	s.Equal("0", contentLengthHeaders[0].Value, "Autocompletion should add 'Content-Length' header to POST requests")

	connectionHeaders := request.Headers().GetAll(header_names.Connection)
	s.Len(connectionHeaders, 1)
	s.Equal("close", connectionHeaders[0].Value, "Autocompletion should add 'Connection: close' header")
}

func (s *runTestSuite) TestGetRequestFromTestWithoutAutocompleteHeaders() {
	boolean := false
	method := "POST"
	input := test.NewInput(&schema.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             map[string]string{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
	})
	request, err := getRequestFromTest(input)
	s.Require().NoError(err)

	client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
	s.Require().NoError(err)

	dest := &ftwhttp.Destination{
		DestAddr: input.GetDestAddr(),
		Port:     input.GetPort(),
		Protocol: input.GetProtocol(),
	}
	err = client.NewConnection(*dest)
	s.Require().NoError(err)
	_, err = client.Do(*request)
	s.Require().NoError(err)

	s.False(request.Headers().HasAny(header_names.ContentLength), "Autocompletion is disabled")
	s.False(request.Headers().HasAny(header_names.Connection), "Autocompletion is disabled")
}

// This test case verifies that the `retry_once` option works around a race condition in phase 5,
// where the log entry for a phase 5 rule may appear after the end marker of the last test.
// The race condition doesn't occur often, so retrying once should usually fix the issue.
func (s *runTestSuite) TestRetryOnce() {
	stageId := ""
	serverHitCount := 0

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, client"))

		// write logs on each start marker request
		nextStageId := r.Header.Get(s.cfg.LogMarkerHeaderName)
		if nextStageId != "" && nextStageId != stageId {
			stageId = nextStageId
			logMessage := ""
			switch serverHitCount {
			case 0:
				// start marker
				logMessage = fmt.Sprintf(
					`[Sat Mar 18 16:47:21.474075 2023] [security2:error] [pid 193:tid 140523746522880] [client 172.18.0.1:39150] [client 172.18.0.1] ModSecurity: Warning. Pattern match "^.*$" at REQUEST_HEADERS:X-CRS-Test. [file "/etc/modsecurity.d/owasp-crs/crs-setup.conf"] [line "737"] [id "999999"] [msg "%s"] [tag "modsecurity"] [hostname "localhost"] [uri "/status/200"] [unique_id "ZBXrGVXqtKqlnATxdUEg7QAAANg"]`,
					stageId)
			case 1:
				// hit without match + end marker
				logMessage = fmt.Sprintf(
					`[Sat Mar 18 16:47:21.476378 2023] [security2:error] [pid 193:tid 140524082149120] [client 172.18.0.1:39164] [client 172.18.0.1] ModSecurity: Warning. Pattern match "(?:^([\\\\d.]+|\\\\[[\\\\da-f:]+\\\\]|[\\\\da-f:]+)(:[\\\\d]+)?$)" at REQUEST_HEADERS:Host. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "761"] [id "920350"] [msg "Host header is a numeric IP address"] [data "127.0.0.1"] [severity "WARNING"] [ver "OWASP_CRS/4.0.0-rc1"] [tag "modsecurity"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [hostname "127.0.0.1"] [uri "/"] [unique_id "ZBXrGVXqtKqlnATxdUEg7gAAAMQ"]
[Sat Mar 18 16:47:21.480771 2023] [security2:error] [pid 193:tid 140524098930432] [client 172.18.0.1:39172] [client 172.18.0.1] ModSecurity: Warning. Pattern match "^.*$" at REQUEST_HEADERS:X-CRS-Test. [file "/etc/modsecurity.d/owasp-crs/crs-setup.conf"] [line "737"] [id "999999"] [msg "%s"] [tag "modsecurity"] [hostname "localhost"] [uri "/status/200"] [unique_id "ZBXrGVXqtKqlnATxdUEg7wAAAMM"]`,
					stageId)
			case 2:
				// late flushed phase 5 hit + start marker
				logMessage = fmt.Sprintf(
					`[Sat Mar 18 16:47:21.483333 2023] [security2:error] [pid 193:tid 140524082149120] [client 172.18.0.1:39164] [client 172.18.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "96"] [id "980170"] [msg "Anomaly Scores: (Inbound Scores: blocking=3, detection=3, per_pl=3-0-0-0, threshold=5) - (Outbound Scores: blocking=0, detection=0, per_pl=0-0-0-0, threshold=4) - (SQLI=0, XSS=0, RFI=0, LFI=0, RCE=0, PHPI=0, HTTP=0, SESS=0, COMBINED_SCORE=3)"] [ver "OWASP_CRS/4.0.0-rc1"] [tag "modsecurity"] [tag "reporting"] [hostname "127.0.0.1"] [uri "/"] [unique_id "ZBXrGVXqtKqlnATxdUEg7gAAAMQ"]
[Sat Mar 18 16:47:21.474075 2023] [security2:error] [pid 193:tid 140523746522880] [client 172.18.0.1:39150] [client 172.18.0.1] ModSecurity: Warning. Pattern match "^.*$" at REQUEST_HEADERS:X-CRS-Test. [file "/etc/modsecurity.d/owasp-crs/crs-setup.conf"] [line "737"] [id "999999"] [msg "%s"] [tag "modsecurity"] [hostname "localhost"] [uri "/status/200"] [unique_id "ZBXrGVXqtKqlnATxdUEg7QAAANg"]`,
					stageId)
			default:
				// hit with match + end marker
				logMessage = fmt.Sprintf(
					`[Sat Mar 18 16:47:21.476378 2023] [security2:error] [pid 193:tid 140524082149120] [client 172.18.0.1:39164] [client 172.18.0.1] ModSecurity: Warning. Pattern match "(?:^([\\\\d.]+|\\\\[[\\\\da-f:]+\\\\]|[\\\\da-f:]+)(:[\\\\d]+)?$)" at REQUEST_HEADERS:Host. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "761"] [id "920350"] [msg "Host header is a numeric IP address"] [data "127.0.0.1"] [severity "WARNING"] [ver "OWASP_CRS/4.0.0-rc1"] [tag "modsecurity"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [hostname "127.0.0.1"] [uri "/"] [unique_id "ZBXrGVXqtKqlnATxdUEg7gAAAMQ"]
[Sat Mar 18 16:47:21.483333 2023] [security2:error] [pid 193:tid 140524082149120] [client 172.18.0.1:39164] [client 172.18.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "96"] [id "980170"] [msg "Anomaly Scores: (Inbound Scores: blocking=3, detection=3, per_pl=3-0-0-0, threshold=5) - (Outbound Scores: blocking=0, detection=0, per_pl=0-0-0-0, threshold=4) - (SQLI=0, XSS=0, RFI=0, LFI=0, RCE=0, PHPI=0, HTTP=0, SESS=0, COMBINED_SCORE=3)"] [ver "OWASP_CRS/4.0.0-rc1"] [tag "modsecurity"] [tag "reporting"] [hostname "127.0.0.1"] [uri "/"] [unique_id "ZBXrGVXqtKqlnATxdUEg7gAAAMQ"]
[Sat Mar 18 16:47:21.480771 2023] [security2:error] [pid 193:tid 140524098930432] [client 172.18.0.1:39172] [client 172.18.0.1] ModSecurity: Warning. Pattern match "^.*$" at REQUEST_HEADERS:X-CRS-Test. [file "/etc/modsecurity.d/owasp-crs/crs-setup.conf"] [line "737"] [id "999999"] [msg "%s"] [tag "modsecurity"] [hostname "localhost"] [uri "/status/200"] [unique_id "ZBXrGVXqtKqlnATxdUEg7wAAAMM"]`,
					stageId)
			}

			s.writeTestServerLog(logMessage)
		}

		serverHitCount++
	}

	s.ts.Config.Handler = http.HandlerFunc(handler)
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{
		Output: output.Quiet,
	}, s.out)
	s.Require().NoError(err)
	s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
}

func (s *runTestSuite) TestFailFast() {
	s.Equal(3, len(s.ftwTests[0].Tests))

	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{FailFast: true}, s.out)
	s.Require().NoError(err)
	s.Equal(1, res.Stats.TotalFailed(), "Oops, test run failed!")
	s.Equal(2, res.Stats.Run)
}

func (s *runTestSuite) TestIsolatedSanity() {
	rc := &TestRunContext{
		Config: s.cfg,
	}
	stage := types.Stage{
		Input: types.Input{},
		Output: types.Output{
			Isolated: true,
			Log: types.Log{
				ExpectIds: []uint{},
			},
		},
	}
	err := RunStage(rc, &check.FTWCheck{}, types.Test{}, stage)
	s.ErrorContains(err, "'isolated' is only valid if 'expected_ids' has exactly one entry")

	stage.Output.Log.ExpectIds = []uint{1, 2}
	err = RunStage(rc, &check.FTWCheck{}, types.Test{}, stage)
	s.ErrorContains(err, "'isolated' is only valid if 'expected_ids' has exactly one entry")
}

func (s *runTestSuite) TestVirtualHostMode_Default() {
	method := "POST"
	input := test.NewInput(&schema.Input{
		Method: &method,
		Headers: map[string]string{
			"Host": "not-localhost_virtual-host",
		},
		DestAddr: &s.dest.DestAddr,
		Port:     &s.dest.Port,
		Protocol: &s.dest.Protocol,
	})
	context := &TestRunContext{
		Config: config.NewDefaultConfig(),
	}
	request := buildMarkerRequest(context, input, uuid.NewString())

	hostHeaders := request.Headers().GetAll("Host")
	s.Len(hostHeaders, 1)
	s.Equal("localhost", hostHeaders[0].Value)
}

func (s *runTestSuite) TestVirtualHostMode_False() {
	method := "POST"
	input := test.NewInput(&schema.Input{
		Method: &method,
		Headers: map[string]string{
			"Host": "not-localhost_virtual-host",
		},
		DestAddr:        &s.dest.DestAddr,
		Port:            &s.dest.Port,
		Protocol:        &s.dest.Protocol,
		VirtualHostMode: false,
	})
	context := &TestRunContext{
		Config: config.NewDefaultConfig(),
	}
	request := buildMarkerRequest(context, input, uuid.NewString())

	hostHeaders := request.Headers().GetAll("Host")
	s.Len(hostHeaders, 1)
	s.Equal("localhost", hostHeaders[0].Value)
}

func (s *runTestSuite) TestVirtualHostMode_True() {
	method := "POST"
	input := test.NewInput(&schema.Input{
		Method: &method,
		Headers: map[string]string{
			"Host": "not-localhost_virtual-host",
		},
		DestAddr:        &s.dest.DestAddr,
		Port:            &s.dest.Port,
		Protocol:        &s.dest.Protocol,
		VirtualHostMode: true,
	})
	context := &TestRunContext{
		Config: config.NewDefaultConfig(),
	}
	request := buildMarkerRequest(context, input, uuid.NewString())

	hostHeaders := request.Headers().GetAll("Host")
	s.Len(hostHeaders, 1)
	s.Equal("not-localhost_virtual-host", hostHeaders[0].Value)
}

func (s *runTestSuite) TestGetRequestFromData() {
	data := "This is Springfield"
	boolean := true
	method := "POST"
	input := test.NewInput(&schema.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             map[string]string{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
		Data:                &data,
	})
	request, err := getRequestFromTest(input)
	s.Require().NoError(err)

	s.Equal(data, string(request.Data()))
}

func (s *runTestSuite) TestGetRequestFromEncodedData() {
	data := base64.StdEncoding.EncodeToString([]byte("This is Springfield"))
	boolean := true
	method := "POST"
	input := test.NewInput(&schema.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             map[string]string{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
		Data:                &data,
	})
	request, err := getRequestFromTest(input)
	s.Require().NoError(err)

	s.Equal(data, string(request.Data()))
}

func (s *runTestSuite) TestTriggeredRules() {
	res, err := Run(s.cfg, s.ftwTests, &RunnerConfig{}, s.out)
	s.Require().NoError(err)
	triggeredRules := map[string][][]uint{
		"123456-1": {{
			920210,
			920300,
			949110,
			980130,
		}},
		"123456-2": {{
			920210,
			920300,
			949110,
			980130,
		}, {
			920210,
			920300,
			949110,
			980130,
		}}}
	s.Equal(triggeredRules, res.Stats.TriggeredRules, "Oops, triggered rules don't match expectation")
}

func (s *runTestSuite) TestEncodedRequest() {
	client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
	s.Require().NoError(err)
	ll, err := waflog.NewFTWLogLines(s.cfg)
	s.T().Cleanup(func() { _ = ll.Cleanup() })
	s.Require().NoError(err)

	context := &TestRunContext{
		Config:   s.cfg,
		Client:   client,
		LogLines: ll,
		Stats:    NewRunStats(),
		Output:   s.out,
	}
	stage := s.ftwTests[0].Tests[0].Stages[0]
	_check, err := check.NewCheck(s.cfg)
	s.T().Cleanup(func() { _ = _check.Close() })
	s.Require().NoError(err)

	err = RunStage(context, _check, types.Test{}, stage)
	s.Require().NoError(err)
	s.Equal(Success, context.Result)
}

func (s *runTestSuite) TestEncodedRequest_InvalidEncoding() {
	client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
	s.Require().NoError(err)
	ll, err := waflog.NewFTWLogLines(s.cfg)
	s.T().Cleanup(func() { _ = ll.Cleanup() })
	s.Require().NoError(err)

	context := &TestRunContext{
		Config:   s.cfg,
		Client:   client,
		LogLines: ll,
		Stats:    NewRunStats(),
		Output:   s.out,
	}
	stage := s.ftwTests[0].Tests[0].Stages[0]
	_check, err := check.NewCheck(s.cfg)
	s.T().Cleanup(func() { _ = _check.Close() })
	s.Require().NoError(err)

	err = RunStage(context, _check, types.Test{}, stage)
	s.Error(err, "failed to read request from test specification: illegal base64 data at input byte 4")
}
