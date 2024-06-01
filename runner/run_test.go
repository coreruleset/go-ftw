// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"text/template"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/coreruleset/go-ftw/check"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/test"
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
    ".*-1": "This test result must be ignored"
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
	"TestApplyInputOverrideRAWRequest": `---
testoverride:
  input:
    raw_request: %s
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
		file, err := os.CreateTemp("", "go-ftw-test-*.log")
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
	tempDir := s.T().TempDir()
	testFileContents, err := os.CreateTemp(tempDir, "mock-test-*.yaml")
	s.Require().NoError(err, "cannot create temporary file")
	err = tmpl.Execute(testFileContents, vars)
	s.Require().NoError(err, "cannot execute template")
	// get tests from file
	s.ftwTests, err = test.GetTestsFromFiles(testFileContents.Name())
	s.Require().NoError(err, "cannot get tests from file")
	// save the name of the temporary file so we can delete it later
	s.tempFileName = testFileContents.Name()
}

func (s *runTestSuite) AfterTest(_ string, _ string) {
	err := os.Remove(s.logFilePath)
	s.Require().NoError(err, "cannot remove log file")
	log.Info().Msgf("Deleting temporary file '%s'", s.logFilePath)
	if s.tempFileName != "" {
		err = os.Remove(s.tempFileName)
		s.Require().NoError(err, "cannot remove test file")
		s.tempFileName = ""
	}
}

func TestRunTestsTestSuite(t *testing.T) {
	suite.Run(t, new(runTestSuite))
}

func (s *runTestSuite) TestRunTests_Run() {
	s.Run("show time and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			ShowTime: true,
			Output:   output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
	})

	s.Run("be verbose and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include:  regexp.MustCompile("0*"),
			ShowTime: true,
		}, s.out)
		s.Require().NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "verbose and execute all failed")
	})

	s.Run("don't show time and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include: regexp.MustCompile("0*"),
		}, s.out)
		s.Require().NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("execute only test 008 but exclude all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include: regexp.MustCompile("008"),
			Exclude: regexp.MustCompile("0*"),
		}, s.out)
		s.Require().NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("exclude test 010", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Exclude: regexp.MustCompile("010"),
		}, s.out)
		s.Require().NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "failed to exclude test")
	})

	s.Run("test exceptions 1", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include: regexp.MustCompile("1*"),
			Exclude: regexp.MustCompile("0*"),
			Output:  output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "failed to test exceptions")
	})
}

func (s *runTestSuite) TestRunMultipleMatches() {
	s.Run("execute multiple...test", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Output: output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 1, "Oops, %d tests failed to run! Expected 1 failing test", res.Stats.TotalFailed())
	})
}

func (s *runTestSuite) TestOverrideRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
		Output: output.Quiet,
	}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestBrokenOverrideRun() {
	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestBrokenPortOverrideRun() {
	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestLogsRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestFailedTestsRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.Equal(1, res.Stats.TotalFailed())
}

func (s *runTestSuite) TestIgnoredTestsRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.Require().NoError(err)
	s.Equal(res.Stats.TotalFailed(), 1, "Oops, test run failed!")
}

func (s *runTestSuite) TestGetRequestFromTestWithAutocompleteHeaders() {
	boolean := true
	method := "POST"
	input := test.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             ftwhttp.Header{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
	}
	request := getRequestFromTest(input)

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

	s.Equal("0", request.Headers().Get("Content-Length"), "Autocompletion should add 'Content-Length' header to POST requests")
	s.Equal("close", request.Headers().Get("Connection"), "Autocompletion should add 'Connection: close' header")
}

func (s *runTestSuite) TestGetRawRequestFromTestWithAutocompleteHeaders() {
	boolean := true
	method := "POST"
	input := test.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             ftwhttp.Header{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
		RAWRequest:          "POST / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test\r\n\r\n",
	}
	request := getRequestFromTest(input)

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

	s.Equal("", request.Headers().Get("Content-Length"), "Raw requests should not be modified")
	s.Equal("", request.Headers().Get("Connection"), "Raw requests should not be modified")
}

func (s *runTestSuite) TestGetRequestFromTestWithoutAutocompleteHeaders() {
	boolean := false
	method := "POST"
	input := test.Input{
		AutocompleteHeaders: &boolean,
		Method:              &method,
		Headers:             ftwhttp.Header{},
		DestAddr:            &s.dest.DestAddr,
		Port:                &s.dest.Port,
		Protocol:            &s.dest.Protocol,
	}
	request := getRequestFromTest(input)

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

	s.Equal("", request.Headers().Get("Content-Length"), "Autocompletion is disabled")
	s.Equal("", request.Headers().Get("Connection"), "Autocompletion is disabled")
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
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
		Output: output.Quiet,
	}, s.out)
	s.Require().NoError(err)
	s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
}

func (s *runTestSuite) TestFailFast() {
	s.Equal(3, len(s.ftwTests[0].Tests))

	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{FailFast: true}, s.out)
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
