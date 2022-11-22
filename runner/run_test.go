package runner

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/check"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/test"
)

var yamlConfig = `
---
testoverride:
  ignore:
    "920400-1": "This test result must be ignored"
`

var yamlConfigPortOverride = `
---
testoverride:
  input:
    dest_addr: "TEST_ADDR"
    port: %d
    protocol: "http"
`

var yamlConfigEmptyHostHeaderOverride = `
---
testoverride:
  input:
    dest_addr: %s
    headers:
      Host: %s
    override_empty_host_header: true
`

var yamlConfigHostHeaderOverride = `
---
testoverride:
  input:
    dest_addr: address.org
    headers:
      unique_id: %s
`

var yamlConfigHeaderOverride = `
---
testoverride:
  input:
    dest_addr: address.org
    headers:
      unique_id: %s
`

var yamlConfigURIOverride = `
---
testoverride:
  input:
   uri: %s
`

var yamlConfigVersionOverride = `
---
testoverride:
  input:
   version: %s
`

var yamlConfigMethodOverride = `
---
testoverride:
  input:
   method: %s
`

var yamlConfigDataOverride = `
---
testoverride:
  input:
   data: %s
`

var yamlConfigStopMagicOverride = `
---
testoverride:
  input:
   stop_magic: %t
`

var yamlConfigEncodedRequestOverride = `
---
testoverride:
  input:
   encoded_request: %s
`

var yamlConfigRAWRequestOverride = `
---
testoverride:
  input:
   raw_request: %s
`

var yamlConfigOverride = `
---
testoverride:
  input:
    dest_addr: "TEST_ADDR"
    # -1 designates port value must be replaced by test setup
    port: -1
    protocol: "http"
`

var yamlBrokenConfigOverride = `
---
testoverride:
  input:
    dest_addr: "TEST_ADDR"
    # -1 designates port value must be replaced by test setup
    port: -1
    this_does_not_exist: "test"
`

var yamlConfigIgnoreTests = `
---
testoverride:
  ignore:
    "001": "This test result must be ignored"
  forcefail:
    "008": "This test should pass, but it is going to fail"
  forcepass:
    "099": "This test failed, but it shall pass!"
`

var yamlCloudConfig = `
---
mode: cloud
`

var logText = `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
`

var yamlTest = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test"
tests:
  - test_title: "001"
    description: "access real external site"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "TEST_ADDR"
          output:
            expect_error: False
            status: [200]
  - test_title: "008"
    description: "this test is number 8"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            status: [200]
  - test_title: "010"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            version: "HTTP/1.1"
            method: "OTHER"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            response_contains: "Hello, client"
  - test_title: "101"
    description: "this tests exceptions (connection timeout)"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            port: 8090
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "none.host"
          output:
            expect_error: True
  - test_title: "102"
    description: "this tests exceptions (connection timeout)"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            port: 8090
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Host: "none.host"
              Accept: "*/*"
            encoded_request: "UE9TVCAvaW5kZXguaHRtbCBIVFRQLzEuMQ0KSG9zdDogMTkyLjE2OC4xLjIzDQpVc2VyLUFnZW50OiBjdXJsLzcuNDMuMA0KQWNjZXB0OiAqLyoNCkNvbnRlbnQtTGVuZ3RoOiA2NA0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbm5lY3Rpb246IGNsb3NlDQoNCmQ9MTsyOzM7NDs1XG4xO0BTVU0oMSsxKSpjbWR8JyBwb3dlcnNoZWxsIElFWCh3Z2V0IDByLnBlL3ApJ1whQTA7Mw=="
          output:
            expect_error: True
`

var yamlTestMultipleMatches = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test with multiple expected outputs per single rule"
tests:
  - test_title: "001"
    description: "access real external site"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "TEST_ADDR"
          output:
            status: [200]
            response_contains: "Not contains this"
`

var yamlTestOverride = `
---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Override Test"
tests:
  -
    test_title: "001"
    description: "access real external site"
    stages:
      -
        stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
                User-Agent: "ModSecurity CRS 3 Tests"
                Host: "TEST_ADDR"
          output:
            expect_error: False
            status: [200]
`

var yamlTestOverrideWithNoPort = `
---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Override Test"
tests:
  -
    test_title: "001"
    description: "access real external site"
    stages:
      -
        stage:
          input:
            dest_addr: "TEST_ADDR"
            headers:
                User-Agent: "ModSecurity CRS 3 Tests"
                Host: "TEST_ADDR"
          output:
            expect_error: False
            status: [200]
`

var yamlDisabledTest = `
---
meta:
  author: "tester"
  enabled: false
  name: "we do not care, this test is disabled"
  description: "Example Test"
tests:
  -
    test_title: "001"
    description: "access real external site"
    stages:
      -
        stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
                User-Agent: "ModSecurity CRS 3 Tests"
                Host: "TEST_ADDR"
          output:
            status: [1234]
`

var yamlTestLogs = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test"
tests:
  - test_title: "200"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            log_contains: id \"949110\"
  - test_title: "201"
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            no_log_contains: ABCDE
`

var yamlFailedTest = `---
meta:
  author: "tester"
  enabled: true
  name: "gotest-ftw.yaml"
  description: "Example Test"
tests:
  - test_title: "990"
    description: test that fails
    stages:
      - stage:
          input:
            dest_addr: "TEST_ADDR"
            # -1 designates port value must be replaced by test setup
            port: -1
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "none.host"
          output:
            status: [413]
`

type runTestsTestSuite struct {
	suite.Suite
	cfg         *config.FTWConfiguration
	ftwTest     test.FTWTest
	logFilePath string
	ts          *httptest.Server
}

// Error checking omitted for brevity
func (s *runTestsTestSuite) newTestServer(logLines string) (destination *ftwhttp.Destination) {
	s.setUpLogFileForTestServer()

	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, client"))

		s.writeTestServerLog(logLines, r)
	}))

	dest, err := ftwhttp.DestinationFromString((s.ts).URL)
	s.NoError(err, "cannot get destination from string")

	return dest
}

//// Error checking omitted for brevity
//func (s *runTestsTestSuite) newTestServerForCloudTest(responseStatus int) (server *httptest.Server, destination *ftwhttp.Destination) {
//	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.WriteHeader(responseStatus)
//		_, _ = w.Write([]byte("Hello, client"))
//	}))
//
//	// close server after test
//	s.Cleanup(server.Close)
//
//	dest, err := ftwhttp.DestinationFromString(server.URL)
//	s.NoErrorf(err, "cannot get destination from string", err.Error())
//
//	return server, dest
//}

func (s *runTestsTestSuite) setUpLogFileForTestServer() {
	// log to the configured file
	if s.cfg != nil && s.cfg.RunMode == config.DefaultRunMode {
		s.logFilePath = s.cfg.LogFile
	}
	// if no file has been configured, create one and handle cleanup
	if s.logFilePath == "" {
		file, err := os.CreateTemp("", "go-ftw-test-*.log")
		s.NoError(err)
		s.logFilePath = file.Name()
	}
}

func (s *runTestsTestSuite) writeTestServerLog(logLines string, r *http.Request) {
	// write supplied log lines, emulating the output of the rule engine
	logMessage := logLines
	// if the request has the special test header, log the request instead
	// this emulates the log marker rule
	if r.Header.Get(s.cfg.LogMarkerHeaderName) != "" {
		logMessage = fmt.Sprintf("request line: %s %s %s, headers: %s\n", r.Method, r.RequestURI, r.Proto, r.Header)
	}
	file, err := os.OpenFile(s.logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	s.Errorf(err, "cannot open file", err.Error())

	defer file.Close()

	_, err = file.WriteString(logMessage)
	s.NoErrorf(err, "cannot write log message to file", err.Error())
}

func replaceDestinationInTest(ftwTest *test.FTWTest, d ftwhttp.Destination) {
	// This function doesn't use `range` because we want to modify the struct in place.
	// Range (and assignments in general) create copies of structs, not references.
	// Maps, slices, etc. on the other hand, are assigned as references.
	for testIndex := 0; testIndex < len(ftwTest.Tests); testIndex++ {
		testCase := &ftwTest.Tests[testIndex]
		for stageIndex := 0; stageIndex < len(testCase.Stages); stageIndex++ {
			input := &testCase.Stages[stageIndex].Stage.Input

			if *input.DestAddr == "TEST_ADDR" {
				input.DestAddr = &d.DestAddr
			}
			if input.Headers.Get("Host") == "TEST_ADDR" {
				input.Headers.Set("Host", d.DestAddr)
			}
			if input.Port != nil && *input.Port == -1 {
				input.Port = &d.Port
			}
		}
	}
}

func replaceDestinationInConfiguration(override *config.FTWTestOverride, dest ftwhttp.Destination) {
	replaceableAddress := "TEST_ADDR"
	replaceablePort := -1

	overriddenInputs := &override.Overrides
	if overriddenInputs.DestAddr != nil && *overriddenInputs.DestAddr == replaceableAddress {
		overriddenInputs.DestAddr = &dest.DestAddr
	}
	if overriddenInputs.Port != nil && *overriddenInputs.Port == replaceablePort {
		overriddenInputs.Port = &dest.Port
	}
}

func (s *runTestsTestSuite) SetupTest() {
	var err error
	s.cfg, err = config.NewConfigFromString(yamlConfig)
	s.NoError(err)

	// setup test webserver (not a waf)
	dest := s.newTestServer(logText)
	s.cfg.WithLogfile(s.logFilePath)
	s.ftwTest, err = test.GetTestFromYaml([]byte(yamlTest))
	s.NoError(err)

	replaceDestinationInTest(&s.ftwTest, *dest)
}

func (s *runTestsTestSuite) BeforeTest(_ string, _ string) {
}

func (s *runTestsTestSuite) AfterTest(_ string, _ string) {
	s.ts.Close()
	_ = os.Remove(s.logFilePath)
	log.Info().Msgf("Deleting temporary file '%s'", s.logFilePath)
}

func TestRunTestsTestSuite(t *testing.T) {
	suite.Run(new(runTestsTestSuite))
}

func (s *runTestsTestSuite) TestRunTests_Run() {
	out := output.NewOutput("normal", os.Stdout)

	s.Run("show time and execute all", func() {
		res, err := Run(s.cfg, []test.FTWTest{s.ftwTest}, RunnerConfig{
			ShowTime: true,
			Output:   output.Quiet,
		}, out)
		s.NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
	})

	s.Run("be verbose and execute all", func() {
		res, err := Run(s.cfg, []test.FTWTest{s.ftwTest}, RunnerConfig{
			Include:  regexp.MustCompile("0*"),
			ShowTime: true,
		}, out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "verbose and execute all failed")
	})

	s.Run("don't show time and execute all", func() {
		res, err := Run(s.cfg, []test.FTWTest{s.ftwTest}, RunnerConfig{
			Include: regexp.MustCompile("0*"),
		}, out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("execute only test 008 but exclude all", func() {
		res, err := Run(s.cfg, []test.FTWTest{s.ftwTest}, RunnerConfig{
			Include: regexp.MustCompile("008"),
			Exclude: regexp.MustCompile("0*"),
		}, out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("exclude test 010", func() {
		res, err := Run(s.cfg, []test.FTWTest{s.ftwTest}, RunnerConfig{
			Exclude: regexp.MustCompile("010"),
		}, out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "failed to exclude test")
	})

	s.Run("test exceptions 1", func() {
		res, err := Run(s.cfg, []test.FTWTest{s.ftwTest}, RunnerConfig{
			Include: regexp.MustCompile("1*"),
			Exclude: regexp.MustCompile("0*"),
			Output:  output.Quiet,
		}, out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "failed to test exceptions")
	})
}

func (s *runTestsTestSuite) TestRunMultipleMatches() {
	cfg, err := config.NewConfigFromString(yamlConfig)
	s.NoError(err)

	out := output.NewOutput("normal", os.Stdout)

	dest := s.newTestServer(logText)
	cfg.WithLogfile(s.logFilePath)
	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestMultipleMatches))
	s.NoError(err)

	replaceDestinationInTest(&ftwTest, *dest)

	s.Run("execute multiple...test", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Output: output.Quiet,
		}, out)
		s.NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 1, "Oops, %d tests failed to run! Expected 1 failing test", res.Stats.TotalFailed())
	})
}

func (s *runTestsTestSuite) TestOverrideRun() {
	// setup test webserver (not a waf)
	cfg, err := config.NewConfigFromString(yamlConfigOverride)
	s.NoError(err)

	out := output.NewOutput("normal", os.Stdout)

	dest := s.newTestServer(logText)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(s.logFilePath)

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	s.NoError(err, "Failed to parse fake destination")

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverride))
	s.NoError(err)

	replaceDestinationInTest(&ftwTest, *fakeDestination)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
		Output: output.Quiet,
	}, out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestsTestSuite) TestBrokenOverrideRun() {
	cfg, err := config.NewConfigFromString(yamlBrokenConfigOverride)
	s.NoError(err)

	out := output.NewOutput("normal", os.Stdout)

	dest := s.newTestServer(logText)
	cfg.WithLogfile(s.logFilePath)
	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	s.NoError(err, "Failed to parse fake destination")

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverride))
	s.NoError(err)

	replaceDestinationInTest(&ftwTest, *fakeDestination)

	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestsTestSuite) TestBrokenPortOverrideRun() {
	defaultConfig := config.NewDefaultConfig()
	// TestServer initialized first to retrieve the correct port number
	dest := s.newTestServer(defaultConfig, logText)

	// replace destination port inside the yaml with the retrieved one
	cfg, err := config.NewConfigFromString(fmt.Sprintf(yamlConfigPortOverride, dest.Port))
	s.NoError(err)

	out := output.NewOutput("normal", os.Stdout)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogFile(s.logFilePath)

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	s.NoErrorf(err, "Failed to parse fake destination", err.Error())

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverrideWithNoPort))
	s.NoError(err)

	replaceDestinationInTest(&ftwTest, *fakeDestination)

	// the test should succeed, despite the unknown override property
	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestsTestSuite) TestDisabledRun() {
	cfg, err := config.NewConfigFromString(yamlCloudConfig)
	s.NoError(err)
	out := output.NewOutput("normal", os.Stdout)

	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	s.NoErrorf(err, "Failed to parse fake destination", err.Error())

	ftwTest, err := test.GetTestFromYaml([]byte(yamlDisabledTest))
	s.NoError(err)
	replaceDestinationInTest(&ftwTest, *fakeDestination)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestsTestSuite) TestLogsRun() {
	cfg, err := config.NewConfigFromString(yamlConfig)
	s.NoError(err)
	// setup test webserver (not a waf)
	dest := s.newTestServer(logText)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(s.logFilePath)

	out := output.NewOutput("normal", os.Stdout)

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
	s.NoError(err)
	replaceDestinationInTest(&ftwTest, *dest)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestsTestSuite) TestCloudRun() {
	cfg, err := config.NewConfigFromString(yamlCloudConfig)
	s.NoError(err)
	out := output.NewOutput("normal", os.Stdout)
	stats := NewRunStats()

	ftwTestDummy, err := test.GetTestFromYaml([]byte(yamlTestLogs))
	s.NoError(err)

	s.Run("don't show time and execute all", func() {
		for testCaseIndex, testCaseDummy := range ftwTestDummy.Tests {
			for stageIndex := range testCaseDummy.Stages {
				// Read the tests for every stage, so we can replace the destination
				// in each run. The server needs to be configured for each stage
				// individually.
				ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
				s.NoError(err)
				testCase := &ftwTest.Tests[testCaseIndex]
				stage := &testCase.Stages[stageIndex].Stage

				ftwCheck := check.NewCheck(s.cfg)

				// this mirrors check.SetCloudMode()
				responseStatus := 200
				if stage.Output.LogContains != "" {
					responseStatus = 403
				} else if stage.Output.NoLogContains != "" {
					responseStatus = 405
				}
				server, dest := s.newTestServerForCloudTest(responseStatus)

				replaceDestinationInConfiguration(&cfg.TestOverride, *dest)

				replaceDestinationInTest(&ftwTest, *dest)
				s.NoError(err)
				client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
				s.NoError(err)
				runContext := TestRunContext{
					Config:   s.cfg,
					Include:  nil,
					Exclude:  nil,
					ShowTime: false,
					Stats:    stats,
					Output:   out,
					Client:   client,
					LogLines: nil,
				}

				err = RunStage(&runContext, ftwCheck, *testCase, *stage)
				s.NoError(err)
				s.LessOrEqual(0, runContext.Stats.TotalFailed(), "Oops, test run failed!")

				server.Close()
			}
		}
	})
}

func (s *runTestsTestSuite) TestFailedTestsRun() {
	cfg, err := config.NewConfigFromString(yamlConfig)
	s.NoError(err)
	dest := s.newTestServer(logText)

	out := output.NewOutput("normal", os.Stdout)
	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(s.logFilePath)

	ftwTest, err := test.GetTestFromYaml([]byte(yamlFailedTest))
	s.NoError(err)
	replaceDestinationInTest(&ftwTest, *dest)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	s.NoError(err)
	s.Equal(1, res.Stats.TotalFailed())
}

func (s *runTestsTestSuite) TestApplyInputOverrideSetHostFromDestAddr() {
	originalHost := "original.com"
	overrideHost := "override.com"
	testInput := test.Input{
		DestAddr: &originalHost,
	}
	cfg := &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Overrides: test.Overrides{
				DestAddr:                &overrideHost,
				OverrideEmptyHostHeader: true,
			},
		},
	}

	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	s.Equal(overrideHost, *testInput.DestAddr, "`dest_addr` should have been overridden")

	s.NotNil(testInput.Headers, "Header map must exist after overriding `dest_addr`")

	hostHeader := testInput.Headers.Get("Host")
	s.NotEqual("", hostHeader, "Host header must be set after overriding `dest_addr`")
	s.Equal(overrideHost, hostHeader, "Host header must be identical to `dest_addr` after overrding `dest_addr`")
}

func (s *runTestsTestSuite) TestApplyInputOverrideSetHostFromHostHeaderOverride() {
	originalDestAddr := "original.com"
	overrideDestAddress := "wrong.org"
	overrideHostHeader := "override.com"

	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigEmptyHostHeaderOverride, overrideDestAddress, overrideHostHeader))
	s.NoError(err1)

	testInput := test.Input{
		DestAddr: &originalDestAddr,
	}

	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	hostHeader := testInput.Headers.Get("Host")
	s.NotEqual("", hostHeader, "Host header must be set after overriding the `Host` header")
	if hostHeader == overrideDestAddress {
		s.Equal(overrideHostHeader, hostHeader, "Host header override must take precence over OverrideEmptyHostHeader")
	} else {
		s.Equal(overrideHostHeader, hostHeader, "Host header must be identical to overridden `Host` header.")
	}
}

func (s *runTestsTestSuite) TestApplyInputOverrideSetHeaderOverridingExistingOne() {
	originalHeaderValue := "original"
	overrideHeaderValue := "override"
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigHostHeaderOverride, overrideHeaderValue))
	s.NoError(err1)

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	overriddenHeader := testInput.Headers.Get("unique_id")
	s.NotEqual("", overriddenHeader, "unique_id header must be set after overriding it")
	s.Equal(overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func (s *runTestsTestSuite) TestApplyInputOverrides() {
	originalHeaderValue := "original"
	overrideHeaderValue := "override"
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigHeaderOverride, overrideHeaderValue))
	s.NoError(err1)

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	overriddenHeader := testInput.Headers.Get("unique_id")
	s.NotEqual("", overriddenHeader, "unique_id header must be set after overriding it")
	s.Equal(overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func (s *runTestsTestSuite) TestApplyInputOverrideURI() {
	originalURI := "original.com"
	overrideURI := "override.com"
	testInput := test.Input{
		URI: &originalURI,
	}

	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigURIOverride, overrideURI))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideURI, *testInput.URI, "`URI` should have been overridden")
}

func (s *runTestsTestSuite) TestApplyInputOverrideVersion() {
	originalVersion := "HTTP/0.9"
	overrideVersion := "HTTP/1.1"
	testInput := test.Input{
		Version: &originalVersion,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigVersionOverride, overrideVersion))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideVersion, *testInput.Version, "`Version` should have been overridden")
}

func (s *runTestsTestSuite) TestApplyInputOverrideMethod() {
	originalMethod := "original.com"
	overrideMethod := "override.com"
	testInput := test.Input{
		Method: &originalMethod,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigMethodOverride, overrideMethod))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	assert.Equal(overrideMethod, *testInput.Method, "`Method` should have been overridden")
}

func (s *runTestsTestSuite) TestApplyInputOverrideData() {
	originalData := "data"
	overrideData := "new data"
	testInput := test.Input{
		Data: &originalData,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigDataOverride, overrideData))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideData, *testInput.Data, "`Data` should have been overridden")
}

func (s *runTestsTestSuite) TestApplyInputOverrideStopMagic() {
	overrideStopMagic := true
	testInput := test.Input{
		StopMagic: false,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigStopMagicOverride, overrideStopMagic))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideStopMagic, testInput.StopMagic, "`StopMagic` should have been overridden")
}

func (s *runTestsTestSuite) TestApplyInputOverrideEncodedRequest() {
	originalEncodedRequest := "originalbase64"
	overrideEncodedRequest := "modifiedbase64"
	testInput := test.Input{
		EncodedRequest: originalEncodedRequest,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigEncodedRequestOverride, overrideEncodedRequest))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideEncodedRequest, testInput.EncodedRequest, "`EncodedRequest` should have been overridden")
}

func (s *runTestsTestSuite) TestApplyInputOverrideRAWRequest() {
	originalRAWRequest := "original"
	overrideRAWRequest := "override"
	testInput := test.Input{
		RAWRequest: originalRAWRequest,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigRAWRequestOverride, overrideRAWRequest))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideRAWRequest, testInput.RAWRequest, "`RAWRequest` should have been overridden")
}

func (s *runTestsTestSuite) TestIgnoredTestsRun() {
	cfg, err := config.NewConfigFromString(yamlConfigIgnoreTests)
	dest := s.newTestServer(logText)
	s.NoError(err)

	out := output.NewOutput("normal", os.Stdout)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(s.logFilePath)

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTest))
	s.NoError(err)

	replaceDestinationInTest(&ftwTest, *dest)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	s.NoError(err)
	s.Equal(res.Stats.TotalFailed(), 1, "Oops, test run failed!")
}
