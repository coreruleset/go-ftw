package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/coreruleset/go-ftw/output"

	"github.com/stretchr/testify/assert"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/check"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
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

// Error checking omitted for brevity
func newTestServer(t *testing.T, cfg *config.FTWConfiguration, logLines string) (destination *ftwhttp.Destination, logFilePath string) {
	logFilePath = setUpLogFileForTestServer(t, cfg)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, client"))

		writeTestServerLog(t, cfg, logLines, logFilePath, r)
	}))

	// close server after test
	t.Cleanup(ts.Close)

	dest, err := ftwhttp.DestinationFromString(ts.URL)
	if err != nil {
		assert.FailNow(t, "cannot get destination from string", err.Error())
	}
	return dest, logFilePath
}

// Error checking omitted for brevity
func newTestServerForCloudTest(t *testing.T, responseStatus int) (server *httptest.Server, destination *ftwhttp.Destination) {
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(responseStatus)
		_, _ = w.Write([]byte("Hello, client"))
	}))

	// close server after test
	t.Cleanup(server.Close)

	dest, err := ftwhttp.DestinationFromString(server.URL)
	if err != nil {
		assert.FailNow(t, "cannot get destination from string", err.Error())
	}

	return server, dest
}

func setUpLogFileForTestServer(t *testing.T, cfg *config.FTWConfiguration) (logFilePath string) {
	// log to the configured file
	if cfg.RunMode == config.DefaultRunMode {
		logFilePath = cfg.LogFile
	}
	// if no file has been configured, create one and handle cleanup
	if logFilePath == "" {
		file, err := os.CreateTemp("", "go-ftw-test-*.log")
		assert.NoError(t, err)
		logFilePath = file.Name()
		t.Cleanup(func() {
			_ = os.Remove(logFilePath)
			log.Info().Msgf("Deleting temporary file '%s'", logFilePath)
		})
	}
	return logFilePath
}

func writeTestServerLog(t *testing.T, cfg *config.FTWConfiguration, logLines string, logFilePath string, r *http.Request) {
	// write supplied log lines, emulating the output of the rule engine
	logMessage := logLines
	// if the request has the special test header, log the request instead
	// this emulates the log marker rule
	if r.Header.Get(cfg.LogMarkerHeaderName) != "" {
		logMessage = fmt.Sprintf("request line: %s %s %s, headers: %s\n", r.Method, r.RequestURI, r.Proto, r.Header)
	}
	file, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		assert.FailNow(t, "cannot open file", err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(logMessage)
	if err != nil {
		assert.FailNow(t, "cannot write log message to file", err.Error())
	}
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

	input := &override.Input
	if input.DestAddr != nil && *input.DestAddr == replaceableAddress {
		input.DestAddr = &dest.DestAddr
	}
	if input.Port != nil && *input.Port == replaceablePort {
		input.Port = &dest.Port
	}
}

func TestRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlConfig)
	assert.NoError(t, err)

	out := output.NewOutput("normal", os.Stdout)

	// setup test webserver (not a waf)
	dest, logFilePath := newTestServer(t, cfg, logText)
	cfg.WithLogfile(logFilePath)
	ftwTest, err := test.GetTestFromYaml([]byte(yamlTest))
	assert.NoError(t, err)

	replaceDestinationInTest(&ftwTest, *dest)

	t.Run("show time and execute all", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			ShowTime: true,
			Output:   output.Quiet,
		}, out)
		assert.NoError(t, err)
		assert.Equalf(t, res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
	})

	t.Run("be verbose and execute all", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Include:  regexp.MustCompile("0*"),
			ShowTime: true,
		}, out)
		assert.NoError(t, err)
		assert.Equal(t, res.Stats.TotalFailed(), 0, "verbose and execute all failed")
	})

	t.Run("don't show time and execute all", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Include: regexp.MustCompile("0*"),
		}, out)
		assert.NoError(t, err)
		assert.Equal(t, res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Include: regexp.MustCompile("008"),
			Exclude: regexp.MustCompile("0*"),
		}, out)
		assert.NoError(t, err)
		assert.Equal(t, res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	t.Run("exclude test 010", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Exclude: regexp.MustCompile("010"),
		}, out)
		assert.NoError(t, err)
		assert.Equal(t, res.Stats.TotalFailed(), 0, "failed to exclude test")
	})

	t.Run("test exceptions 1", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Include: regexp.MustCompile("1*"),
			Exclude: regexp.MustCompile("0*"),
			Output:  output.Quiet,
		}, out)
		assert.NoError(t, err)
		assert.Equal(t, res.Stats.TotalFailed(), 0, "failed to test exceptions")
	})
}

func TestRunMultipleMatches(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlConfig)
	assert.NoError(t, err)

	out := output.NewOutput("normal", os.Stdout)

	dest, logFilePath := newTestServer(t, cfg, logText)
	cfg.WithLogfile(logFilePath)
	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestMultipleMatches))
	assert.NoError(t, err)

	replaceDestinationInTest(&ftwTest, *dest)

	t.Run("execute multiple...test", func(t *testing.T) {
		res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
			Output: output.Quiet,
		}, out)
		assert.NoError(t, err)
		assert.Equalf(t, res.Stats.TotalFailed(), 1, "Oops, %d tests failed to run! Expected 1 failing test", res.Stats.TotalFailed())
	})
}

func TestOverrideRun(t *testing.T) {
	// setup test webserver (not a waf)
	cfg, err := config.NewConfigFromString(yamlConfigOverride)
	assert.NoError(t, err)

	out := output.NewOutput("normal", os.Stdout)

	dest, logFilePath := newTestServer(t, cfg, logText)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(logFilePath)

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		assert.FailNow(t, err.Error(), "Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverride))
	assert.NoError(t, err)

	replaceDestinationInTest(&ftwTest, *fakeDestination)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{
		Output: output.Quiet,
	}, out)
	assert.NoError(t, err)
	assert.LessOrEqual(t, 0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func TestBrokenOverrideRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlBrokenConfigOverride)
	assert.NoError(t, err)

	out := output.NewOutput("normal", os.Stdout)

	dest, logFilePath := newTestServer(t, cfg, logText)
	cfg.WithLogfile(logFilePath)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		assert.FailNow(t, err.Error(), "Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverride))
	assert.NoError(t, err)

	replaceDestinationInTest(&ftwTest, *fakeDestination)

	// the test should succeed, despite the unknown override property
	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	assert.NoError(t, err)
	assert.LessOrEqual(t, 0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func TestBrokenPortOverrideRun(t *testing.T) {
	defaultConfig := config.NewDefaultConfig()
	// TestServer initialized first to retrieve the correct port number
	dest, logFilePath := newTestServer(t, defaultConfig, logText)
	// replace destination port inside the yaml with the retrieved one
	cfg, err := config.NewConfigFromString(fmt.Sprintf(yamlConfigPortOverride, dest.Port))
	assert.NoError(t, err)

	out := output.NewOutput("normal", os.Stdout)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(logFilePath)

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		assert.FailNow(t, err.Error(), "Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverrideWithNoPort))
	assert.NoError(t, err)

	replaceDestinationInTest(&ftwTest, *fakeDestination)

	// the test should succeed, despite the unknown override property
	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	assert.NoError(t, err)
	assert.LessOrEqual(t, 0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func TestDisabledRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlCloudConfig)
	assert.NoError(t, err)
	out := output.NewOutput("normal", os.Stdout)

	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		assert.FailNow(t, err.Error(), "Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlDisabledTest))
	assert.NoError(t, err)
	replaceDestinationInTest(&ftwTest, *fakeDestination)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	assert.NoError(t, err)
	assert.LessOrEqual(t, 0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func TestLogsRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlConfig)
	assert.NoError(t, err)
	// setup test webserver (not a waf)
	dest, logFilePath := newTestServer(t, cfg, logText)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(logFilePath)

	out := output.NewOutput("normal", os.Stdout)

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
	assert.NoError(t, err)
	replaceDestinationInTest(&ftwTest, *dest)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	assert.NoError(t, err)
	assert.LessOrEqual(t, 0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func TestCloudRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlCloudConfig)
	assert.NoError(t, err)
	out := output.NewOutput("normal", os.Stdout)
	stats := NewRunStats()

	ftwTestDummy, err := test.GetTestFromYaml([]byte(yamlTestLogs))
	assert.NoError(t, err)

	t.Run("don't show time and execute all", func(t *testing.T) {
		for testCaseIndex, testCaseDummy := range ftwTestDummy.Tests {
			for stageIndex := range testCaseDummy.Stages {
				// Read the tests for every stage, so we can replace the destination
				// in each run. The server needs to be configured for each stage
				// individually.
				ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
				assert.NoError(t, err)
				testCase := &ftwTest.Tests[testCaseIndex]
				stage := &testCase.Stages[stageIndex].Stage

				ftwCheck := check.NewCheck(cfg)

				// this mirrors check.SetCloudMode()
				responseStatus := 200
				if stage.Output.LogContains != "" {
					responseStatus = 403
				} else if stage.Output.NoLogContains != "" {
					responseStatus = 405
				}
				server, dest := newTestServerForCloudTest(t, responseStatus)

				replaceDestinationInConfiguration(&cfg.TestOverride, *dest)

				replaceDestinationInTest(&ftwTest, *dest)
				assert.NoError(t, err)
				client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
				assert.NoError(t, err)
				runContext := TestRunContext{
					Config:   cfg,
					Include:  nil,
					Exclude:  nil,
					ShowTime: false,
					Stats:    stats,
					Output:   out,
					Client:   client,
					LogLines: nil,
				}

				err = RunStage(&runContext, ftwCheck, *testCase, *stage)
				assert.NoError(t, err)
				assert.LessOrEqual(t, 0, runContext.Stats.TotalFailed(), "Oops, test run failed!")

				server.Close()
			}
		}
	})
}

func TestFailedTestsRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlConfig)
	assert.NoError(t, err)
	dest, logFilePath := newTestServer(t, cfg, logText)

	out := output.NewOutput("normal", os.Stdout)
	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(logFilePath)

	ftwTest, err := test.GetTestFromYaml([]byte(yamlFailedTest))
	assert.NoError(t, err)
	replaceDestinationInTest(&ftwTest, *dest)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	assert.NoError(t, err)
	assert.Equal(t, 1, res.Stats.TotalFailed())
}

func TestApplyInputOverrideHostFromDestAddr(t *testing.T) {
	originalHost := "original.com"
	overrideHost := "override.com"
	testInput := test.Input{
		DestAddr: &originalHost,
	}
	cfg := &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Input: test.Input{
				DestAddr: &overrideHost,
			},
		},
	}

	err := applyInputOverride(cfg.TestOverride, &testInput)
	assert.NoError(t, err, "Failed to apply input overrides")

	assert.Equal(t, overrideHost, *testInput.DestAddr, "`dest_addr` should have been overridden")

	assert.NotNil(t, testInput.Headers, "Header map must exist after overriding `dest_addr`")

	hostHeader := testInput.Headers.Get("Host")
	assert.Equal(t, "", hostHeader, "Without OverrideEmptyHostHeader, Host header must not be set after overriding `dest_addr`")
}

func TestApplyInputOverrideEmptyHostHeaderSetHostFromDestAddr(t *testing.T) {
	originalHost := "original.com"
	overrideHost := "override.com"
	testInput := test.Input{
		DestAddr: &originalHost,
	}
	cfg := &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Input: test.Input{
				DestAddr:                &overrideHost,
				OverrideEmptyHostHeader: true,
			},
		},
	}

	err := applyInputOverride(cfg.TestOverride, &testInput)
	assert.NoError(t, err, "Failed to apply input overrides")

	assert.Equal(t, overrideHost, *testInput.DestAddr, "`dest_addr` should have been overridden")

	assert.NotNil(t, testInput.Headers, "Header map must exist after overriding `dest_addr`")

	hostHeader := testInput.Headers.Get("Host")
	assert.NotEqual(t, "", hostHeader, "Host header must be set after overriding `dest_addr`")
	assert.Equal(t, overrideHost, hostHeader, "Host header must be identical to `dest_addr` after overrding `dest_addr`")
}

func TestApplyInputOverrideSetHostFromHostHeaderOverride(t *testing.T) {
	originalDestAddr := "original.com"
	overrideDestAddress := "wrong.org"
	overrideHostHeader := "override.com"
	testConfig := `
---
testoverride:
  input:
    dest_addr: %s
    headers:
      Host: %s
    override_empty_host_header: true
`

	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(testConfig, overrideDestAddress, overrideHostHeader))
	assert.NoError(t, err1)

	testInput := test.Input{
		DestAddr: &originalDestAddr,
	}

	err := applyInputOverride(cfg.TestOverride, &testInput)
	assert.NoError(t, err, "Failed to apply input overrides")

	hostHeader := testInput.Headers.Get("Host")
	assert.NotEqual(t, "", hostHeader, "Host header must be set after overriding the `Host` header")
	if hostHeader == overrideDestAddress {
		assert.Equal(t, overrideHostHeader, hostHeader, "Host header override must take precence over OverrideEmptyHostHeader")
	} else {
		assert.Equal(t, overrideHostHeader, hostHeader, "Host header must be identical to overridden `Host` header.")
	}
}

func TestApplyInputOverrideSetHeaderOverridingExistingOne(t *testing.T) {
	originalHeaderValue := "original"
	overrideHeaderValue := "override"
	testConfig := `
---
testoverride:
  input:
    dest_addr: address.org
    headers:
      unique_id: %s
`

	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(testConfig, overrideHeaderValue))
	assert.NoError(t, err1)

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	assert.NotNil(t, testInput.Headers, "Header map must exist before overriding any header")

	err := applyInputOverride(cfg.TestOverride, &testInput)
	assert.NoError(t, err, "Failed to apply input overrides")

	overriddenHeader := testInput.Headers.Get("unique_id")
	assert.NotEqual(t, "", overriddenHeader, "unique_id header must be set after overriding it")
	assert.Equal(t, overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func TestIgnoredTestsRun(t *testing.T) {
	cfg, err := config.NewConfigFromString(yamlConfigIgnoreTests)
	dest, logFilePath := newTestServer(t, cfg, logText)
	assert.NoError(t, err)

	out := output.NewOutput("normal", os.Stdout)

	replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
	cfg.WithLogfile(logFilePath)

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTest))
	assert.NoError(t, err)

	replaceDestinationInTest(&ftwTest, *dest)

	res, err := Run(cfg, []test.FTWTest{ftwTest}, RunnerConfig{}, out)
	assert.NoError(t, err)
	assert.Equal(t, res.Stats.TotalFailed(), 1, "Oops, test run failed!")
}
