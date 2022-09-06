package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/rs/zerolog/log"

	"github.com/fzipi/go-ftw/check"
	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/ftwhttp"
	"github.com/fzipi/go-ftw/test"
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
func newTestServer(t *testing.T, logLines string) (destination *ftwhttp.Destination, logFilePath string) {
	logFilePath = setUpLogFileForTestServer(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, client"))

		writeTestServerLog(t, logLines, logFilePath, r)
	}))

	// close server after test
	t.Cleanup(ts.Close)

	dest, err := ftwhttp.DestinationFromString(ts.URL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	return dest, logFilePath
}

// Error checking omitted for brevity
func newTestServerForCloudTest(t *testing.T, responseStatus int, logLines string) (server *httptest.Server, destination *ftwhttp.Destination) {
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(responseStatus)
		_, _ = w.Write([]byte("Hello, client"))
	}))

	// close server after test
	t.Cleanup(server.Close)

	dest, err := ftwhttp.DestinationFromString(server.URL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	return server, dest
}

func setUpLogFileForTestServer(t *testing.T) (logFilePath string) {
	// log to the configured file
	if config.FTWConfig != nil && config.FTWConfig.RunMode == config.DefaultRunMode {
		logFilePath = config.FTWConfig.LogFile
	}
	// if no file has been configured, create one and handle cleanup
	if logFilePath == "" {
		file, err := os.CreateTemp("", "go-ftw-test-*.log")
		if err != nil {
			t.Error(err)
		}
		logFilePath = file.Name()
		t.Cleanup(func() {
			os.Remove(logFilePath)
			log.Info().Msgf("Deleting temporary file '%s'", logFilePath)
		})
	}
	return logFilePath
}

func writeTestServerLog(t *testing.T, logLines string, logFilePath string, r *http.Request) {
	// write supplied log lines, emulating the output of the rule engine
	logMessage := logLines
	// if the request has the special test header, log the request instead
	// this emulates the log marker rule
	if r.Header.Get(config.FTWConfig.LogMarkerHeaderName) != "" {
		logMessage = fmt.Sprintf("request line: %s %s %s, headers: %s\n", r.Method, r.RequestURI, r.Proto, r.Header)
	}
	file, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	defer file.Close()

	_, err = file.WriteString(logMessage)
	if err != nil {
		t.Error(err)
		t.FailNow()
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

func replaceDestinationInConfiguration(dest ftwhttp.Destination) {
	replaceableAddress := "TEST_ADDR"
	replaceablePort := -1

	input := &config.FTWConfig.TestOverride.Input
	if input.DestAddr != nil && *input.DestAddr == replaceableAddress {
		input.DestAddr = &dest.DestAddr
	}
	if input.Port != nil && *input.Port == replaceablePort {
		input.Port = &dest.Port
	}
}

func TestRun(t *testing.T) {
	t.Cleanup(config.Reset)

	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}

	// setup test webserver (not a waf)
	dest, logFilePath := newTestServer(t, logText)
	config.FTWConfig.LogFile = logFilePath
	ftwTest, err := test.GetTestFromYaml([]byte(yamlTest))
	if err != nil {
		t.Error(err)
	}
	replaceDestinationInTest(&ftwTest, *dest)

	t.Run("show time and execute all", func(t *testing.T) {
		if res := Run([]test.FTWTest{ftwTest}, Config{
			ShowTime: true,
			Quiet:    true,
		}); res.Stats.TotalFailed() > 0 {
			t.Errorf("Oops, %d tests failed to run!", res.Stats.TotalFailed())
		}
	})

	t.Run("be verbose and execute all", func(t *testing.T) {
		if res := Run([]test.FTWTest{ftwTest}, Config{
			Include:  regexp.MustCompile("0*"),
			ShowTime: true,
		}); res.Stats.TotalFailed() > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("don't show time and execute all", func(t *testing.T) {
		if res := Run([]test.FTWTest{ftwTest}, Config{
			Include: regexp.MustCompile("0*"),
		}); res.Stats.TotalFailed() > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		if res := Run([]test.FTWTest{ftwTest}, Config{
			Include: regexp.MustCompile("008"),
			Exclude: regexp.MustCompile("0*"),
		}); res.Stats.TotalFailed() > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("exclude test 010", func(t *testing.T) {
		if res := Run([]test.FTWTest{ftwTest}, Config{
			Exclude: regexp.MustCompile("010"),
		}); res.Stats.TotalFailed() > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("test exceptions 1", func(t *testing.T) {
		if res := Run([]test.FTWTest{ftwTest}, Config{
			Include: regexp.MustCompile("1*"),
			Exclude: regexp.MustCompile("0*"),
			Quiet:   true,
		}); res.Stats.TotalFailed() > 0 {
			t.Error("Oops, test run failed!")
		}
	})
}

func TestOverrideRun(t *testing.T) {
	t.Cleanup(config.Reset)

	// setup test webserver (not a waf)
	err := config.NewConfigFromString(yamlConfigOverride)
	if err != nil {
		t.Error(err)
	}

	dest, logFilePath := newTestServer(t, logText)

	replaceDestinationInConfiguration(*dest)
	config.FTWConfig.LogFile = logFilePath

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		t.Fatalf("Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverride))
	if err != nil {
		t.Error(err)
	}
	replaceDestinationInTest(&ftwTest, *fakeDestination)

	if res := Run([]test.FTWTest{ftwTest}, Config{
		Quiet: true,
	}); res.Stats.TotalFailed() > 0 {
		t.Error("Oops, test run failed!")
	}
}

func TestBrokenOverrideRun(t *testing.T) {
	t.Cleanup(config.Reset)

	err := config.NewConfigFromString(yamlBrokenConfigOverride)
	if err != nil {
		t.Errorf("Failed!")
	}

	dest, logFilePath := newTestServer(t, logText)

	replaceDestinationInConfiguration(*dest)
	config.FTWConfig.LogFile = logFilePath

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		t.Fatalf("Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverride))
	if err != nil {
		t.Error(err)
	}
	replaceDestinationInTest(&ftwTest, *fakeDestination)

	// the test should succeed, despite the unknown override property
	if res := Run([]test.FTWTest{ftwTest}, Config{
		Quiet: true,
	}); res.Stats.TotalFailed() > 0 {
		t.Error("Oops, test run failed!")
	}
}

func TestBrokenPortOverrideRun(t *testing.T) {
	t.Cleanup(config.Reset)

	// TestServer initialized first to retrieve the correct port number
	dest, logFilePath := newTestServer(t, logText)

	// replace destination port inside the yaml with the retrieved one
	err := config.NewConfigFromString(fmt.Sprintf(yamlConfigPortOverride, dest.Port))
	if err != nil {
		t.Errorf("Failed!")
	}

	replaceDestinationInConfiguration(*dest)
	config.FTWConfig.LogFile = logFilePath

	// replace host and port with values that can be overridden by config
	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		t.Fatalf("Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestOverrideWithNoPort))
	if err != nil {
		t.Error(err)
	}
	replaceDestinationInTest(&ftwTest, *fakeDestination)

	// the test should succeed, despite the unknown override property
	if res := Run([]test.FTWTest{ftwTest}, Config{
		Quiet: true,
	}); res.Stats.TotalFailed() > 0 {
		t.Error("Oops, test run failed!")
	}
}

func TestDisabledRun(t *testing.T) {
	t.Cleanup(config.Reset)

	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}

	fakeDestination, err := ftwhttp.DestinationFromString("http://example.com:1234")
	if err != nil {
		t.Fatalf("Failed to parse fake destination")
	}

	ftwTest, err := test.GetTestFromYaml([]byte(yamlDisabledTest))
	if err != nil {
		t.Error(err)
	}
	replaceDestinationInTest(&ftwTest, *fakeDestination)

	if res := Run([]test.FTWTest{ftwTest}, Config{
		Quiet: true,
	}); res.Stats.TotalFailed() > 0 {
		t.Error("Oops, test run failed!")
	}
}

func TestLogsRun(t *testing.T) {
	t.Cleanup(config.Reset)

	// setup test webserver (not a waf)
	dest, logFilePath := newTestServer(t, logText)

	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
	replaceDestinationInConfiguration(*dest)
	config.FTWConfig.LogFile = logFilePath

	ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
	if err != nil {
		t.Error(err)
	}
	replaceDestinationInTest(&ftwTest, *dest)

	if res := Run([]test.FTWTest{ftwTest}, Config{
		Quiet: true,
	}); res.Stats.TotalFailed() > 0 {
		t.Error("Oops, test run failed!")
	}
}

func TestCloudRun(t *testing.T) {
	t.Cleanup(config.Reset)

	err := config.NewConfigFromString(yamlCloudConfig)
	if err != nil {
		t.Errorf("Failed!")
	}

	ftwTestDummy, err := test.GetTestFromYaml([]byte(yamlTestLogs))
	if err != nil {
		t.Error(err)
	}

	t.Run("don't show time and execute all", func(t *testing.T) {
		for testCaseIndex, testCaseDummy := range ftwTestDummy.Tests {
			for stageIndex := range testCaseDummy.Stages {
				// Read the tests for every stage so we can replace the destination
				// in each run. The server needs to be configured for each stage
				// individually.
				ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
				if err != nil {
					t.Error(err)
				}
				testCase := &ftwTest.Tests[testCaseIndex]
				stage := &testCase.Stages[stageIndex].Stage

				ftwCheck := check.NewCheck(config.FTWConfig)

				// this mirrors check.SetCloudMode()
				responseStatus := 200
				if stage.Output.LogContains != "" {
					responseStatus = 403
				} else if stage.Output.NoLogContains != "" {
					responseStatus = 405
				}
				server, dest := newTestServerForCloudTest(t, responseStatus, logText)

				replaceDestinationInConfiguration(*dest)

				replaceDestinationInTest(&ftwTest, *dest)
				if err != nil {
					t.Error(err)
				}
				runContext := TestRunContext{
					Include:  nil,
					Exclude:  nil,
					ShowTime: false,
					Output:   true,
					Client:   ftwhttp.NewClient(ftwhttp.NewClientConfig()),
					LogLines: nil,
				}

				RunStage(&runContext, ftwCheck, *testCase, *stage)
				if runContext.Stats.TotalFailed() > 0 {
					t.Error("Oops, test run failed!")
				}

				server.Close()
			}
		}
	})
}

func TestFailedTestsRun(t *testing.T) {
	t.Cleanup(config.Reset)

	err := config.NewConfigFromString(yamlConfig)
	dest, logFilePath := newTestServer(t, logText)
	if err != nil {
		t.Errorf("Failed!")
	}
	replaceDestinationInConfiguration(*dest)
	config.FTWConfig.LogFile = logFilePath

	ftwTest, err := test.GetTestFromYaml([]byte(yamlFailedTest))
	if err != nil {
		t.Error(err.Error())
	}
	replaceDestinationInTest(&ftwTest, *dest)

	if res := Run([]test.FTWTest{ftwTest}, Config{}); res.Stats.TotalFailed() != 1 {
		t.Error("Oops, test run failed!")
	}
}

func TestApplyInputOverrideSetHostFromDestAddr(t *testing.T) {
	t.Cleanup(config.Reset)

	originalHost := "original.com"
	overrideHost := "override.com"
	testInput := test.Input{
		DestAddr: &originalHost,
	}
	config.FTWConfig = &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Input: test.Input{
				DestAddr: &overrideHost,
			},
		},
	}

	err := applyInputOverride(&testInput)
	if err != nil {
		t.Error("Failed to apply input overrides", err)
	}

	if *testInput.DestAddr != overrideHost {
		t.Error("`dest_addr` should have been overridden")
	}
	if testInput.Headers == nil {
		t.Error("Header map must exist after overriding `dest_addr`")
	}

	hostHeader := testInput.Headers.Get("Host")
	if hostHeader == "" {
		t.Error("Host header must be set after overriding `dest_addr`")
	}
	if hostHeader != overrideHost {
		t.Error("Host header must be identical to `dest_addr` after overrding `dest_addr`")
	}
}
