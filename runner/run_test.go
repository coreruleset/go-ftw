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
	"TestDisabledRun": `---
mode: 'cloud'
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
    "001": "This test result must be ignored"
  forcefail:
    "008": "This test should pass, but it is going to fail"
  forcepass:
    "099": "This test failed, but it shall pass!"
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
	"TestDisabledRun":       "http://example.com:1234",
}

type runTestSuite struct {
	suite.Suite
	cfg          *config.FTWConfiguration
	ftwTests     []test.FTWTest
	logFilePath  string
	out          *output.Output
	ts           *httptest.Server
	dest         *ftwhttp.Destination
	tempFileName string
}

// type runCloudTestSuite struct {
//	suite.Suite
//	cfg          *config.FTWConfiguration
//	ftwTests     []test.FTWTest
//	logFilePath  string
//	out          *output.Output
//	ts           *httptest.Server
//	dest         *ftwhttp.Destination
//	tempFileName string
//}
//
// type inputOverrideTestSuite struct {
//	suite.Suite
//}

// Error checking omitted for brevity
func (s *runTestSuite) newTestServer(logLines string) {
	var err error
	s.setUpLogFileForTestServer()

	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, client"))

		s.writeTestServerLog(logLines, r)
	}))

	s.dest, err = ftwhttp.DestinationFromString((s.ts).URL)
	s.Require().NoError(err, "cannot get destination from string")
}

func (s *runTestSuite) setUpLogFileForTestServer() {
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

func (s *runTestSuite) writeTestServerLog(logLines string, r *http.Request) {
	// write supplied log lines, emulating the output of the rule engine
	logMessage := logLines
	// if the request has the special test header, log the request instead
	// this emulates the log marker rule
	if r.Header.Get(s.cfg.LogMarkerHeaderName) != "" {
		logMessage = fmt.Sprintf("request line: %s %s %s, headers: %s\n", r.Method, r.RequestURI, r.Proto, r.Header)
	}
	file, err := os.OpenFile(s.logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	s.NoError(err, "cannot open file")

	defer file.Close()

	n, err := file.WriteString(logMessage)
	s.Len(logMessage, n, "cannot write log message to file")
	s.NoError(err, "cannot write log message to file")
}

func (s *runTestSuite) SetupTest() {
	s.cfg = config.NewDefaultConfig()
	// setup test webserver (not a waf)
	s.newTestServer(logText)
	if s.logFilePath != "" {
		s.cfg.WithLogfile(s.logFilePath)
	}

	s.out = output.NewOutput("normal", os.Stdout)
}

func (s *runTestSuite) TearDownTest() {
	s.ts.Close()
}

func (s *runTestSuite) BeforeTest(_ string, name string) {
	var err error
	var cfg string
	var ok bool

	// if we have a configuration for this test, use it
	// else use the default configuration
	if cfg, ok = testConfigMap[name]; !ok {
		cfg = testConfigMap["BaseConfig"]
	}

	// if we have a destination for this test, use it
	// else use the default destination
	if s.dest == nil {
		s.dest, err = ftwhttp.DestinationFromString(destinationMap[name])
		s.NoError(err)
	}

	log.Info().Msgf("Using port %d and addd '%s'", s.dest.Port, s.dest.DestAddr)

	// set up variables for template
	vars := map[string]interface{}{
		"TestPort": s.dest.Port,
		"TestAddr": s.dest.DestAddr,
	}

	// set up configuration from template
	configTmpl, err := template.New("config-test").Parse(cfg)
	s.NoError(err, "cannot parse template")
	buf := &bytes.Buffer{}
	err = configTmpl.Execute(buf, vars)
	s.NoError(err, "cannot execute template")
	s.cfg, err = config.NewConfigFromString(buf.String())
	s.NoError(err, "cannot get config from string")
	if s.logFilePath != "" {
		s.cfg.WithLogfile(s.logFilePath)
	}
	// get tests template from file
	tmpl, err := template.ParseFiles(fmt.Sprintf("testdata/%s.yaml", name))
	s.NoError(err)
	// create a temporary file to hold the test
	testFileContents, err := os.CreateTemp("testdata", "mock-test-*.yaml")
	s.NoError(err, "cannot create temporary file")
	err = tmpl.Execute(testFileContents, vars)
	s.NoError(err, "cannot execute template")
	// get tests from file
	s.ftwTests, err = test.GetTestsFromFiles(testFileContents.Name())
	s.NoError(err, "cannot get tests from file")
	// save the name of the temporary file so we can delete it later
	s.tempFileName = testFileContents.Name()
}

func (s *runTestSuite) AfterTest(_ string, _ string) {
	err := os.Remove(s.logFilePath)
	s.NoError(err, "cannot remove log file")
	log.Info().Msgf("Deleting temporary file '%s'", s.logFilePath)
	if s.tempFileName != "" {
		err = os.Remove(s.tempFileName)
		s.NoError(err, "cannot remove test file")
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
		s.NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
	})

	s.Run("be verbose and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include:  regexp.MustCompile("0*"),
			ShowTime: true,
		}, s.out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "verbose and execute all failed")
	})

	s.Run("don't show time and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include: regexp.MustCompile("0*"),
		}, s.out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("execute only test 008 but exclude all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include: regexp.MustCompile("008"),
			Exclude: regexp.MustCompile("0*"),
		}, s.out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "do not show time and execute all failed")
	})

	s.Run("exclude test 010", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Exclude: regexp.MustCompile("010"),
		}, s.out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "failed to exclude test")
	})

	s.Run("test exceptions 1", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Include: regexp.MustCompile("1*"),
			Exclude: regexp.MustCompile("0*"),
			Output:  output.Quiet,
		}, s.out)
		s.NoError(err)
		s.Equal(res.Stats.TotalFailed(), 0, "failed to test exceptions")
	})
}

func (s *runTestSuite) TestRunMultipleMatches() {
	s.Run("execute multiple...test", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			Output: output.Quiet,
		}, s.out)
		s.NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 1, "Oops, %d tests failed to run! Expected 1 failing test", res.Stats.TotalFailed())
	})
}

func (s *runTestSuite) TestOverrideRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
		Output: output.Quiet,
	}, s.out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestBrokenOverrideRun() {
	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestBrokenPortOverrideRun() {
	// the test should succeed, despite the unknown override property
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestDisabledRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestLogsRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.NoError(err)
	s.LessOrEqual(0, res.Stats.TotalFailed(), "Oops, test run failed!")
}

func (s *runTestSuite) TestFailedTestsRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.NoError(err)
	s.Equal(1, res.Stats.TotalFailed())
}

func (s *runTestSuite) TestIgnoredTestsRun() {
	res, err := Run(s.cfg, s.ftwTests, RunnerConfig{}, s.out)
	s.NoError(err)
	s.Equal(res.Stats.TotalFailed(), 1, "Oops, test run failed!")
}

// func (s *runCloudTestSuite) TestCloudRun() {
//    stats := NewRunStats()
//
//    ftwTestDummy, err := test.GetTestFromYaml([]byte(yamlTestLogs))
//    s.NoError(err)
//
//    s.Run("don't show time and execute all", func() {
//        for testCaseIndex, testCaseDummy := range ftwTestDummy.Tests {
//            for stageIndex := range testCaseDummy.Stages {
//                // Read the tests for every stage, so we can replace the destination
//                // in each run. The server needs to be configured for each stage
//                // individually.
//                ftwTest, err := test.GetTestFromYaml([]byte(yamlTestLogs))
//                s.NoError(err)
//                testCase := &ftwTest.Tests[testCaseIndex]
//                stage := &testCase.Stages[stageIndex].Stage
//
//                ftwCheck := check.NewCheck(s.cfg)
//
//                // this mirrors check.SetCloudMode()
//                responseStatus := 200
//                if stage.Output.LogContains != "" {
//                    responseStatus = 403
//                } else if stage.Output.NoLogContains != "" {
//                    responseStatus = 405
//                }
//                server, dest := s.newTestServerForCloudTest(responseStatus)
//
//                replaceDestinationInConfiguration(&cfg.TestOverride, *dest)
//
//                replaceDestinationInTest(&ftwTest, *dest)
//                s.NoError(err)
//                client, err := ftwhttp.NewClient(ftwhttp.NewClientConfig())
//                s.NoError(err)
//                runContext := TestRunContext{
//                    Config:   s.cfg,
//                    Include:  nil,
//                    Exclude:  nil,
//                    ShowTime: false,
//                    Stats:    stats,
//                    Output:   out,
//                    Client:   client,
//                    LogLines: nil,
//                }
//
//                err = RunStage(&runContext, ftwCheck, *testCase, *stage)
//                s.NoError(err)
//                s.LessOrEqual(0, runContext.Stats.TotalFailed(), "Oops, test run failed!")
//
//                server.Close()
//            }
//        }
//    })
//}

/*

func (s *inputOverrideTestSuite) TestApplyInputOverrideSetHostFromDestAddr() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideSetHostFromHostHeaderOverride() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideSetHeaderOverridingExistingOne() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrides() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideURI() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideVersion() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideMethod() {
	originalMethod := "original.com"
	overrideMethod := "override.com"
	testInput := test.Input{
		Method: &originalMethod,
	}
	cfg, err1 := config.NewConfigFromString(fmt.Sprintf(yamlConfigMethodOverride, overrideMethod))
	s.NoError(err1)
	err := applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideMethod, *testInput.Method, "`Method` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideData() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideStopMagic() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideEncodedRequest() {
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

func (s *inputOverrideTestSuite) TestApplyInputOverrideRAWRequest() {
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

*/
