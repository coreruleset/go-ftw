package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/fzipi/go-ftw/config"
	"github.com/fzipi/go-ftw/ftwhttp"
	"github.com/fzipi/go-ftw/test"
	"github.com/fzipi/go-ftw/utils"
)

var yamlConfig = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
  ignore:
    '920400-1': 'This test result must be ignored'
`

var yamlConfigOverride = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
testoverride:
  input:
    dest_addr: 'httpbin.org'
    port: '80'
    protocol: 'http'
`

var yamlBrokenConfigOverride = `
---
logfile: 'tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
testoverride:
  input:
    dest_addr: 'httpbin.org'
    port: '80'
    this_does_not_exist: 'test'
`

var yamlCloudConfig = `
---
testoverride:
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
            dest_addr: "httpbin.org"
            port: 80
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "httpbin.org"
          output:
            expect_error: False
            status: [200]
  - test_title: "008"
    stages:
      - stage:
          input:
            dest_addr: TEST_ADDR
            port: TEST_PORT
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
            dest_addr: TEST_ADDR
            port: TEST_PORT
            version: "HTTP/1.1"
            method: "OTHER"
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "localhost"
          output:
            response_contains: "Hello, client"
  - test_title: "101"
    description: "this tests exceptions"
    stages:
      - stage:
          input:
            dest_addr: "1.1.1.1"
            port: 8090
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "none.host"
          output:
            expect_error: True
  - test_title: "102"
    description: this tests exceptions
    stages:
      - stage:
          input:
            dest_addr: "1.1.1.1"
            port: 8090
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Host: "none.host"
              Accept: "*/*"
            encoded_request: 'UE9TVCAvaW5kZXguaHRtbCBIVFRQLzEuMQ0KSG9zdDogMTkyLjE2OC4xLjIzDQpVc2VyLUFnZW50OiBjdXJsLzcuNDMuMA0KQWNjZXB0OiAqLyoNCkNvbnRlbnQtTGVuZ3RoOiA2NA0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbm5lY3Rpb246IGNsb3NlDQoNCmQ9MTsyOzM7NDs1XG4xO0BTVU0oMSsxKSpjbWR8JyBwb3dlcnNoZWxsIElFWCh3Z2V0IDByLnBlL3ApJ1whQTA7Mw=='
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
            dest_addr: "test.me"
            port: 8080
            headers:
                User-Agent: "ModSecurity CRS 3 Tests"
                Host: "httpbin.org"
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
            dest_addr: "httpbin.org"
            port: 80
            headers:
                User-Agent: "ModSecurity CRS 3 Tests"
                Host: "httpbin.org"
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
            dest_addr: TEST_ADDR
            port: TEST_PORT
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
            dest_addr: TEST_ADDR
            port: TEST_PORT
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
            dest_addr: TEST_ADDR
            port: TEST_PORT
            headers:
              User-Agent: "ModSecurity CRS 3 Tests"
              Accept: "*/*"
              Host: "none.host"
          output:
            status: [413]
`

// Error checking omitted for brevity
func newTestServer() *httptest.Server {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello, client"))
	}))

	return ts
}

// replace localhost or 127.0.0.1 in tests with test url
func replaceLocalhostWithTestServer(yaml string, d ftwhttp.Destination) string {
	destChanged := strings.ReplaceAll(yaml, "TEST_ADDR", d.DestAddr)
	replacedYaml := strings.ReplaceAll(destChanged, "TEST_PORT", strconv.Itoa(d.Port))

	return replacedYaml
}

func TestRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	// setup test webserver (not a waf)
	server := newTestServer()
	d, err := ftwhttp.DestinationFromString(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse destination")
	}
	yamlTestContent := replaceLocalhostWithTestServer(yamlTest, *d)

	filename, err := utils.CreateTempFileWithContent(yamlTestContent, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("showtime and execute all", func(t *testing.T) {
		if res := Run("", "", true, false, tests); res > 0 {
			t.Errorf("Oops, %d tests failed to run!", res)
		}
	})

	t.Run("be verbose and execute all", func(t *testing.T) {
		if res := Run("0*", "", true, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("don't showtime and execute all", func(t *testing.T) {
		if res := Run("0*", "", false, false, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		if res := Run("008", "0*", false, false, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("exclude test 010", func(t *testing.T) {
		if res := Run("*", "010", false, false, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("test exceptions 1", func(t *testing.T) {
		if res := Run("1*", "0*", false, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	server.Close()
	os.Remove(logName)
	os.Remove(filename)
}

func TestOverrideRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlConfigOverride)
	if err != nil {
		t.Errorf("Failed!")
	}
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	filename, err := utils.CreateTempFileWithContent(yamlTestOverride, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("override and execute all", func(t *testing.T) {
		if res := Run("", "", false, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	os.Remove(logName)
	os.Remove(filename)
}

func TestBrokenOverrideRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlBrokenConfigOverride)
	if err != nil {
		t.Errorf("Failed!")
	}
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	filename, err := utils.CreateTempFileWithContent(yamlTestOverride, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("showtime and execute all", func(t *testing.T) {
		if res := Run("", "", false, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	os.Remove(logName)
	os.Remove(filename)
}

func TestDisabledRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	filename, err := utils.CreateTempFileWithContent(yamlDisabledTest, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("showtime and execute all", func(t *testing.T) {
		if res := Run("*", "", false, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	os.Remove(logName)
	os.Remove(filename)
}

func TestLogsRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	filename, err := utils.CreateTempFileWithContent(yamlTestLogs, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("showtime and execute all", func(t *testing.T) {
		if res := Run("", "", false, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	os.Remove(logName)
	os.Remove(filename)
}

func TestCloudRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlCloudConfig)
	if err != nil {
		t.Errorf("Failed!")
	}

	filename, err := utils.CreateTempFileWithContent(yamlTestLogs, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("showtime and execute all", func(t *testing.T) {
		if res := Run("", "", false, true, tests); res > 0 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	os.Remove(filename)
}

func TestFailedTestsRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	err := config.NewConfigFromString(yamlConfig)
	if err != nil {
		t.Errorf("Failed!")
	}
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	// setup test webserver (not a waf)
	server := newTestServer()
	d, err := ftwhttp.DestinationFromString(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse destination")
	}
	yamlTestContent := replaceLocalhostWithTestServer(yamlFailedTest, *d)

	filename, err := utils.CreateTempFileWithContent(yamlTestContent, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	} else {
		fmt.Printf("Using testfile %s\n", filename)
	}

	tests, err := test.GetTestsFromFiles(filename)
	if err != nil {
		t.Error(err.Error())
	}

	t.Run("run test that fails", func(t *testing.T) {
		if res := Run("*", "", false, false, tests); res != 1 {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	server.Close()
	os.Remove(logName)
	os.Remove(filename)
}
