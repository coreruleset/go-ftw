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
	httpftw "github.com/fzipi/go-ftw/http"
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
`

var logText = `
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
`

var yamlTest = `
---
  meta:
    author: "tester"
    enabled: true
    name: "go-ftw.yaml"
    description: "Example Test"
  tests:
    -
      test_title: 001
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
              expect_error: True
    -
      test_title: 008
      stages:
        -
          stage:
            input:
              dest_addr: TEST_ADDR
              port: TEST_PORT
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "localhost"
            output:
              status: [200]
    -
      test_title: 010
      stages:
        -
          stage:
            input:
              dest_addr: TEST_ADDR
              port: TEST_PORT
              version: "HTTP/1.1"
              method: "OTHER"
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "localhost"
            output:
              response_contains: "Hello, client"
`

// Error checking omitted for brevity
func testServer() (server *httptest.Server) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))

	return ts
}

// replace localhost or 127.0.0.1 in tests with test url
func replaceLocalhostWithTestServer(yaml string, url string) string {
	d := httpftw.DestinationFromString(url)

	destChanged := strings.ReplaceAll(yaml, "TEST_ADDR", d.DestAddr)
	replacedYaml := strings.ReplaceAll(destChanged, "TEST_PORT", strconv.Itoa(d.Port))

	return replacedYaml
}

func TestRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	config.ImportFromString(yamlConfig)
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	// setup test webserver (not a waf)
	server := testServer()

	// We should inject server.URL now into some tests
	// d := DestinationFromString(server.URL)
	yamlTestContent := replaceLocalhostWithTestServer(yamlTest, server.URL)

	filename, err := utils.CreateTempFileWithContent(yamlTestContent, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	}

	tests, _ := test.GetTestsFromFiles(filename)

	t.Run("showtime and execute all", func(t *testing.T) {
		if err := Run("", "", false, true, tests); err != nil {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("don't showtime and execute all", func(t *testing.T) {
		if err := Run("*", "", false, false, tests); err != nil {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		if err := Run("008", "*", false, false, tests); err != nil {
			t.Error("Oops, test run failed!")
		}
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		if err := Run("*", "010", false, false, tests); err != nil {
			t.Error("Oops, test run failed!")
		}
	})

	// Clean up
	server.Close()
	os.Remove(logName)
	os.Remove(filename)
}
