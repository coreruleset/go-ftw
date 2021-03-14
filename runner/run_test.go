package runner

import (
	"os"
	"testing"

	"github.com/fzipi/go-ftw/config"
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
              dest_addr: "www.example.com"
              port: 80
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "www.example.com"
            output:
              status: [200]
    -
      test_title: 008
      stages:
        -
          stage:
            input:
              dest_addr: "127.0.0.1"
              port: 80
              method: "OPTIONS"
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "localhost"
            output:
              expect_error: True
    -
      test_title: 010
      stages:
        -
          stage:
            input:
              dest_addr: "127.0.0.1"
              port: 80
              method: "OTHER"
              headers:
                  User-Agent: "ModSecurity CRS 3 Tests"
                  Host: "localhost"
            output:
              expect_error: True
`

func TestRun(t *testing.T) {
	// This is an integration test, and depends on having the waf up for checking logs
	// We might use it to check for error, so we don't need anything up and running
	config.ImportFromString(yamlConfig)
	logName, _ := utils.CreateTempFileWithContent(logText, "test-apache-*.log")
	config.FTWConfig.LogFile = logName

	filename, err := utils.CreateTempFileWithContent(yamlTest, "goftw-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed!: %s\n", err.Error())
	}

	defer os.Remove(filename) // clean up

	tests, _ := test.GetTestsFromFiles("/tmp/goftw-test-*.yaml")

	t.Run("showtime and execute all", func(t *testing.T) {
		if res := Run("", "", false, true, tests); !res {
			t.Fatalf("Oops, test run failed!")
		}
	})

	t.Run("don't showtime and execute all", func(t *testing.T) {
		if res := Run("*", "", false, false, tests); !res {
			t.Fatalf("Oops, test run failed!")
		}
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		if res := Run("008", "*", false, false, tests); !res {
			t.Fatalf("Oops, test run failed!")
		}
	})

	t.Run("execute only test 008 but exclude all", func(t *testing.T) {
		if res := Run("*", "010", false, false, tests); !res {
			t.Fatalf("Oops, test run failed!")
		}
	})
}
