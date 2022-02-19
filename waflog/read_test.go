package waflog

import (
	"os"
	"testing"
	"time"

	"github.com/fzipi/go-ftw/utils"
)

var waflogTests = []struct {
	timeRegex          string
	timeFormat         string
	formattedTimeSince string
	formattedTimeUntil string
	logContents        string
	contains           string
}{
	{`\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]`,
		"ddd MMM DD HH:mm:ss.S YYYY",
		"2021-01-05T12:30:26.371Z",
		"2021-01-06T18:30:26.371Z",
		`
[Tue Jan 05 02:21:09.637165 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Pattern match "\\\\b(?:keep-alive|close),\\\\s?(?:keep-alive|close)\\\\b" at REQUEST_HEADERS:Connection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "339"] [id "920210"] [msg "Multiple/Conflicting Connection Header Data Found"] [data "close,close"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.637731 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.638572 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.647668 2021] [:error] [pid 76:tid 139683434571520] [client 172.23.0.1:58998] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFSe1VwjCgYRI9FsbHgAAAIY"]
[Tue Jan 05 02:21:09.650990 2021] [:error] [pid 208:tid 139683468142336] [client 172.23.0.1:59004] [client 172.23.0.1] ModSecurity: Warning. Match of "pm AppleWebKit Android" against "REQUEST_HEADERS:User-Agent" required. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1230"] [id "920300"] [msg "Request Missing an Accept Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFUENzekSa52B-HD6IAAAAMI"]
[Tue Jan 05 02:21:09.656997 2021] [:error] [pid 208:tid 139683468142336] [client 172.23.0.1:59004] [client 172.23.0.1] ModSecurity: Warning. Operator GT matched 1 at TX:executing_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "76"] [id "980120"] [msg "Inbound Anomaly Score (Total Inbound Score: 0 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 0, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "localhost"] [uri "/"] [unique_id "X-PNFUENzekSa52B-HD6IAAAAMI"]
[Tue Jan 05 12:35:48.846465 2021] [:error] [pid 76:tid 139682906093312] [client 172.23.0.1:42496] [client 172.23.0.1] ModSecurity: Warning. Pattern match "^[\\\\d.:]+$" at REQUEST_HEADERS:Host. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "736"] [id "920350"] [msg "Host header is a numeric IP address"] [data "192.168.1.188"] [severity "WARNING"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [hostname "192.168.1.188"] [uri "/api/nouser/config"] [unique_id "X-RdJCe1VwjCgYRI9FsbHwAAAIw"]
[Tue Jan 05 12:35:48.847143 2021] [:error] [pid 76:tid 139682906093312] [client 172.23.0.1:42496] [client 172.23.0.1] ModSecurity: Warning. Operator EQ matched 0 at REQUEST_HEADERS. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1283"] [id "920320"] [msg "Missing User Agent Header"] [severity "NOTICE"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/2"] [hostname "192.168.1.188"] [uri "/api/nouser/config"] [unique_id "X-RdJCe1VwjCgYRI9FsbHwAAAIw"]
[Tue Jan 05 12:35:48.848409 2021] [:error] [pid 76:tid 139682906093312] [client 172.23.0.1:42496] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "91"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "192.168.1.188"] [uri "/api/nouser/config"] [unique_id "X-RdJCe1VwjCgYRI9FsbHwAAAIw"]
[Tue Jan 05 12:35:48.857805 2021] [:error] [pid 76:tid 139682906093312] [client 172.23.0.1:42496] [client 172.23.0.1] ModSecurity: Warning. Operator GE matched 5 at TX:inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/RESPONSE-980-CORRELATION.conf"] [line "87"] [id "980130"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 3, 2, 0, 0"] [ver "OWASP_CRS/3.3.0"] [tag "event-correlation"] [hostname "192.168.1.188"] [uri "/api/nouser/config"] [unique_id "X-RdJCe1VwjCgYRI9FsbHwAAAIw"]
`, "X-RdJCe1VwjCgYRI9FsbHwAAAIw"},
	{`(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})`,
		"YYYY/MM/DD HH:mm:ss",
		"2021-03-15T12:30:26.371Z",
		"2021-03-18T12:30:26.371Z",
		`
2021/03/16 12:40:19 [info] 17#17: *2495 ModSecurity: Warning. Matched "Operator ` + "`" + `Within' with parameter ` + "`" + `GET HEAD POST OPTIONS' against variable ` + "`" + `REQUEST_METHOD' (Value: ` + "`" + `OTHER' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf"] [line "27"] [id "911100"] [rev ""] [msg "Method is not allowed by policy"] [data "OTHER"] [severity "2"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272/220/274"] [tag "PCI/12.1"] [hostname "172.19.0.3"] [uri "/"] [unique_id "161589841954.023243"] [ref "v0,5"], client: 172.19.0.1, server: modsec3-nginx, request: "OTHER / HTTP/1.1", host: "localhost"
2021/03/16 12:40:19 [info] 17#17: *2495 ModSecurity: Warning. Matched "Operator ` + "`" + `Pm' with parameter ` + "`" + `AppleWebKit Android' against variable ` + "`" + `REQUEST_HEADERS:User-Agent' (Value: ` + "`" + `ModSecurity CRS 3 Tests' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1360"] [id "920300"] [rev ""] [msg "Request Missing an Accept Header"] [data ""] [severity "5"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/3"] [hostname "172.19.0.3"] [uri "/"] [unique_id "161589841954.023243"] [ref "v0,5v63,23"], client: 172.19.0.1, server: modsec3-nginx, request: "OTHER / HTTP/1.1", host: "localhost"
2021/03/16 12:40:19 [info] 17#17: *2495 ModSecurity: Warning. Matched "Operator ` + "`" + `Ge' with parameter ` + "`" + `5' against variable ` + "`" + `TX:ANOMALY_SCORE' (Value: ` + "`" + `7' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "138"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 7)"] [data ""] [severity "2"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "172.19.0.3"] [uri "/"] [unique_id "161589841954.023243"] [ref ""], client: 172.19.0.1, server: modsec3-nginx, request: "OTHER / HTTP/1.1", host: "localhost"
2021/03/16 12:40:19 [info] 17#17: *2497 ModSecurity: Warning. Matched "Operator ` + "`" + `Within' with parameter ` + "`" + `GET HEAD POST OPTIONS' against variable ` + "`" + `REQUEST_METHOD' (Value: ` + "`" + `OTHER' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf"] [line "27"] [id "911100"] [rev ""] [msg "Method is not allowed by policy"] [data "OTHER"] [severity "2"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/210/272/220/274"] [tag "PCI/12.1"] [hostname "172.19.0.3"] [uri "/"] [unique_id "161589841970.216949"] [ref "v0,5"], client: 172.19.0.1, server: modsec3-nginx, request: "OTHER / HTTP/1.1", host: "localhost"
2021/03/16 12:40:19 [info] 17#17: *2497 ModSecurity: Warning. Matched "Operator ` + "`" + `Pm' with parameter ` + "`" + `AppleWebKit Android' against variable ` + "`" + `REQUEST_HEADERS:User-Agent' (Value: ` + "`" + `ModSecurity CRS 3 Tests' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1360"] [id "920300"] [rev ""] [msg "Request Missing an Accept Header"] [data ""] [severity "5"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS"] [tag "capec/1000/210/272"] [tag "PCI/6.5.10"] [tag "paranoia-level/3"] [hostname "172.19.0.3"] [uri "/"] [unique_id "161589841970.216949"] [ref "v0,5v63,23"], client: 172.19.0.1, server: modsec3-nginx, request: "OTHER / HTTP/1.1", host: "localhost"
2021/03/16 12:40:19 [info] 17#17: *2497 ModSecurity: Warning. Matched "Operator ` + "`" + `Ge' with parameter ` + "`" + `5' against variable ` + "`" + `TX:ANOMALY_SCORE' (Value: ` + "`" + `7' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "138"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 7)"] [data ""] [severity "2"] [ver "OWASP_CRS/3.3.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "172.19.0.3"] [uri "/"] [unique_id "161589841970.216949"] [ref ""], client: 172.19.0.1, server: modsec3-nginx, request: "OTHER / HTTP/1.1", host: "localhost"
`, "id \"949110\""},
}

func TestReadLogsBadTimeSpan(t *testing.T) {
	for _, log := range waflogTests {
		filename, err := utils.CreateTempFileWithContent(log.logContents, "test-errorlog-")

		// Remember to clean up the file afterwards
		defer os.Remove(filename)

		if err != nil {
			t.Fatalf(err.Error())
		}

		// Unrealistic search times, should fail
		ll := &FTWLogLines{
			FileName:   filename,
			TimeRegex:  log.timeRegex,
			TimeFormat: log.timeFormat,
			Since:      time.Now(),
			Until:      time.Now(),
		}

		b := ll.Contains(log.contains)

		if !b {
			t.Logf("Success !")
		} else {
			t.Fatal("Error")
		}
	}
}

func TestReadLogsSinceFail(t *testing.T) {
	// this test should match up to [Tue Jan 05 12:35:48.846465 2021]
	for _, log := range waflogTests {
		filename, err := utils.CreateTempFileWithContent(log.logContents, "test-errorlog-")

		// Remember to clean up the file afterwards
		defer os.Remove(filename)

		if err != nil {
			t.Fatalf(err.Error())
		}

		since := utils.GetFormattedTime(log.formattedTimeSince)
		until := utils.GetFormattedTime(log.formattedTimeUntil)

		ll := &FTWLogLines{
			FileName:   filename,
			TimeRegex:  log.timeRegex,
			TimeFormat: log.timeFormat,
			Since:      since,
			Until:      until,
		}

		b := ll.Contains(log.contains)

		if b {
			t.Logf("Success !")
		} else {
			t.Fatal("Error")
		}
	}
}

func TestReadLogsSinceGood(t *testing.T) {
	// this test should match up to [Tue Jan 05 12:35:48.846465 2021]
	for _, log := range waflogTests {
		filename, err := utils.CreateTempFileWithContent(log.logContents, "test-errorlog-")

		// Remember to clean up the file afterwards
		defer os.Remove(filename)
		if err != nil {
			t.Fatalf(err.Error())
		}

		since := utils.GetFormattedTime(log.formattedTimeSince)

		ll := &FTWLogLines{
			FileName:   filename,
			TimeRegex:  log.timeRegex,
			TimeFormat: log.timeFormat,
			Since:      since,
			Until:      time.Now(),
		}

		b := ll.Contains(log.contains)

		if b {
			t.Logf("Success !")
		} else {
			t.Fatal("Error")
		}
	}
}

func TestReadLogsWithBadRegex(t *testing.T) {
	for _, log := range waflogTests {
		filename, err := utils.CreateTempFileWithContent(log.logContents, "test-errorlog-")

		// Remember to clean up the file afterwards
		defer os.Remove(filename)

		if err != nil {
			t.Fatalf(err.Error())
		}

		since := utils.GetFormattedTime("2021-01-05T12:30:26.371Z")

		ll := &FTWLogLines{
			FileName:   filename,
			TimeRegex:  "$^",
			TimeFormat: log.timeFormat,
			Since:      since,
			Until:      time.Now(),
		}

		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()

		_ = ll.Contains(log.contains)

	}

}

func TestReadLogsBadTimeFormat(t *testing.T) {
	for _, log := range waflogTests {
		filename, err := utils.CreateTempFileWithContent(log.logContents, "test-errorlog-")

		// Remember to clean up the file afterwards
		defer os.Remove(filename)

		if err != nil {
			t.Fatalf(err.Error())
		}

		// Unrealistic search times, should fail
		ll := &FTWLogLines{
			FileName:   filename,
			TimeRegex:  log.timeRegex,
			TimeFormat: "j q k l m %",
			Since:      time.Now(),
			Until:      time.Now(),
		}

		b := ll.Contains(log.contains)

		if !b {
			t.Logf("Success !")
		} else {
			t.Fatal("Error")
		}
	}
}
