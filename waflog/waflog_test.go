package waflog

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var apacheWaflog = `
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
`

func TestReadLogsBadTimeSpan(t *testing.T) { // Create our Temp File:  This will create a filename like /tmp/prefix-123456
	// We can use a pattern of "pre-*.txt" to get an extension like: /tmp/pre-123456.txt
	tmpFile, err := ioutil.TempFile(os.TempDir(), "apache-errorlog-")
	if err != nil {
		t.Fatal("Cannot create temporary file", err)
	}

	// Remember to clean up the file afterwards
	defer os.Remove(tmpFile.Name())

	// Example writing to the file
	text := []byte(apacheWaflog)
	if _, err = tmpFile.Write(text); err != nil {
		t.Fatal("Failed to write to temporary file", err)
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Unrealistic search times, should fail
	ll := FTWLogLines{
		FileName:   tmpFile.Name(),
		TimeRegex:  `\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]`,
		TimeFormat: "ddd MMM DD HH:mm:ss.S YYYY",
		Since:      time.Now(),
		Until:      time.Now(),
	}

	b := SearchLogContains("X-PNFSe1VwjCgYRI9FsbHgAAAIY", &ll)

	if !b {
		t.Logf("Sucess !")
	} else {
		t.Fatal("Error")
	}
}

func TestReadLogsSinceFail(t *testing.T) {
	// this test should match up to [Tue Jan 05 12:35:48.846465 2021]
	tmpFile, err := ioutil.TempFile(os.TempDir(), "apache-errorlog-")
	if err != nil {
		t.Fatal("Cannot create temporary file", err)
	}

	// Remember to clean up the file afterwards
	defer os.Remove(tmpFile.Name())

	// Example writing to the file
	text := []byte(apacheWaflog)
	if _, err = tmpFile.Write(text); err != nil {
		t.Fatal("Failed to write to temporary file", err)
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	layout := "2006-01-02T15:04:05.000Z"
	sinceTime := "2021-01-05T00:30:26.371Z"
	since, _ := time.Parse(layout, sinceTime)
	untilTime := "2021-01-05T08:30:26.371Z"
	until, _ := time.Parse(layout, untilTime)

	// Unrealistic search times, should fail
	ll := FTWLogLines{
		FileName:   tmpFile.Name(),
		TimeRegex:  `\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]`,
		TimeFormat: "ddd MMM DD HH:mm:ss.S YYYY",
		Since:      since, // Some date in the past
		Until:      until,
	}

	b := SearchLogContains("X-PNFSe1VwjCgYRI9FsbHgAAAIY", &ll)

	if b {
		t.Logf("Sucess !")
	} else {
		t.Fatal("Error")
	}
}

func TestReadLogsSinceGood(t *testing.T) {
	// this test should match up to [Tue Jan 05 12:35:48.846465 2021]
	tmpFile, err := ioutil.TempFile(os.TempDir(), "apache-errorlog-")
	if err != nil {
		t.Fatal("Cannot create temporary file", err)
	}

	// Remember to clean up the file afterwards
	defer os.Remove(tmpFile.Name())

	// Example writing to the file
	text := []byte(apacheWaflog)
	if _, err = tmpFile.Write(text); err != nil {
		t.Fatal("Failed to write to temporary file", err)
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	layout := "2006-01-02T15:04:05.000Z"
	str := "2021-01-05T12:30:26.371Z"
	since, _ := time.Parse(layout, str)

	// Unrealistic search times, should fail
	ll := FTWLogLines{
		FileName:   tmpFile.Name(),
		TimeRegex:  `\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]`,
		TimeFormat: "ddd MMM DD HH:mm:ss.S YYYY",
		Since:      since, // Some date in the past
		Until:      time.Now(),
	}

	b := SearchLogContains("X-RdJCe1VwjCgYRI9FsbHwAAAIw", &ll)

	if b {
		t.Logf("Sucess !")
	} else {
		t.Fatal("Error")
	}
}
