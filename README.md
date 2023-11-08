# Go-FTW - Framework for Testing WAFs in Go!

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Go Report Card](https://goreportcard.com/badge/github.com/coreruleset/go-ftw)](https://goreportcard.com/report/github.com/coreruleset/go-ftw)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/coreruleset/go-ftw)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/coreruleset/go-ftw)](https://pkg.go.dev/github.com/coreruleset/go-ftw)
[![Release](https://img.shields.io/github/v/release/coreruleset/go-ftw.svg?style=flat-square)](https://github.com/coreruleset/go-ftw/releases/latest)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/coreruleset/go-ftw.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/coreruleset/go-ftw/alerts/)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=coreruleset_go-ftw&metric=coverage)](https://sonarcloud.io/dashboard?id=coreruleset_go-ftw)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=coreruleset_go-ftw&metric=alert_status)](https://sonarcloud.io/dashboard?id=coreruleset_go-ftw)


Go-FTW is a replacement for [FTW](https://pypi.org/project/ftw/) which had reached its limits in terms of maintainability and performance.

Features of Go-FTW include:
  - fully customizable HTTP traffic
  - CI/CD friendly
  - fast (at least faster than FTW was)
  - syntax checking of test files

## Install

Go to the [releases](https://github.com/coreruleset/go-ftw/releases) page and get the one that matches your OS.

If you have Go installed and configured to run Go binaries from your shell you can also run
```bash
go install github.com/coreruleset/go-ftw@latest
```

## Example Usage

The go-ftw is designed to run Web Application Firewall (WAF) unit tests. The primary focus is the [OWASP ModSecurity Core Rule Set](https://github.com/coreruleset/coreruleset).

In order to run the tests, you need to prepare the following:

1. Active WAF
2. Log where the WAF writes the alert messages
3. go-ftw config file `.ftw.yaml` in the local folder or in your home folder (see [YAML Config file](https://github.com/coreruleset/go-ftw#yaml-config-file) for more information).
4. At least one unit test in (go)-ftw's yaml format.

### YAML Config file

With the configuration, you can set paths for your environment, enable and disable features and you can also use it to alter the test results.

The config file has six basic settings:

* `logfile` : path to WAF log with alert messages, relative or absolute
* `testoverride` : a list of things to override (see [Overriding tests](https://github.com/coreruleset/go-ftw#overriding-tests) below)
* `mode` : "default" or "cloud" (only change it if you need "cloud")
* `logmarkerheadername` : name of an HTTP header used for marking log messages, usually `X-CRS-TEST` (see [How log parsing works](https://github.com/coreruleset/go-ftw#how-log-parsing-works) below)
* `maxmarkerretries` : the maximum number of times the search for log markers will be repeated; each time an additional request is sent to the web server, eventually forcing the log to be flushed
* `maxmarkerloglines` the maximum number of lines to search for a marker before aborting

You can probably leave the last three alone, they are set to sane defaults.

__Example with absolute logfile__:

```yaml
logfile: /apache/logs/error.log
logmarkerheadername: X-CRS-TEST
testoverride:
mode: "default"
```

__Example with relative logfile__:

```yaml
logfile: ../logs/error.log
logmarkerheadername: X-CRS-TEST
testoverride:
mode: "default"
```

__Example with minimal definitions__:

The minimal requirement for go-ftw is to have a logfile when running in default mode:

```yaml
logfile: ../logs/error.log
```

By default, _go-ftw_ looks for a file in `$PWD` / local folder with the name `.ftw.yaml`. If this can not be found, it will look in the user's HOME folder. You can pass the `--config <config file name>` to point it to a different file.

### WAF Server

I normally perform my testing using the [Core Rule Set](https://github.com/coreruleset/coreruleset/).

You can start the containers from that repo using `docker compose`:

```bash
git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset
docker compose -f tests/docker-compose.yml up -d modsec2-apache
```

### Logfile

Running in default mode implies you have access to a logfile for checking the WAF behavior against test results. For this example, assuming you are in the base directory of the coreruleset repository, these are the configurations for `apache` and `nginx`:

```yaml
---
logfile: 'tests/logs/modsec2-apache/error.log'
```

```yaml
---
logfile: 'tests/logs/modsec3-nginx/error.log'
```

## Running

This is the help for the `run` command:
```bash
./ftw run --help
Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.

Usage:
  ftw run [flags]

Flags:
      --connect-timeout duration               timeout for connecting to endpoints during test execution (default 3s)
  -d, --dir string                             recursively find yaml tests in this directory (default ".")
  -e, --exclude string                         exclude tests matching this Go regexp (e.g. to exclude all tests beginning with "91", use "91.*").
                                               If you want more permanent exclusion, check the 'testoverride' option in the config file.
  -f, --file string                            output file path for ftw tests. Prints to standard output by default.
  -h, --help                                   help for run
  -i, --include string                         include only tests matching this Go regexp (e.g. to include only tests beginning with "91", use "91.*").
      --max-marker-log-lines int               maximum number of lines to search for a marker before aborting (default 500)
      --max-marker-retries int                 maximum number of times the search for log markers will be repeated.
                                               Each time an additional request is sent to the web server, eventually forcing the log to be flushed (default 20)
  -o, --output string                          output type for ftw tests. "normal" is the default. (default "normal")
      --read-timeout duration                  timeout for receiving responses during test execution (default 1s)
      --show-failures-only                     shows only the results of failed tests
  -t, --time                                   show time spent per test
      --wait-delay duration                    Time to wait between retries for all wait operations. (default 1s)
      --wait-for-connection-timeout duration   Http connection timeout, The timeout includes connection time, any redirects, and reading the response body. (default 3s)
      --wait-for-expect-body-json string       Expect response body JSON pattern. To know more about JSON syntax see https://github.com/tidwall/gjson/blob/master/SYNTAX.md
      --wait-for-expect-body-regex string      Expect response body pattern. This is just a regex.
      --wait-for-expect-body-xpath string      Expect response body XPath pattern. Example: `"//*[@id="tux-gear"]"`
      --wait-for-expect-header string          Expect response header pattern. This is a regex. Example: `"Content-Type: application/json"`.
      --wait-for-expect-status-code int        Expect response code e.g. 200, 204, ... .
      --wait-for-host string                   Wait for host to be available before running tests.
      --wait-for-insecure-skip-tls-verify      Skips TLS certificate checks for the HTTPS request.
      --wait-for-no-redirect                   Do not follow HTTP 3xx redirects.
      --wait-for-timeout duration              Sets the timeout for all wait operations, 0 is unlimited. (default 10s)

Global Flags:
      --cloud           cloud mode: rely only on HTTP status codes for determining test success or failure (will not process any logs)
      --config string   override config file (default is $PWD/.ftw.yaml)
      --debug           debug output
      --trace           trace output: really, really verbose
```
All the wait for flags are implemented using the [wait4x](https://github.com/atkrad/wait4x#http) library.
See their examples on how to use them. In our flags we added the prefix `--wait-for` but they behave similarly.

Note: Duration flags above accept any input valid for [`time.ParseDuration`](https://pkg.go.dev/time#ParseDuration).

Here's an example on how to run your tests recursively in the folder `tests`:

```bash
ftw run -d tests -t
```

And the result should be similar to:

```bash
❯ ./ftw run -d tests -t

🛠️  Starting tests!
🚀 Running!
👉 executing tests in file 911100.yaml
	running 911100-1: ✔ passed 6.382692ms
	running 911100-2: ✔ passed 4.590739ms
	running 911100-3: ✔ passed 4.833236ms
	running 911100-4: ✔ passed 4.675082ms
	running 911100-5: ✔ passed 3.581742ms
	running 911100-6: ✔ passed 6.426949ms
...
	running 944300-322: ✔ passed 13.292549ms
	running 944300-323: ✔ passed 8.960695ms
	running 944300-324: ✔ passed 7.558008ms
	running 944300-325: ✔ passed 5.977716ms
	running 944300-326: ✔ passed 5.457394ms
	running 944300-327: ✔ passed 5.896309ms
	running 944300-328: ✔ passed 5.873305ms
	running 944300-329: ✔ passed 5.828122ms
➕ run 2354 total tests in 18.923445528s
⏭ skipped 7 tests
🎉 All tests successful!
```
Happy testing!

## Output

Now you can choose how the output of the test session is shown by passing the `-o` flag. The default output is `-o normal`,
and it will show the emojis in all the supported terminals. If yours doesn't support emojis, or you want a plain format,
you can use `-o plain`:
```shell
./ftw run -d tests -o plain -i 932240

** Running go-ftw!
	skipping 920360-1 - (enabled: false) in file.
	skipping 920370-1 - (enabled: false) in file.
	skipping 920380-1 - (enabled: false) in file.
	skipping 920390-1 - (enabled: false) in file.
=> executing tests in file 932240.yaml
	running 932240-1: + passed in 39.928201ms (RTT 67.096865ms)
	running 932240-2: + passed in 29.299056ms (RTT 65.650821ms)
	running 932240-3: + passed in 30.426324ms (RTT 63.173202ms)
	running 932240-4: + passed in 29.111381ms (RTT 66.593728ms)
	running 932240-5: + passed in 30.627351ms (RTT 67.101436ms)
	running 932240-6: + passed in 40.735442ms (RTT 79.628474ms)
+ run 6 total tests in 200.127755ms
>> skipped 3322 tests
\o/ All tests successful!
```

To support automation for processing the test results, there is also a new JSON output available using `-o json`:
```json
{
  "run": 8,
  "success": [
    "911100-1",
    "911100-2",
    "911100-3",
    "911100-4",
    "911100-5",
    "911100-6",
    "911100-7",
    "911100-8"
  ],
  "failed": null,
  "skipped": [
    "913100-1",
    "913100-2",
    "913100-3",
    "...",
    "980170-2"
  ],
  "ignored": null,
  "forced-pass": null,
  "forced-fail": null,
  "runtime": {
    "911100-1": 20631077,
    "911100-2": 14112617,
    "911100-3": 14524897,
    "911100-4": 14699391,
    "911100-5": 16137499,
    "911100-6": 16589660,
    "911100-7": 16741235,
    "911100-8": 20658905
  },
  "TotalTime": 134095281
}
```

Then it is easy to use your `jq` skils to get the information you want.

The list of supported outputs is:
- "normal"
- "quiet"
- "github"
- "json"
- "plain"

#### Only show failures

If you are only interested to see when tests fail, there is a new flag `--show-only-failures` that does exactly that.
This is helpful when running in CI/CD systems like GHA to get shorter outputs.

## Additional features

- templates with the power of Go [text/template](https://golang.org/pkg/text/template/). Add your template to any `data:` sections and enjoy!
- [Sprig functions](https://masterminds.github.io/sprig/) can be added to templates as well.
- Override test results.
- Cloud mode! This new mode will ignore log files and rely solely on the HTTP status codes of the requests for determining success and failure of tests.

With templates and functions, you can simplify bulk test writing, or even read values from the environment while executing. These features allow you to write tests like this:

```yaml
data: 'foo=%3d{{ "+" | repeat 34 }}'
```

Will be expanded to:

```yaml
data: 'foo=%3d++++++++++++++++++++++++++++++++++'
```

But also, you can get values from the environment dynamically when the test is run:

```yaml
data: 'username={{ env "USERNAME" }}
```

Will give you, as you expect, the username running the tests:

```yaml
data: 'username=fzipi
```

Other interesting functions you can use are: `randBytes`, `htpasswd`, `encryptAES`, etc.

## Overriding tests

Sometimes you have tests that work well for some platform combinations, e.g. Apache + ModSecurity 2, but fail for others, e.g. NGiNX + ModSecurity 3. Taking that into account, you can override test results using the `testoverride` config param. The test will be skipped, and the result forced as configured.

Tests can be altered using four lists:
- `input` allows you to override global parameters in tests. The following ones can be overridden:
  - `dest_addr`: overrides the destination address (accepts IP or hostname)
  - `override_empty_host_header`: if true and `dest_addr` override is _also_ set, empty `Host` headers will be replaced with `dest_addr`
  - `port`: overrides the port number
  - `protocol`: overrides the protocol
  - `uri`: overrides the uri
  - `version`: overrides the HTTP version. E.g. "HTTP/1.1"
  - `headers`: overrides headers, the format is a map of strings
  - `method`: overrides the method used to perform the request
  - `data`: overrides data sent in the request
  - `autocomplete_headers`: overrides header autocompletion (currently sets `Connection: close` and `Content-Length` for requests with body data)
  - `encodedrequest`: overrides base64 encoded request
  - `rawrequest`: permits to provide a raw request. `method`, `uri` and `version` values will be ignored
- `ignore` is for tests you want to ignore. You should add a comment on why you ignore the test
- `forcepass` is for tests you want to pass unconditionally. You should add a comment on why you force to pass the test
- `forcefail` is for tests you want to fail unconditionally. You should add a comment on why you force to fail the test

Each list is populated by regular expressions (see https://pkg.go.dev/regexp), which match against test IDs.
The following is an example using all the lists mentioned above:

```yaml
...
testoverride:
  input:
    dest_addr: "192.168.1.100"
    port: 8080
    protocol: "http"
  ignore:
    # text comes from our friends at https://github.com/digitalwave/ftwrunner
    '941190-3$': 'known MSC bug - PR #2023 (Cookie without value)'
    '941330-1$': 'know MSC bug - #2148 (double escape)'
    '942480-2$': 'known MSC bug - PR #2023 (Cookie without value)'
    '944100-11$': 'known MSC bug - PR #2045, ISSUE #2146'
    '^920': 'All the tests about Protocol Attack (rules starting with "920") will be ignored'
  forcefail:
    '123456-01$': 'I want this specific test to fail, even if passing'
  forcepass:
    '123456-02$': 'This test will always pass'
    '123457-.*': 'All the tests about rule 123457 will always pass'
```

You can combine any of `ignore`, `forcefail` and `forcepass` to make it work for you.

## ☁️ Cloud mode

Most of the tests rely on having access to a logfile to check for success or failure. Sometimes that is not possible, for example, when testing cloud services or servers where you don't have access to logfiles and/or logfiles won't have the information you need to decide if the test was good or bad.

With cloud mode, we move the decision on test failure or success to the HTTP status code received after performing the test. The general idea is that you set up your WAF in blocking mode, so anything matching will return a block status (e.g. 403), and if not we expect a 2XX return code.

You will also want to override the IP configured in the tests, and use the one from your cloud provider instead.

An example config file for this is:
```yaml
---
mode: 'cloud'
testoverride:
  input:
    dest_addr: "<your cloud WAF IP>"
    port: 80
```
Save this file as `cloud-test.yaml` and edit the WAF IP.

Then run: `./ftw run --config cloud-test.yaml`

## How log parsing works

The WAF's log file with the alert messages is parsed and compared to the expected output defined in the unit test under `log_contains` or `no_log_contains`.
Note that the expected output may contain multiple checks (E.g. `log_contains` and `status`). If any of the checks fail, the test will fail.

The problem with log files is that `go-ftw` is very, very fast and the log files are not updated in real time. Frequently, the
web server / WAF is not syncing the file fast enough. That results in a situation where `go-ftw` won't find the log messages it has triggered.

To make log parsing consistent and guarantee that we will see output when we need it, `go-ftw` will send a request that is meant to write a marker into the log file before the individual test and another marker after the individual test.

If `go-ftw` does not see the finishing marker after executing the request, it will send the marker request again until the webserver is forced to write the log file to the disk and the marker can be found.

The [container images for Core Rule Set](https://github.com/coreruleset/modsecurity-crs-docker) can be configured to write these marker log lines by setting
the `CRS_ENABLE_TEST_MARKER` environment variable. If you are testing a different test setup, you will need to instrument it with a rule that generated the marker in the log file via a rule alert (unless you are using "cloud mode").

The rule for CRS looks like this:

```
# Write the value from the X-CRS-Test header as a marker to the log
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  pass,\
  phase:1,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
```

The rule looks for an HTTP header named `X-CRS-Test` and writes its value to the log, the value being the UUID of a test stage. If the header does not exist, the rule will be skipped and no marker will be written. If the header is found, the rule will also disable all further matching against the request to ensure that reported matches only concern actual test requests.

You can configure the name of the HTTP header by setting the `logmarkerheadername` option in the configuration to a custom value (the value is case-insensitive).

## Wait for backend service to be ready

Sometimes you need to wait for a backend service to be ready before running the tests. For example, you may need to wait for an additional container to be ready before running the tests.
Now you can do that by passing the `--wait-for-host` flag. The value of this option is a URL that will be requested, and you can configure the expected result using the following additional flags:
- `--wait-for-host`:                     Wait for host to be available before running tests.
- `--wait-delay`:                        Time to wait between retries for all wait operations. (default 1s)
- `--wait-for-connection-timeout`        Http connection timeout, The timeout includes connection time, any redirects, and reading the response body. (default 3s)
- `--wait-for-expect-body-json`          Expect response body JSON pattern.
- `--wait-for-expect-body-regex`         Expect response body pattern.
- `--wait-for-expect-body-xpath`         Expect response body XPath pattern.
- `--wait-for-expect-header`             Expect response header pattern.
- `--wait-for-expect-status-code`        Expect response code e.g. 200, 204, ... .
- `--wait-for-insecure-skip-tls-verify`  Skips tls certificate checks for the HTTPS request.
- `--wait-for-no-redirect`               Do not follow HTTP 3xx redirects.
- `--wait-for-timeout`                   Sets the timeout for all wait operations, 0 is unlimited. (default 10s)

## Library usage

`go-ftw` can be used as a library also. Just include it in your project:
```sh
go get github.com/coreruleset/go-ftw
```

Then, for the example below, import at least these:
```go
package main

import (
    "net/url"
    "os"
    "path/filepath"
    "strconv"

    "github.com/bmatcuk/doublestar/v4"
    "github.com/coreruleset/go-ftw/config"
    "github.com/coreruleset/go-ftw/output"
    "github.com/coreruleset/go-ftw/runner"
    "github.com/coreruleset/go-ftw/test"
    "github.com/rs/zerolog"
)
```

And a sample code:
```go
     // sample from https://github.com/corazawaf/coraza/blob/v3/dev/testing/coreruleset/coreruleset_test.go#L215-L251
    var tests []test.FTWTest
    err = doublestar.GlobWalk(crsReader, "tests/regression/tests/**/*.yaml", func(path string, d os.DirEntry) error {
        yaml, err := fs.ReadFile(crsReader, path)
        if err != nil {
            return err
        }
        t, err := test.GetTestFromYaml(yaml)
        if err != nil {
            return err
        }
        tests = append(tests, t)
        return nil
    })
    if err != nil {
        log.Fatal(err)
    }

    u, _ := url.Parse(s.URL)
    host := u.Hostname()
    port, _ := strconv.Atoi(u.Port())
    zerolog.SetGlobalLevel(zerolog.InfoLevel)
    cfg, err := config.NewConfigFromFile(".ftw.yml")
    if err != nil {
        log.Fatal(err)
    }
    cfg.WithLogfile(errorPath)
    cfg.TestOverride.Input.DestAddr = &host
    cfg.TestOverride.Input.Port = &port

    res, err := runner.Run(cfg, tests, runner.RunnerConfig{
                    ShowTime: false,
                    }, output.NewOutput("quiet", os.Stdout))
    if err != nil {
        log.Fatal(err)
    }


    if len(res.Stats.Failed) > 0 {
		log.Errorf("failed tests: %v", res.Stats.Failed)
	}
```


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcoreruleset%2Fgo-ftw.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcoreruleset%2Fgo-ftw?ref=badge_large)
