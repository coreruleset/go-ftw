# Go-FTW - Framework for Testing WAFs in Go!

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Go Report Card](https://goreportcard.com/badge/github.com/coreruleset/go-ftw)](https://goreportcard.com/report/github.com/coreruleset/go-ftw)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/coreruleset/go-ftw)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/coreruleset/go-ftw)](https://pkg.go.dev/github.com/coreruleset/go-ftw)
[![Release](https://img.shields.io/github/v/release/coreruleset/go-ftw.svg?style=flat-square)](https://github.com/coreruleset/go-ftw/releases/latest)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/coreruleset/go-ftw.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/coreruleset/go-ftw/alerts/)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=coreruleset_go-ftw&metric=coverage)](https://sonarcloud.io/dashboard?id=coreruleset_go-ftw)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=coreruleset_go-ftw&metric=alert_status)](https://sonarcloud.io/dashboard?id=coreruleset_go-ftw)


This software should be compatible with the [Python version](https://pypi.org/project/ftw/).

I wrote this one to get more insights on the original version, and trying to shed some light on the internals. There are many assumptions on the inner workings that I needed to dig into the code to know how they worked.

My goals are:
- get a compatible `ftw` version, with no dependencies and easy to deploy
- be extremely CI/CD friendly
- be fast (if possible)
- add features like:
  - syntax checking on the test files
  - use docker API to get logs (if possible), so there is no need to read files
  - add different outputs for CI (junit xml?, github, gitlab, etc.)

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

With the configuration set paths for your environment, enable and disabled features and you can also use it to alter the test results.

The config file has four basic values:

* `logfile` : path to WAF log with alert messages, relative of absolute
* `logmarkerheadername` : name of a HTTP header used for marking log messages, usually `X-CRS-TEST` (see [How log parsing works](https://github.com/coreruleset/go-ftw#how-log-parsing-works) below)
* `testoverride` : a list of things to override (see "Overriding tests" below)>
* `mode` : "default" or "cloud" (only change it if you need "cloud")
```

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

__Example with minimal definitions__:

```yaml
logfile: ../logs/error.log
logmarkerheadername:
testoverride:
mode:

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
❯ ftw run -h
Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.

Usage:
  ftw run [flags]

Flags:
      --connect-timeout duration   timeout for connecting to endpoints during test execution (default 3s)
  -d, --dir string                 recursively find yaml tests in this directory (default ".")
  -e, --exclude string             exclude tests matching this Go regexp (e.g. to exclude all tests beginning with "91", use "91.*").
                                   If you want more permanent exclusion, check the 'testoverride' option in the config file.
  -h, --help                       help for run
      --id string                  (deprecated). Use --include matching your test only.
  -i, --include string             include only tests matching this Go regexp (e.g. to include only tests beginning with "91", use "91.*").
  -q, --quiet                      do not show test by test, only results
      --read-timeout duration      timeout for receiving responses during test execution (default 1s)
  -t, --time                       show time spent per test

Global Flags:
      --cloud           cloud mode: rely only on HTTP status codes for determining test success or failure (will not process any logs)
      --config string   override config file (default is $PWD/.ftw.yaml)
      --debug           debug output
      --trace           trace output: really, really verbose
```

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

## Additional features

- templates with the power of Go [text/template](https://golang.org/pkg/text/template/). Add your template to any `data:` sections and enjoy!
- [Sprig functions](https://masterminds.github.io/sprig/) can be added to templates as well.
- Override test results.
- Cloud mode! This new mode will ignore log files and rely solely on the HTTP status codes of the requests for determining success and failure of tests.

With templates and functions you can simplify bulk test writing, or even read values from the environment while executing. This features allow you to write tests like this:

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

Will give you, as you expect, the username running the tests

```yaml
data: 'username=fzipi
```

Other interesting functions you can use are: `randBytes`, `htpasswd`, `encryptAES`, etc.

## Overriding tests

Sometimes you have tests that work well for some platform combinations, e.g. Apache + modsecurity2, but fail for others, e.g. NGiNX + modsecurity3. Taking that into account, you can override test results using the `testoverride` config param. The test will be skipped, and the result forced as configured.

Tests can be altered using four lists:
- `input` allows you to override global parameters in tests. An example usage is if you want to change the `dest_addr` of all tests to point to an external IP or host
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

With cloud mode, we move the decision on test failure or success to the HTTP status code received after performing the test. The general idea is that you setup your WAF in blocking mode, so anything matching will return a block status (e.g. 403), and if not we expect a 2XX return code.

An example config file for this is:
```
---
mode: 'cloud'
```

Or you can just run: `./ftw run --cloud`

## How log parsing works

The WAF's log file with the alert messages is parsed and compared to the expected output defined in the unit test under `log_contains` or `no_log_contains`.

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
  msg:'X-CRS-Test %{MATCHED_VAR}'"
```

The rule looks for an HTTP header named `X-CRS-Test` and writes its value to the log, the value being the UUID of a test stage. If the header is not existing, rule is being ignored and no marker is being written.

You can configure the name of the HTTP header by setting the `logmarkerheadername` option in the configuration to a custom value (the value is case insensitive).

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcoreruleset%2Fgo-ftw.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcoreruleset%2Fgo-ftw?ref=badge_large)
