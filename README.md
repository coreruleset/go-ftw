# Go-FTW - Framework for Testing WAFs in Go!

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Go Report Card](https://goreportcard.com/badge/github.com/fzipi/go-ftw)](https://goreportcard.com/report/github.com/fzipi/go-ftw)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/fzipi/go-ftw)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/fzipi/go-ftw)](https://pkg.go.dev/github.com/fzipi/go-ftw)
[![Release](https://img.shields.io/github/v/release/fzipi/go-ftw.svg?style=flat-square)](https://github.com/fzipi/go-ftw/releases/latest)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/fzipi/go-ftw.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/fzipi/go-ftw/alerts/)


This software should be compatible with the [Python version](https://pypi.org/project/ftw/).

I wrote this one to get more insights on the original version, and trying to shed some lights on the internals. There are many assumptions on the inner workings that I needed to dig into the code to know how they worked.

My goals are:
- get a compatible `ftw` version, with no dependencies and easy to deploy
- be CI/CD extremely friendly
- be fast (if possible)
- add features like:
  - syntax checking on the test files
  - use docker API to get logs (if possible), so there is no need to read files
  - add different outputs for CI (junit xml?, github, gitlab, etc.)

## Install

Go to the [releases](https://github.com/fzipi/go-ftw/releases) page and get the one that matches your OS.

## Example Usage

To run tests you need:
1. a WAF (doh!)
2. a file where the waf stores the logs
3. a config file, or environment variables, with the information to get the logs and how to parse them (I might embed this for the most commonly used, like Apache/Nginx)

By default, _ftw_ would search for a file in `$PWD` with the name `.ftw.yaml`. Example configurations for `apache` and `nginx` below:

```yaml
---
logfile: '../coreruleset/tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: 'ddd MMM DD HH:mm:ss.S YYYY'
```

For nginx, as logs will be to the second, you need to add the amount of time you want to truncate to. This will for example discard anything less than one second:

```yaml
---
logfile: '../coreruleset/tests/logs/modsec3-nginx/nginx/error.log'
logtype:
  name: 'nginx'
  timeregex:  '(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})'
  timeformat: 'YYYY/MM/DD HH:mm:ss'
  timetruncate: 1s
```

Time format specification follows the one used by [gostradamus](https://github.com/bykof/gostradamus#token-table).

If your webserver uses a different time format, please [create an issue](https://github.com/fzipi/go-ftw/issues/new/choose) and we can extend the documentation to cover it.

I normally perform my testing using the [Core Rule Set](https://github.com/coreruleset/coreruleset/).

You can start the containers from that repo using docker-compose:

```bash
git clone https://github.com/coreruleset/coreruleset.git
docker-compose -f tests/docker-compose.yml up -d modsec2-apache
```

This is the help for the `run` command:
```bash
❯ ftw run -h
Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.

Usage:
  ftw run [flags]

Flags:
  -d, --dir string       recursively find yaml tests in this directory (default ".")
  -e, --exclude string   exclude tests matching this Go regexp (e.g. to exclude all tests beginning with "91", use "91.*").
                         If you want more permanent exclusion, check the 'testmodify' option in the config file.
  -h, --help             help for run
      --id string        (deprecated). Use --include matching your test only.
  -i, --include string   include only tests matching this Go regexp (e.g. to include only tests beginning with "91", use "91.*").
  -q, --quiet            do not show test by test, only results
  -t, --time             show time spent per test

Global Flags:
      --config string   override config file (default is $PWD/.ftw.yaml) (default "c")
      --debug           debug output
      --trace           trace output: really, really verbose

```

After merging [this PR](https://github.com/coreruleset/coreruleset/pull/2080), no changes will be needed. 
Until that happens, you can get and apply the [patch](https://patch-diff.githubusercontent.com/raw/coreruleset/coreruleset/pull/2080.patch), using `patch -p1 < 2080.patch`.

Then you can run your tests using:

`ftw run -d tests -t`

And the result should be similar to:

```
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
⏭ skept 7 tests
🎉 All tests successful!
```
Happy testing!

## Additional features

You can add functions to your tests, to simplify bulk writing, or even read values from the environment while executing. This is because `data:` sections in tests will be parse for Go [text/template](https://golang.org/pkg/text/template/) additional syntax, and with the power of additional [Sprig functions](https://masterminds.github.io/sprig/).

This will allow you to write tests like this:

```yaml
data: 'foo=%3d{{ "+" | repeat 34 }}'
```

Will be expanded to:

```yaml
data: 'foo=%3d++++++++++++++++++++++++++++++++++'
```

But also, you can get values from the environment dinamically when the test is run:

```yaml
data: 'username={{ env "USERNAME" }}
```

Will give you, as you expect, the username running the tests

```yaml
data: 'username=fzipi
```

Other interesting functions you can use are: `randBytes`, `htpasswd`, `encryptAES`, etc.

## Overriding test results

Sometimes you have tests that work well in some platform combination, e.g. Apache + modsecurity2, but fail in other, e.g. Nginx + modsecurity3. Taking that into account, you can override test results using the `testoverride` config param. The test will be run, but the _result_ would be overriden, and your comment will be printed out.

Example:

```yaml
...
testoverride:
  ignore:
    # text comes from our friends at https://github.com/digitalwave/ftwrunner
    '941190-3': 'known MSC bug - PR #2023 (Cookie without value)'
    '941330-1': 'know MSC bug - #2148 (double escape)'
    '942480-2': 'known MSC bug - PR #2023 (Cookie without value)'
    '944100-11': 'known MSC bug - PR #2045, ISSUE #2146'
  forcefail:
    '123456-01': 'I want this test to fail, even if passing'
  forcepass:
    '123456-02': 'This test will always pass'
```

You can combine any of `ignore`, `forcefail` and `forcepass` to make it work for you.

## Truncating logs

Log files can get really big. Searching patterns are performed using reverse text search in the file. Because the test tool is *really* fast, we sometimes see failures in nginx depending on how fast the tests are performed, mainly because log times in nginx are truncated to one second.

To overcome this, you can use the new config value `logtruncate: True`. This will, as it says, call _truncate_ on the file, actively modifying it between each test. You will need permissions to write the logfile, implying you might need to call the go-ftw binary using sudo.

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Ffzipi%2Fgo-ftw.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Ffzipi%2Fgo-ftw?ref=badge_large)