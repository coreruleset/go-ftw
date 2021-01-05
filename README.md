# Go-FTW - Framework for Testing WAFs in Go! 

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Go Report Card](https://goreportcard.com/badge/github.com/fzipi/go-ftw)](https://goreportcard.com/report/github.com/fzipi/go-ftw)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/fzipi/go-ftw)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/fzipi/go-ftw)](https://pkg.go.dev/github.com/fzipi/go-ftw)
[![Release](https://img.shields.io/github/v/release/fzipi/go-ftw.svg?style=flat-square)](https://github.com/fzipi/go-ftw/releases/latest)


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

Just get the binary file for your architecture, and run it!

```bash
```

## Example Usage

To run tests you need:
1. a WAF (doh!)
2. a file where the waf stores the logs
3. a config file, or environment variables, with the information to get the logs and how to parse them (I might embed this for the most commonly used, like Apache/Nginx)

By default, _ftw_ would search for a file in `$PWD` with the name `.ftw.yaml`. An example configuration is:

```yaml
---
logfile: '../coreruleset/tests/logs/modsec2-apache/apache2/error.log'
logtype:
  name: 'apache'
  timeregex:  '\[([A-Z][a-z]{2} [A-z][a-z]{2} \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}\.\d+? \d{4})\]'
  timeformat: '%a %b %d %H:%M:%S.%f %Y'
```

I normally perform my testing using the [Core Rule Set](https://github.com/coreruleset/coreruleset/).

You can start the containers from that repo using docker-compose:

```bash
git clone https://github.com/coreruleset/coreruleset.git
docker-compose -f tests/docker-compose.yml up -d modsec2-apache
```

This is the help for the `run` command:
```bash
❯ ./ftw run -h
Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.

Usage:
  ftw run [flags]

Flags:
  -d, --dir string       recursively find yaml tests in this directory (default ".")
      --exclude string   exclude tests matching this Go regexp (e.g. to exclude all tests beginning with "91", use "91.*")
  -h, --help             help for run
      --id string        set test id to run
  -q, --quiet            do not show test by test, only results
  -t, --time             show time spent per test

Global Flags:
      --cfg string   override config file (default is $PWD/.ftw.yaml)
      --debug        debug output

```

Then run all tests (slightly modified, see [here](https://gist.github.com/fzipi/b9e22b3834a5fa32970878c72775d41e)) in the ModSecurity Core Rule set using:

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
