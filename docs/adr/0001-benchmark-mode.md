# 1. Benchmark mode: concurrent request firing without per-request log correlation

Date: 2026-09-08

## Status

Proposed

## Context

[#143](https://github.com/coreruleset/go-ftw/issues/143) asks for a way to send N requests
concurrently, so go-ftw can be used to profile and debug WAF latency under load, using
realistic test data (existing YAML test files) instead of a separate load-testing tool.

`go-ftw run` executes stages strictly one at a time (`runner/run.go:130`, `RunStage`). Each
request is bracketed by a start/end log marker, and a single tailed log reader
(`runContext.LogLines`) is grepped for that marker window to correlate WAF log output back to
the request (`runner/run.go:243`, `markAndFlush`). This only works because requests are
serialized: concurrent requests would interleave their markers in the log, so a marker window
could no longer be trusted to contain only that request's log lines.

Reliable per-request correctness checking under concurrency needs a different correlation
mechanism — e.g. a unique transaction ID that the WAF connector echoes in a response header, so
the corresponding log lines can be found by ID instead of by "everything between marker A and
marker B" (raised by the issue reporter and by airween in the issue thread). That depends on
connector behavior go-ftw doesn't control and is a materially larger change.

The existing `--max-concurrency` flag on `corpus`/`quantitative`/`raw` doesn't transfer here: it
drives an in-process Coraza engine per goroutine (`internal/quantitative/local_engine.go`), with
no external log tailing involved.

The reported need is profiling and latency data, not concurrent regression assertions.

## Decision

Add a benchmark mode that fires the requests from existing YAML test files concurrently, up to a
configurable concurrency limit, and reports aggregate latency/throughput stats
(min/max/avg/percentiles, requests/sec) instead of per-test pass/fail.

- No start/end log markers and no log tailing in this mode — WAF log correlation is exactly the
  part that doesn't work under concurrency, so this mode doesn't attempt it.
- Reuse the existing test-file loader (`test.FTWTest`) and `ftwhttp.Client` — no new HTTP layer.
- Ship as a new `go-ftw bench` subcommand, following the existing `run` / `quantitative` /
  `corpus` subcommand pattern, rather than a flag on `run`. Its output (stats) and semantics (no
  pass/fail) differ enough from regression testing that folding it into `run` would overload one
  command with two unrelated output modes.

## Consequences

**Positive:** satisfies the reported need (latency/throughput profiling against real test data)
with an additive change that doesn't touch the existing `run` assertion path; no dependency on
WAF connectors changing behavior.

**Negative:** benchmark mode cannot verify that a rule fired correctly for any individual
concurrent request — it only reports that requests completed, and how fast. It is not a
replacement for `run`.

**Deferred:** true concurrent regression testing (per-request correctness under concurrency, via
unique transaction ID correlation) is tracked as a possible follow-up, contingent on WAF
connectors exposing that ID in a response header. Not part of this decision.

## Alternatives considered

- **Unique transaction ID correlation** (issue's option 2): rejected for now — requires WAF
  connector support go-ftw doesn't control, and reworking `CheckLogForMarker` to key by ID
  instead of a start/end window. Larger scope than the reported need.
- **Flag on the existing `run` command**: rejected — `run`'s output is pass/fail per test;
  benchmark mode's output is aggregate stats. Different enough to warrant a separate subcommand
  rather than a mode switch inside `run`.
