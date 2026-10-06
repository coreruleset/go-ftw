# 2. Quantitative mode: configurable payload placement, one placement per run

Date: 2026-10-06

## Status

Proposed

## Context

[#673](https://github.com/coreruleset/go-ftw/issues/673) reports that `ftw quantitative` always
builds its request as `/get?uri_payload=<payload>` (`internal/quantitative/local_engine.go`,
`CrsCall`), so every corpus sentence lands in `ARGS` regardless of which corpus is selected.

CRS rules increasingly inspect targets other than `ARGS`: `REQUEST_FILENAME`, `REQUEST_URI`, and
request headers. The 932 (RCE) family recently gained `REQUEST_FILENAME` coverage, and the 941
(XSS) and 942 (SQLi) families already inspect it. A rule change that only affects path or header
matching therefore passes the quantitative false-positive gate with a clean bill of health while
carrying an FP regression the corpus never had a chance to see.

The engine is built once per run via `LocalEngine.Create(prefix, paranoia)` and has exactly two
callers: the runner (`internal/quantitative/runner.go`) and its test. The per-run stats
(`QuantitativeRunStats`) and the `--baseline` / `--compare-crs` JSON comparison have no notion of
where the payload was placed.

## Decision

Add a `--placement` flag to `ftw quantitative` that selects where each corpus payload is placed in
the generated request. Exactly one placement applies to a whole run.

- Accepted values: `args` (default, current behavior), `path`, and `header:<Name>`.
  - `args`: `/get?uri_payload=<QueryEscape(payload)>`, unchanged.
  - `path`: `/get/<PathEscape(payload)>` with no query string. Escaping is required so a raw
    space or `#` cannot truncate or break URI parsing; CRS decodes the value through its
    transformations as it would for any real request.
  - `header:<Name>`: URI is `/get`; the payload is added verbatim as the value of request header
    `<Name>`. When `<Name>` collides with one of the fixed `Host`, `User-Agent`, or `Accept`
    headers the engine always sends, the user-supplied value is the one the rules see.
- The placement is validated in the command layer, carried as `Params.Placement`, and stored on
  the engine at `Create` time. `CrsCall` builds the request from it.
- One placement per run. Covering path and header targets means running the command once per
  placement. This matches how CRS CI wants results labelled anyway: a separate job and a separate
  result file per target class.
- The runner logs the active placement at trace level so a result file can be explained.

## Consequences

**Positive:** CRS gets real quantitative coverage for `REQUEST_FILENAME`, `REQUEST_URI`, and
header-targeted rules using the same corpus and the same reporting, with an additive change. The
default stays `args`, so existing CI jobs and saved baselines keep their meaning.

**Negative:** the stats JSON does not record the placement, so `--baseline` will not warn when a
`path` run is compared against an `args` baseline. Users must keep baselines per placement
themselves. Recording the placement in the output (and warning on mismatch) is a cheap follow-up
if this bites in practice.

**Negative:** header placement sends the payload verbatim. A corpus line containing characters
that are invalid in a header value is the user's problem to filter; the engine does not sanitize.

## Alternatives considered

- **Repeatable `--placement` with one combined report per run:** rejected. It would add a
  placement dimension to `QuantitativeRunStats`, change the JSON schema consumed by `--baseline`
  and `--compare-crs`, and complicate the Markdown output, all to save one extra command
  invocation. If CI later wants a single merged report, that can be built on top of per-placement
  result files.
- **Always send the payload in all three places at once:** rejected. A single sentence would then
  trip a rule up to three times, inflating the FP ratio and making it impossible to attribute a
  regression to a target class. It would also silently change every existing baseline.
- **A separate corpus type per placement:** rejected. Placement is a property of the request, not
  of the input text; tying it to the corpus would duplicate every corpus source.
