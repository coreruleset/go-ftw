# Design: `regex perf` — regex performance benchmarking

Date: 2026-06-08
Status: Approved

## Summary

Add a feature to go-ftw that, inspired by [`digitalwave/msc_retest`](https://github.com/digitalwave/msc_retest),
generates a regular expression from an OWASP CRS regex-assembly (`.ra`) file using the
crs-toolchain assembler, then measures how that regex performs against a large set of input
subjects (the existing "quantitative" corpus). It reports aggregate timing statistics and the
slowest subjects.

Unlike `msc_retest` (which targets PCRE to surface catastrophic backtracking / ReDoS), this
feature measures **Coraza-realistic performance** using Go's stdlib `regexp` engine (RE2,
linear-time). It is intended for performance regression tracking and identifying expensive
regex/input combinations — not ReDoS discovery (RE2 cannot exhibit catastrophic backtracking).

## Goals

- Compile a regex from a `.ra` file via the canonical crs-toolchain assembler.
- Also accept a raw regex pattern directly (skip the assembler).
- Time the compiled regex against subjects sourced from the existing corpus system, or a single
  inline subject.
- Report aggregate stats (total, mean, median, p99, max, throughput, match count) and a top-N
  list of the slowest subjects.

## Non-goals

- ReDoS / catastrophic-backtracking detection (would require a PCRE/backtracking engine via cgo).
- Rule-ID-based lookup against a coreruleset checkout (only `.ra` file and raw pattern inputs).
- Directory/batch walking of many `.ra` files.
- Multiple regex engines or PCRE comparison.

## CLI

New Cobra subcommand under a new `regex` parent group (leaving room for future regex tooling):

```
ftw regex perf [flags]
```

### Regex source (mutually exclusive, exactly one required)

| Flag | Short | Description |
|------|-------|-------------|
| `--file` | `-f` | Path to a `.ra` regex-assembly file; compiled via the assembler. |
| `--pattern` | `-p` | A raw regex pattern; bypasses the assembler. |

### Subject source (mutually exclusive, exactly one required)

| Flag | Description |
|------|-------------|
| corpus flags | Reuse the existing quantitative corpus flags (`--corpus`, `--corpus-size`, `--corpus-lang`, `--corpus-year`, `--corpus-source`, `--corpus-local-path`). |
| `--subject` | A single inline subject string for quick one-off timing. |

### Shared flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--crs-path` | `-C` | `.` | Root dir of the coreruleset so `.ra` `include` directives resolve. |
| `--repeat` | `-R` | `10` | Times each subject is matched; the **minimum** observed time is kept (noise filtering). |
| `--top` | | `10` | Number of slowest subjects to report. |
| `--output` | `-o` | `normal` | Output format: `normal` or `json`. |
| `--file-out` | | stdout | Write report to a file. |

Note: `--file-out` is named to avoid colliding with `-f/--file`. Final long-flag name to be
confirmed in the plan (the existing `quantitative` command uses `-f/--file` for output; here
`-f/--file` is the `.ra` input, so output uses a distinct name).

### Example invocations

```
ftw regex perf --file rules/942100.ra --corpus leipzig --corpus-size 100K -C /path/to/coreruleset
ftw regex perf --pattern '(?i)union\s+select' --subject "' UNION SELECT 1,2,3"
ftw regex perf -p '\d{3}-\d{4}' --corpus raw --corpus-local-path ./subjects.txt -o json
```

## Architecture

```
cmd/regex/regex.go        # parent "regex" cobra group, registered in cmd/root
cmd/regex/perf.go         # "perf" subcommand: flag parsing, validation, wiring
cmd/regex/perf_test.go
internal/regexperf/
  compile.go              # .ra -> regex via crs-toolchain assembler; or passthrough pattern
  compile_test.go
  benchmark.go            # compile regexp, iterate subjects, time matches, collect samples
  benchmark_test.go
  stats.go                # aggregate stats + top-N slowest; report formatting (normal/json)
  stats_test.go
```

Reuses, unchanged:
- `internal/corpus` (Leipzig/raw iterators) for subjects.
- `internal/quantitative/factories.go` corpus factory (or an equivalent thin reuse) to build the
  corpus runner from flags. Exact reuse boundary confirmed in the plan; no duplication of corpus
  iteration logic.
- `output.Output` for `normal`/`json` formatting.

## crs-toolchain integration (verified API)

New dependency: `github.com/coreruleset/crs-toolchain/v2`.

Construction (verified against crs-toolchain `main`):

```go
import (
    "github.com/coreruleset/crs-toolchain/v2/context"
    "github.com/coreruleset/crs-toolchain/v2/regex/processors"
    "github.com/coreruleset/crs-toolchain/v2/regex/operators"
)

rootCtx := context.New(crsPath, configFileName) // appends "/regex-assembly" internally for includes
ctx := processors.NewContext(rootCtx)
assembler := operators.NewAssembler(ctx)
regexStr, err := assembler.Run(string(raFileContent))
```

- `context.New(rootDir string, configurationFileName string) *context.Context` — `rootDir` is the
  coreruleset root (maps to `--crs-path`). The default `configurationFileName` value used by the
  toolchain CLI is to be confirmed in the plan (pass the toolchain's default).
- `assembler.Run(input string) (string, error)` takes `.ra` file **content** and returns the
  compiled regex.

### Dependency justification (per project standards)

Re-implementing the assembler is infeasible and would diverge from canonical CRS output. The
crs-toolchain is the official, maintained generator and a sibling coreruleset project. It pulls a
non-trivial transitive tree; this is accepted as the cost of correct, canonical compilation.

## Data flow

```
--file path        --pattern str
     |                   |
read .ra content    (raw pattern)
     |                   |
assembler.Run() ---------+--> regex string
                              |
                       regexp.Compile (clear error on failure)
                              |
        corpus iterator / single inline subject
                              |
  for each subject: time re.MatchString K times, keep MIN -> {subject, ns, matched}
                              |
                  aggregate -> Stats (total, mean, median, p99, max, throughput, matchCount)
                              |
                  top-N slowest via bounded min-heap
                              |
                   output.Output (normal | json)
```

### Timing method

Per subject, run `re.MatchString(subject)` `--repeat` times and keep the **minimum** elapsed
nanoseconds. Minimum is the cleanest estimator of true cost: it filters scheduler/GC noise and is
stable for the nanosecond-scale, linear-time matches Go's `regexp` produces. Aggregate stats are
computed over the per-subject minima.

## Output

`normal` format (matches approved mockup):

```
regex: 942100 (compiled, 1.2KB)
subjects: 100,000  matched: 312
total: 84ms  mean: 840ns  median: 610ns
p99: 4.1µs  max: 121µs
throughput: 1.19M subj/s

slowest subjects:
  121µs  "' UNION SELECT ...(long)"
   98µs  "<script>...(long)"
   ...
```

`json` format: a struct with `regexSource`, `compiledRegexBytes`, `subjectCount`, `matchCount`,
`totalNs`, `meanNs`, `medianNs`, `p99Ns`, `maxNs`, `throughputPerSec`, and a `slowest` array of
`{subject, ns, matched}`. Long subjects truncated in `normal`; full (or length-capped) in `json`.

## Memory / scale

- Top-N slowest: bounded min-heap of size `--top`; does not retain all samples.
- Percentiles (median, p99): keep a slice of per-subject minimum-ns values for exact computation.
  At 100K subjects that is ~100K × 8 bytes ≈ 800 KB — acceptable. (If larger corpora become a
  concern later, switch to a streaming/approximate quantile; out of scope now.)

## Error handling

- `.ra` file missing/unreadable → clear error naming the path.
- Assembler error → wrap with context (`assembling <file>: %w`).
- Regex compile failure → report the offending pattern and the compile error.
- Mutually-exclusive / missing required flags → validation error before any work.
- Empty corpus / zero subjects → explicit error, not a divide-by-zero in stats.

## Testing (testify suite, per project convention)

- `compile_test.go`: known `.ra` → expected regex; missing/invalid `.ra` → error; raw pattern
  passthrough; invalid regex → clear compile error.
- `stats_test.go`: percentile/mean/throughput math on fixed sample sets; top-N heap correctness;
  empty and single-subject edges.
- `benchmark_test.go`: tiny inline corpus; assert match counts and that timing fields are
  populated and ordered (min ≤ median ≤ max).
- `cmd/regex/perf_test.go`: flag validation (mutual exclusion, required), and a `--pattern
  --subject` end-to-end smoke run.

## Open items to confirm during planning

1. Exact default `configurationFileName` passed to `context.New`.
2. Precise reuse boundary with `internal/quantitative` corpus factory vs. a thin local builder.
3. Final long-flag name for report output file (avoiding `-f/--file` collision).
