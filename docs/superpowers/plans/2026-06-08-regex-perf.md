# Regex Performance Benchmarking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `ftw regex perf` command that compiles a regex from a CRS regex-assembly (`.ra`) file (or a raw pattern) and measures its match performance against the existing quantitative corpus or a single inline subject, reporting aggregate timing stats and the slowest subjects.

**Architecture:** A new `internal/regexperf` package does the work in three focused files: `compile.go` (assembler integration + Go `regexp` compile + preflight guard), `stats.go` (aggregation, percentiles, top-N heap, report formatting), `benchmark.go` (orchestration: resolve regex → iterate subjects → time → aggregate). A new `cmd/regex` package adds the `regex` parent group and its `perf` subcommand, reusing the existing `internal/corpus` loaders and `output.Output`.

**Tech Stack:** Go 1.25, Cobra, `github.com/coreruleset/crs-toolchain/v2` (new dep, canonical assembler), Go stdlib `regexp` (RE2), `container/heap`, testify/suite.

**Spec:** `docs/superpowers/specs/2026-06-08-regex-perf-design.md`

### Resolved spec open-items (verified against crs-toolchain `main`)

1. **Config filename for `context.New`:** `"toolchain.yaml"` (from `crs-toolchain/cmd/internal/types.go:24`). A missing file is non-fatal — `configuration.New` returns an empty config.
2. **Corpus reuse boundary:** `internal/regexperf` calls `leipzig.NewLeipzigCorpus` / `raw.NewRawCorpus` directly via a small local `newCorpus` helper. It does **not** import `internal/quantitative` (which would pull in Coraza). No corpus-iteration logic is duplicated — only the 3-line type switch the factory already does.
3. **Report output flag:** `--out-file` (no shorthand), to avoid colliding with `-f/--file` (the `.ra` input).

### Robustness finding (drives Task 2)

The crs-toolchain assembler/parser call `logger.Fatal()` (→ `os.Exit(1)`) on a missing `include` file (`regex/parser/parser.go:271`) and on an un-simplifiable regex (`regex/operators/assembler.go:193`). A bad `--crs-path` against an `include`-using `.ra` would kill the whole `ftw` process. Task 2 adds a preflight guard: if the `.ra` references any `include`/`include-except`, verify `<crs-path>/regex-assembly` exists and return an actionable error **before** calling the assembler. Residual risk (a present include dir but a specific missing include file, or pathological un-simplifiable input) is documented as a known upstream limitation.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/regexperf/compile.go` | `AssembleFile` (.ra → regex via crs-toolchain), `Compile` (Go regexp wrapper), `preflightAssembly` guard |
| `internal/regexperf/compile_test.go` | assembler behavior, passthrough, preflight, compile errors |
| `internal/regexperf/stats.go` | `Sample`, `Stats`, `Add`, percentiles, top-N `slowestHeap`, `report()`, `printSummary`, `MarshalJSON` |
| `internal/regexperf/stats_test.go` | stats math, heap correctness, edges |
| `internal/regexperf/benchmark.go` | `Params`, `Run`, `resolveRegex`, `newCorpus`, `timeMatch` |
| `internal/regexperf/benchmark_test.go` | inline-subject and raw-corpus end-to-end |
| `cmd/regex/regex.go` | `regex` parent Cobra group |
| `cmd/regex/perf.go` | `perf` subcommand: flags, validation, wiring to `regexperf.Run` |
| `cmd/regex/perf_test.go` | flag validation + `--pattern --subject` smoke |
| `cmd/root.go` (modify) | register `regex.New(cmdContext)` |

---

## Task 1: Add crs-toolchain dependency and the assembler/compile core

**Files:**
- Create: `internal/regexperf/compile.go`
- Test: `internal/regexperf/compile_test.go`
- Modify: `go.mod`, `go.sum` (via `go get`)

- [ ] **Step 1: Add the dependency**

Run:
```bash
go get github.com/coreruleset/crs-toolchain/v2@latest
```
Expected: `go.mod` gains a `require github.com/coreruleset/crs-toolchain/v2 vX.Y.Z` line; `go.sum` updated.

- [ ] **Step 2: Write the failing test**

Create `internal/regexperf/compile_test.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
)

type compileTestSuite struct {
	suite.Suite
	tempDir string
}

func TestCompileTestSuite(t *testing.T) {
	suite.Run(t, new(compileTestSuite))
}

func (s *compileTestSuite) SetupTest() {
	s.tempDir = s.T().TempDir()
}

// writeRA writes content to a .ra file in tempDir and returns its path.
func (s *compileTestSuite) writeRA(name, content string) string {
	path := filepath.Join(s.tempDir, name)
	s.Require().NoError(os.WriteFile(path, []byte(content), 0o600))
	return path
}

func (s *compileTestSuite) TestAssembleFileProducesMatchingRegex() {
	// Two literal alternatives; the assembler emits an optimized alternation.
	raPath := s.writeRA("simple.ra", "homer\nmarge\n")

	regexStr, err := AssembleFile(raPath, s.tempDir)
	s.Require().NoError(err)
	s.Require().NotEmpty(regexStr)

	re, err := Compile(regexStr)
	s.Require().NoError(err)
	s.True(re.MatchString("homer"))
	s.True(re.MatchString("marge"))
	s.False(re.MatchString("bart"))
}

func (s *compileTestSuite) TestAssembleFileMissingFile() {
	_, err := AssembleFile(filepath.Join(s.tempDir, "nope.ra"), s.tempDir)
	s.Require().Error(err)
	s.Contains(err.Error(), "nope.ra")
}

func (s *compileTestSuite) TestCompilePassthroughValid() {
	re, err := Compile(`(?i)union\s+select`)
	s.Require().NoError(err)
	s.True(re.MatchString("UNION   SELECT"))
}

func (s *compileTestSuite) TestCompileInvalidRegex() {
	_, err := Compile(`(unclosed`)
	s.Require().Error(err)
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/regexperf/ -run TestCompileTestSuite -v`
Expected: FAIL — `undefined: AssembleFile` / `undefined: Compile`.

- [ ] **Step 4: Write the implementation**

Create `internal/regexperf/compile.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package regexperf benchmarks the runtime performance of regular expressions
// generated from OWASP CRS regex-assembly (.ra) files, or supplied directly,
// against a corpus of input subjects.
package regexperf

import (
	"fmt"
	"os"
	"regexp"

	crscontext "github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/operators"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

// toolchainConfigFileName is the default crs-toolchain configuration file name.
// A missing file is non-fatal; the toolchain falls back to an empty configuration.
const toolchainConfigFileName = "toolchain.yaml"

// AssembleFile reads a regex-assembly (.ra) file and compiles it to a regex
// string using the crs-toolchain assembler. crsRoot is the coreruleset root
// directory used to resolve `include` directives; it must contain a
// regex-assembly/ subdirectory when the .ra file uses includes.
func AssembleFile(raPath string, crsRoot string) (string, error) {
	content, err := os.ReadFile(raPath)
	if err != nil {
		return "", fmt.Errorf("reading regex-assembly file %q: %w", raPath, err)
	}
	if err := preflightAssembly(string(content), crsRoot); err != nil {
		return "", err
	}
	rootCtx := crscontext.New(crsRoot, toolchainConfigFileName)
	ctx := processors.NewContext(rootCtx)
	assembler := operators.NewAssembler(ctx)
	regexStr, err := assembler.Run(string(content))
	if err != nil {
		return "", fmt.Errorf("assembling %q: %w", raPath, err)
	}
	return regexStr, nil
}

// Compile compiles a regex string with Go's regexp engine (RE2), wrapping the
// error with a hint that some PCRE constructs (backreferences, lookaround,
// possessive quantifiers) are unsupported by RE2.
func Compile(regexStr string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return nil, fmt.Errorf("compiling regex (Go RE2 does not support some PCRE constructs): %w", err)
	}
	return re, nil
}
```

Note: `preflightAssembly` is added in Task 2. For this task, add a temporary stub at the bottom of `compile.go` so the package builds:

```go
// preflightAssembly is implemented in Task 2.
func preflightAssembly(_ string, _ string) error { return nil }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/regexperf/ -run TestCompileTestSuite -v`
Expected: PASS (all 4 subtests).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/regexperf/compile.go internal/regexperf/compile_test.go
git commit -m "feat(regexperf): add crs-toolchain assembler and regex compile"
```

---

## Task 2: Preflight guard against the assembler's fatal include handling

**Files:**
- Modify: `internal/regexperf/compile.go` (replace the `preflightAssembly` stub)
- Test: `internal/regexperf/compile_test.go` (add cases)

- [ ] **Step 1: Write the failing test**

Append to `internal/regexperf/compile_test.go`:

```go
func (s *compileTestSuite) TestAssembleFileIncludeMissingCrsRoot() {
	// .ra references an include, but crsRoot has no regex-assembly/ dir.
	// Must return an error instead of os.Exit-ing the process.
	raPath := s.writeRA("withinclude.ra", "include some-shared-fragment\nhomer\n")

	_, err := AssembleFile(raPath, s.tempDir)
	s.Require().Error(err)
	s.Contains(err.Error(), "regex-assembly")
}

func (s *compileTestSuite) TestPreflightNoIncludeIsOk() {
	s.Require().NoError(preflightAssembly("homer\nmarge\n", s.tempDir))
}

func (s *compileTestSuite) TestPreflightIncludeWithValidRoot() {
	// regex-assembly/ exists -> preflight passes (assembler may still fail later,
	// but preflight's job is only the crsRoot sanity check).
	s.Require().NoError(os.MkdirAll(filepath.Join(s.tempDir, "regex-assembly", "include"), 0o755))
	s.Require().NoError(preflightAssembly("include shared\nfoo\n", s.tempDir))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/regexperf/ -run TestCompileTestSuite -v`
Expected: FAIL — `TestAssembleFileIncludeMissingCrsRoot` expects an error but the stub returns nil (and, worse, would reach the assembler). `TestPreflightIncludeWithValidRoot` passes trivially with the stub; that is acceptable — the meaningful failure is the missing-root case.

- [ ] **Step 3: Write the implementation**

In `internal/regexperf/compile.go`, replace the stub `preflightAssembly` with:

```go
// includeDirectivePattern matches `include` and `include-except` directives at
// the start of a (trimmed) regex-assembly line.
var includeDirectivePattern = regexp.MustCompile(`(?m)^\s*include(-except)?\s`)

// preflightAssembly guards against the crs-toolchain assembler's use of
// logger.Fatal() (which calls os.Exit) when an include file cannot be opened.
// If the .ra content uses any include directive, the coreruleset root must
// contain a regex-assembly/ directory; otherwise we return an actionable error
// before the assembler runs.
func preflightAssembly(content string, crsRoot string) error {
	if !includeDirectivePattern.MatchString(content) {
		return nil
	}
	assemblyDir := filepath.Join(crsRoot, "regex-assembly")
	info, err := os.Stat(assemblyDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf(
			"regex-assembly file uses include directives but %q has no regex-assembly/ directory; pass --crs-path pointing at a coreruleset checkout",
			crsRoot)
	}
	return nil
}
```

Add `"path/filepath"` to the imports in `compile.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/regexperf/ -run TestCompileTestSuite -v`
Expected: PASS (all subtests, including the three new ones).

- [ ] **Step 5: Commit**

```bash
git add internal/regexperf/compile.go internal/regexperf/compile_test.go
git commit -m "feat(regexperf): preflight guard for assembler include fatals"
```

---

## Task 3: Stats core — aggregation, percentiles, top-N heap

**Files:**
- Create: `internal/regexperf/stats.go`
- Test: `internal/regexperf/stats_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/regexperf/stats_test.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type statsTestSuite struct {
	suite.Suite
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(statsTestSuite))
}

func (s *statsTestSuite) TestAggregateBasics() {
	st := NewStats("pattern", 10, 1, 3)
	st.Add("a", 100, true)
	st.Add("b", 300, false)
	st.Add("c", 200, true)

	r := st.report()
	s.Equal(3, r.SubjectCount)
	s.Equal(2, r.MatchCount)
	s.Equal(int64(600), r.TotalNs)
	s.Equal(int64(200), r.MeanNs)   // 600/3
	s.Equal(int64(200), r.MedianNs) // middle of [100,200,300]
	s.Equal(int64(300), r.MaxNs)
}

func (s *statsTestSuite) TestTopNKeepsSlowest() {
	st := NewStats("pattern", 1, 1, 2) // keep top 2
	st.Add("slow1", 500, true)
	st.Add("fast", 10, false)
	st.Add("slow2", 400, true)
	st.Add("mid", 100, false)

	r := st.report()
	s.Len(r.Slowest, 2)
	s.Equal("slow1", r.Slowest[0].Subject) // descending by Ns
	s.Equal(int64(500), r.Slowest[0].Ns)
	s.Equal("slow2", r.Slowest[1].Subject)
	s.Equal(int64(400), r.Slowest[1].Ns)
}

func (s *statsTestSuite) TestEmptyStats() {
	st := NewStats("pattern", 0, 1, 3)
	r := st.report()
	s.Equal(0, r.SubjectCount)
	s.Equal(int64(0), r.MeanNs)
	s.Equal(float64(0), r.ThroughputPerSec)
	s.Empty(r.Slowest)
}

func (s *statsTestSuite) TestThroughput() {
	st := NewStats("pattern", 0, 1, 1)
	// 2 subjects taking 1ms total -> 2000 subj/s
	st.Add("a", 400_000, true)
	st.Add("b", 600_000, true)
	r := st.report()
	s.InDelta(2000.0, r.ThroughputPerSec, 0.001)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/regexperf/ -run TestStatsTestSuite -v`
Expected: FAIL — `undefined: NewStats`.

- [ ] **Step 3: Write the implementation**

Create `internal/regexperf/stats.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"container/heap"
	"math"
	"slices"
)

// Sample is the timing result for one subject.
type Sample struct {
	Subject string `json:"subject"`
	Ns      int64  `json:"ns"`
	Matched bool   `json:"matched"`
}

// slowestHeap is a min-heap of Samples by Ns, used to retain the top-N slowest.
type slowestHeap []Sample

func (h slowestHeap) Len() int            { return len(h) }
func (h slowestHeap) Less(i, j int) bool  { return h[i].Ns < h[j].Ns }
func (h slowestHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *slowestHeap) Push(x any)         { *h = append(*h, x.(Sample)) }
func (h *slowestHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// Stats accumulates per-subject timing results.
type Stats struct {
	regexSource  string
	regexBytes   int
	repeat       int
	topN         int
	subjectCount int
	matchCount   int
	totalNs      int64
	maxNs        int64
	minsNs       []int64 // per-subject minimum ns, for percentiles
	slowest      slowestHeap
}

// NewStats returns an empty Stats. regexSource describes the regex origin,
// regexBytes is the length of the compiled regex string, repeat is the per-subject
// match repetition count, topN is how many slowest subjects to retain.
func NewStats(regexSource string, regexBytes int, repeat int, topN int) *Stats {
	return &Stats{
		regexSource: regexSource,
		regexBytes:  regexBytes,
		repeat:      repeat,
		topN:        topN,
		minsNs:      make([]int64, 0, 1024),
		slowest:     make(slowestHeap, 0, topN+1),
	}
}

// Add records one subject's timing result.
func (s *Stats) Add(subject string, ns int64, matched bool) {
	s.subjectCount++
	if matched {
		s.matchCount++
	}
	s.totalNs += ns
	if ns > s.maxNs {
		s.maxNs = ns
	}
	s.minsNs = append(s.minsNs, ns)
	if s.topN > 0 {
		heap.Push(&s.slowest, Sample{Subject: subject, Ns: ns, Matched: matched})
		if s.slowest.Len() > s.topN {
			heap.Pop(&s.slowest)
		}
	}
}

// report is the computed view of the accumulated stats, shared by the normal
// and JSON output paths.
type report struct {
	RegexSource      string   `json:"regexSource"`
	RegexBytes       int      `json:"regexBytes"`
	Repeat           int      `json:"repeat"`
	SubjectCount     int      `json:"subjectCount"`
	MatchCount       int      `json:"matchCount"`
	TotalNs          int64    `json:"totalNs"`
	MeanNs           int64    `json:"meanNs"`
	MedianNs         int64    `json:"medianNs"`
	P99Ns            int64    `json:"p99Ns"`
	MaxNs            int64    `json:"maxNs"`
	ThroughputPerSec float64  `json:"throughputPerSec"`
	Slowest          []Sample `json:"slowest"`
}

func (s *Stats) report() report {
	sorted := slices.Clone(s.minsNs)
	slices.Sort(sorted)

	var meanNs int64
	var throughput float64
	if s.subjectCount > 0 {
		meanNs = s.totalNs / int64(s.subjectCount)
	}
	if s.totalNs > 0 {
		throughput = float64(s.subjectCount) / (float64(s.totalNs) / 1e9)
	}

	return report{
		RegexSource:      s.regexSource,
		RegexBytes:       s.regexBytes,
		Repeat:           s.repeat,
		SubjectCount:     s.subjectCount,
		MatchCount:       s.matchCount,
		TotalNs:          s.totalNs,
		MeanNs:           meanNs,
		MedianNs:         percentile(sorted, 50),
		P99Ns:            percentile(sorted, 99),
		MaxNs:            s.maxNs,
		ThroughputPerSec: throughput,
		Slowest:          s.slowestSorted(),
	}
}

// slowestSorted returns the retained slowest samples in descending Ns order.
func (s *Stats) slowestSorted() []Sample {
	out := slices.Clone([]Sample(s.slowest))
	slices.SortFunc(out, func(a, b Sample) int {
		return int(b.Ns - a.Ns)
	})
	return out
}

// percentile returns the p-th percentile (0-100) of a sorted slice using
// nearest-rank rounding. Returns 0 for an empty slice.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := p / 100 * float64(len(sorted)-1)
	idx := int(math.Round(rank))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/regexperf/ -run TestStatsTestSuite -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/regexperf/stats.go internal/regexperf/stats_test.go
git commit -m "feat(regexperf): stats aggregation, percentiles, top-N heap"
```

---

## Task 4: Stats output — normal and JSON formatting

**Files:**
- Modify: `internal/regexperf/stats.go` (add `printSummary`, `MarshalJSON`)
- Test: `internal/regexperf/stats_test.go` (add cases)

- [ ] **Step 1: Write the failing test**

Append to `internal/regexperf/stats_test.go`:

```go
import (
	"bytes"
	"encoding/json"

	"github.com/coreruleset/go-ftw/v2/output"
)
// NOTE: merge these imports into the existing import block at the top of the file.

func (s *statsTestSuite) TestPrintSummaryNormal() {
	st := NewStats("file:foo.ra", 12, 5, 3)
	st.Add("' UNION SELECT 1", 1200, true)
	st.Add("hello", 300, false)

	var buf bytes.Buffer
	out := output.NewOutput("plain", &buf)
	st.printSummary(out)

	text := buf.String()
	s.Contains(text, "file:foo.ra")
	s.Contains(text, "subjects: 2")
	s.Contains(text, "matched: 1")
	s.Contains(text, "slowest subjects")
	s.Contains(text, "UNION SELECT")
}

func (s *statsTestSuite) TestPrintSummaryJSON() {
	st := NewStats("pattern", 8, 1, 2)
	st.Add("a", 100, true)
	st.Add("b", 200, false)

	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)
	st.printSummary(out)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal("pattern", r.RegexSource)
	s.Equal(2, r.SubjectCount)
	s.Equal(1, r.MatchCount)
	s.Len(r.Slowest, 2)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/regexperf/ -run TestStatsTestSuite -v`
Expected: FAIL — `st.printSummary undefined`.

- [ ] **Step 3: Write the implementation**

Add to the imports of `internal/regexperf/stats.go`:

```go
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/v2/output"
```

Append to `internal/regexperf/stats.go`:

```go
// maxSubjectDisplayLen caps subject length in normal (human) output.
const maxSubjectDisplayLen = 80

// MarshalJSON renders the computed report.
func (s *Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.report())
}

// printSummary writes the report to out in JSON or human-readable form.
func (s *Stats) printSummary(out *output.Output) {
	if out.IsJson() {
		b, err := json.Marshal(s)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal regexperf stats to JSON")
			return
		}
		out.RawPrint(string(b))
		return
	}

	r := s.report()
	out.Println("regex: %s (compiled, %d bytes)", r.RegexSource, r.RegexBytes)
	out.Println("subjects: %d  matched: %d", r.SubjectCount, r.MatchCount)
	out.Println("total: %s  mean: %s  median: %s",
		dur(r.TotalNs), dur(r.MeanNs), dur(r.MedianNs))
	out.Println("p99: %s  max: %s", dur(r.P99Ns), dur(r.MaxNs))
	out.Println("throughput: %.0f subj/s", r.ThroughputPerSec)

	if len(r.Slowest) == 0 {
		return
	}
	out.Println("")
	out.Println("slowest subjects:")
	for _, sample := range r.Slowest {
		out.Println("  %s  %q", dur(sample.Ns), truncate(sample.Subject, maxSubjectDisplayLen))
	}
}

// dur formats a nanosecond count as a human-readable duration.
func dur(ns int64) string {
	return time.Duration(ns).String()
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

var _ = fmt.Sprintf // retain fmt import if unused elsewhere; remove if linter flags it
```

Note: if `gofumpt`/`golangci-lint` flags the unused `fmt` import, delete the `fmt` import line and the `var _ = fmt.Sprintf` line. (They are included only as a safety net; `fmt` is not otherwise used in this file.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/regexperf/ -run TestStatsTestSuite -v`
Expected: PASS.

- [ ] **Step 5: Verify formatting/lint of the new file**

Run: `gofumpt -l internal/regexperf/stats.go && golangci-lint run ./internal/regexperf/...`
Expected: no output from `gofumpt` (already formatted), no lint errors. Fix any reported issues (e.g. remove the `fmt` safety-net lines if flagged).

- [ ] **Step 6: Commit**

```bash
git add internal/regexperf/stats.go internal/regexperf/stats_test.go
git commit -m "feat(regexperf): normal and JSON report output"
```

---

## Task 5: Benchmark orchestration — inline subject path

**Files:**
- Create: `internal/regexperf/benchmark.go`
- Test: `internal/regexperf/benchmark_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/regexperf/benchmark_test.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/output"
)

type benchmarkTestSuite struct {
	suite.Suite
}

func TestBenchmarkTestSuite(t *testing.T) {
	suite.Run(t, new(benchmarkTestSuite))
}

func (s *benchmarkTestSuite) TestRunInlineSubjectMatch() {
	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	err := Run(Params{
		Pattern: `(?i)select`,
		Subject: "UNION SELECT 1",
		Repeat:  3,
		TopN:    5,
	}, out)
	s.Require().NoError(err)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal("pattern", r.RegexSource)
	s.Equal(1, r.SubjectCount)
	s.Equal(1, r.MatchCount)
	s.Len(r.Slowest, 1)
	s.True(r.Slowest[0].Matched)
}

func (s *benchmarkTestSuite) TestRunInlineSubjectNoMatch() {
	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	err := Run(Params{
		Pattern: `\d{5}`,
		Subject: "no digits here",
		Repeat:  1,
		TopN:    5,
	}, out)
	s.Require().NoError(err)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal(1, r.SubjectCount)
	s.Equal(0, r.MatchCount)
}

func (s *benchmarkTestSuite) TestRunInvalidPattern() {
	out := output.NewOutput("json", &bytes.Buffer{})
	err := Run(Params{Pattern: `(unclosed`, Subject: "x", Repeat: 1, TopN: 1}, out)
	s.Require().Error(err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/regexperf/ -run TestBenchmarkTestSuite -v`
Expected: FAIL — `undefined: Run` / `undefined: Params`.

- [ ] **Step 3: Write the implementation**

Create `internal/regexperf/benchmark.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package regexperf

import (
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative/leipzig"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative/raw"
	"github.com/coreruleset/go-ftw/v2/output"
)

// Params holds the inputs for a regex performance run.
type Params struct {
	// Pattern is a raw regex; when set, the assembler is skipped.
	Pattern string
	// RaFile is the path to a regex-assembly (.ra) file.
	RaFile string
	// CrsPath is the coreruleset root for resolving .ra includes.
	CrsPath string
	// Subject is a single inline subject; when set, the corpus is skipped.
	Subject string
	// Repeat is how many times each subject is matched (minimum time kept).
	Repeat int
	// TopN is how many slowest subjects to report.
	TopN int
	// Lines optionally limits how many corpus subjects are processed (0 = all).
	Lines int
	// Corpus selection and metadata (used in corpus mode).
	Corpus          corpus.Type
	CorpusSize      string
	CorpusYear      string
	CorpusLang      string
	CorpusSource    string
	CorpusLocalPath string
}

// Run resolves the regex, then times it against the inline subject or the
// configured corpus, writing a report to out.
func (p Params) repeatOrOne() int {
	if p.Repeat < 1 {
		return 1
	}
	return p.Repeat
}

func Run(params Params, out *output.Output) error {
	regexStr, source, err := resolveRegex(params)
	if err != nil {
		return err
	}
	re, err := Compile(regexStr)
	if err != nil {
		return err
	}
	stats := NewStats(source, len(regexStr), params.repeatOrOne(), params.TopN)

	if params.Subject != "" {
		ns, matched := timeMatch(re, params.Subject, params.repeatOrOne())
		stats.Add(params.Subject, ns, matched)
		stats.printSummary(out)
		return nil
	}

	if err := runCorpus(params, re, stats); err != nil {
		return err
	}
	if stats.subjectCount == 0 {
		return fmt.Errorf("no subjects found in corpus")
	}
	stats.printSummary(out)
	return nil
}

// resolveRegex returns the regex string and a human-readable source label.
func resolveRegex(p Params) (regexStr string, source string, err error) {
	if p.Pattern != "" {
		return p.Pattern, "pattern", nil
	}
	if p.RaFile == "" {
		return "", "", fmt.Errorf("either a pattern or a regex-assembly file is required")
	}
	regexStr, err = AssembleFile(p.RaFile, p.CrsPath)
	if err != nil {
		return "", "", err
	}
	return regexStr, "file:" + p.RaFile, nil
}

// runCorpus iterates the configured corpus, timing the regex against each subject.
func runCorpus(params Params, re *regexp.Regexp, stats *Stats) error {
	corpusRunner, err := newCorpus(params.Corpus, params.CorpusLocalPath)
	if err != nil {
		return err
	}
	corpusRunner = corpusRunner.
		WithSize(params.CorpusSize).
		WithYear(params.CorpusYear).
		WithSource(params.CorpusSource).
		WithLanguage(params.CorpusLang)

	cf := corpusRunner.FetchCorpusFile()
	repeat := params.repeatOrOne()
	for iter := corpusRunner.GetIterator(cf); iter.HasNext(); {
		if params.Lines > 0 && stats.subjectCount >= params.Lines {
			break
		}
		payload := iter.Next()
		ns, matched := timeMatch(re, payload.Content(), repeat)
		stats.Add(payload.Content(), ns, matched)
	}
	return corpusRunner.CloseIterator()
}

// newCorpus builds a corpus runner for the given type (mirrors the quantitative
// factory without importing it, to avoid pulling in the Coraza engine).
func newCorpus(t corpus.Type, localPath string) (corpus.Corpus, error) {
	switch t {
	case corpus.Leipzig:
		return leipzig.NewLeipzigCorpus(localPath), nil
	case corpus.Raw:
		return raw.NewRawCorpus(localPath), nil
	default:
		return nil, fmt.Errorf("unsupported corpus type: %s", t)
	}
}

// timeMatch matches subject `repeat` times and returns the minimum elapsed
// nanoseconds (the cleanest estimator of true cost) and whether it matched.
func timeMatch(re *regexp.Regexp, subject string, repeat int) (int64, bool) {
	var minNs int64 = math.MaxInt64
	var matched bool
	for i := 0; i < repeat; i++ {
		start := time.Now()
		m := re.MatchString(subject)
		elapsed := time.Since(start).Nanoseconds()
		if i == 0 {
			matched = m
		}
		if elapsed < minNs {
			minNs = elapsed
		}
	}
	return minNs, matched
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/regexperf/ -run TestBenchmarkTestSuite -v`
Expected: PASS (3 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/regexperf/benchmark.go internal/regexperf/benchmark_test.go
git commit -m "feat(regexperf): benchmark runner with inline subject path"
```

---

## Task 6: Benchmark — raw corpus iteration

**Files:**
- Test: `internal/regexperf/benchmark_test.go` (add a raw-corpus case)

This task verifies the corpus path already implemented in Task 5 against a real (raw) corpus file.

- [ ] **Step 1: Write the failing test**

Append to `internal/regexperf/benchmark_test.go`:

```go
import (
	"os"
	"path/filepath"
)
// NOTE: merge these into the existing import block.

func (s *benchmarkTestSuite) TestRunRawCorpus() {
	dir := s.T().TempDir()
	subjects := filepath.Join(dir, "subjects.txt")
	content := "alpha select beta\nplain line\nSELECT again\n"
	s.Require().NoError(os.WriteFile(subjects, []byte(content), 0o600))

	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	err := Run(Params{
		Pattern:         `(?i)select`,
		Repeat:          2,
		TopN:            10,
		Corpus:          corpus.Raw,
		CorpusLocalPath: subjects,
	}, out)
	s.Require().NoError(err)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal(3, r.SubjectCount)
	s.Equal(2, r.MatchCount) // lines 1 and 3 contain "select"
	s.LessOrEqual(r.MedianNs, r.MaxNs)
}

func (s *benchmarkTestSuite) TestRunLinesLimit() {
	dir := s.T().TempDir()
	subjects := filepath.Join(dir, "many.txt")
	s.Require().NoError(os.WriteFile(subjects, []byte("a\nb\nc\nd\ne\n"), 0o600))

	var buf bytes.Buffer
	out := output.NewOutput("json", &buf)

	err := Run(Params{
		Pattern:         `x`,
		Repeat:          1,
		TopN:            3,
		Lines:           2,
		Corpus:          corpus.Raw,
		CorpusLocalPath: subjects,
	}, out)
	s.Require().NoError(err)

	var r report
	s.Require().NoError(json.Unmarshal(buf.Bytes(), &r))
	s.Equal(2, r.SubjectCount)
}
```

Add the `"github.com/coreruleset/go-ftw/v2/internal/corpus"` import to `benchmark_test.go` if not already present.

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `go test ./internal/regexperf/ -run TestBenchmarkTestSuite -v`
Expected: PASS (the corpus path was implemented in Task 5). If `TestRunRawCorpus`/`TestRunLinesLimit` fail, fix `runCorpus` in `benchmark.go` until they pass. (This task exists to prove the corpus path; do not skip running it.)

- [ ] **Step 3: Commit**

```bash
git add internal/regexperf/benchmark_test.go
git commit -m "test(regexperf): raw corpus iteration and lines limit"
```

---

## Task 7: CLI — `regex` group and `perf` subcommand

**Files:**
- Create: `cmd/regex/regex.go`
- Create: `cmd/regex/perf.go`
- Test: `cmd/regex/perf_test.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/regex/perf_test.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
)

type perfCmdTestSuite struct {
	suite.Suite
}

func TestPerfCmdTestSuite(t *testing.T) {
	suite.Run(t, new(perfCmdTestSuite))
}

func (s *perfCmdTestSuite) newCmd() (*bytes.Buffer, *bytes.Buffer, *cobraRoot) {
	return nil, nil, nil
}

func (s *perfCmdTestSuite) TestRequiresFileOrPattern() {
	root := New(internal.NewCommandContext())
	root.SetArgs([]string{"perf", "--subject", "x"})
	err := root.Execute()
	s.Require().Error(err)
	s.Contains(err.Error(), "either")
}

func (s *perfCmdTestSuite) TestRejectsBothFileAndPattern() {
	root := New(internal.NewCommandContext())
	root.SetArgs([]string{"perf", "--file", "a.ra", "--pattern", "x", "--subject", "y"})
	err := root.Execute()
	s.Require().Error(err)
	s.Contains(err.Error(), "only one")
}

func (s *perfCmdTestSuite) TestPatternWithSubjectSmoke() {
	var buf bytes.Buffer
	root := New(internal.NewCommandContext())
	root.SetOut(&buf)
	root.SetArgs([]string{"perf",
		"--pattern", "(?i)select",
		"--subject", "UNION SELECT 1",
		"--output", "json",
	})
	err := root.Execute()
	s.Require().NoError(err)
	s.Contains(buf.String(), "\"subjectCount\":1")
}
```

Remove the unused `newCmd`/`cobraRoot` helper stub before finishing — it is shown here only to illustrate; the actual tests construct the command via `New(...)`. (Delete the `newCmd` method and any `cobraRoot` reference.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/regex/ -run TestPerfCmdTestSuite -v`
Expected: FAIL — `undefined: New` (package has no command yet).

- [ ] **Step 3: Write the parent group**

Create `cmd/regex/regex.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
)

// New returns the `regex` parent command and registers its subcommands.
func New(cmdContext *internal.CommandContext) *cobra.Command {
	regexCmd := &cobra.Command{
		Use:   "regex",
		Short: "Tools for working with CRS regular expressions",
		Long:  "Tools for working with OWASP CRS regular expressions, such as performance benchmarking.",
	}
	regexCmd.AddCommand(newPerfCommand(cmdContext))
	return regexCmd
}
```

- [ ] **Step 4: Write the perf subcommand**

Create `cmd/regex/perf.go`:

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/regexperf"
	"github.com/coreruleset/go-ftw/v2/output"
)

const (
	fileFlag            = "file"
	patternFlag         = "pattern"
	subjectFlag         = "subject"
	crsPathFlag         = "crs-path"
	repeatFlag          = "repeat"
	topFlag             = "top"
	linesFlag           = "lines"
	corpusFlag          = "corpus"
	corpusSizeFlag      = "corpus-size"
	corpusLangFlag      = "corpus-lang"
	corpusYearFlag      = "corpus-year"
	corpusSourceFlag    = "corpus-source"
	corpusLocalPathFlag = "corpus-local-path"
	outputTypeFlag      = "output"
	outFileFlag         = "out-file"
)

// newPerfCommand builds the `regex perf` subcommand.
func newPerfCommand(_ *internal.CommandContext) *cobra.Command {
	perfCmd := &cobra.Command{
		Use:   "perf",
		Short: "Benchmark the runtime performance of a regex against input subjects",
		Long: `Compile a regex from a CRS regex-assembly (.ra) file or a raw pattern,
then measure how it performs against the quantitative corpus or a single subject.`,
		RunE: runPerfE,
	}

	perfCmd.Flags().StringP(fileFlag, "f", "", "Path to a regex-assembly (.ra) file to compile and benchmark.")
	perfCmd.Flags().StringP(patternFlag, "p", "", "Raw regex pattern to benchmark (skips the assembler).")
	perfCmd.Flags().String(subjectFlag, "", "Single inline subject to benchmark against (skips the corpus).")
	perfCmd.Flags().StringP(crsPathFlag, "C", ".", "Path to top folder of local CRS installation (for .ra includes).")
	perfCmd.Flags().IntP(repeatFlag, "R", 10, "Times each subject is matched; the minimum time is kept.")
	perfCmd.Flags().Int(topFlag, 10, "Number of slowest subjects to report.")
	perfCmd.Flags().IntP(linesFlag, "l", 0, "Maximum number of corpus subjects to process (0 = all).")
	perfCmd.Flags().StringP(corpusFlag, "c", "leipzig", "Corpus to use (leipzig, raw).")
	perfCmd.Flags().StringP(corpusSizeFlag, "s", "100K", "Corpus size, e.g. \"100K\", \"1M\".")
	perfCmd.Flags().StringP(corpusLangFlag, "L", "eng", "Corpus language.")
	perfCmd.Flags().StringP(corpusYearFlag, "y", "2023", "Corpus year.")
	perfCmd.Flags().StringP(corpusSourceFlag, "S", "news", "Corpus source, e.g. \"news\", \"web\".")
	perfCmd.Flags().String(corpusLocalPathFlag, "", "Storage path for downloaded corpora; for \"raw\", the path to the corpus file.")
	perfCmd.Flags().StringP(outputTypeFlag, "o", "normal", "Output type: normal or json.")
	perfCmd.Flags().String(outFileFlag, "", "Write the report to this file (default stdout).")

	return perfCmd
}

//gocyclo:ignore
func runPerfE(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	file, err := cmd.Flags().GetString(fileFlag)
	if err != nil {
		return err
	}
	pattern, err := cmd.Flags().GetString(patternFlag)
	if err != nil {
		return err
	}
	if file != "" && pattern != "" {
		return fmt.Errorf("only one of --%s or --%s may be set", fileFlag, patternFlag)
	}
	if file == "" && pattern == "" {
		return fmt.Errorf("either --%s or --%s is required", fileFlag, patternFlag)
	}

	subject, err := cmd.Flags().GetString(subjectFlag)
	if err != nil {
		return err
	}
	if subject != "" && cmd.Flags().Changed(corpusFlag) {
		return fmt.Errorf("--%s cannot be combined with --%s", subjectFlag, corpusFlag)
	}

	params, err := buildPerfParams(cmd, file, pattern, subject)
	if err != nil {
		return err
	}

	out, closer, err := openPerfOutput(cmd)
	if err != nil {
		return err
	}
	defer closer()

	return regexperf.Run(params, out)
}

// buildPerfParams reads the remaining flags into a regexperf.Params.
func buildPerfParams(cmd *cobra.Command, file, pattern, subject string) (regexperf.Params, error) {
	var p regexperf.Params
	var err error

	p.RaFile = file
	p.Pattern = pattern
	p.Subject = subject

	if p.CrsPath, err = cmd.Flags().GetString(crsPathFlag); err != nil {
		return p, err
	}
	if p.Repeat, err = cmd.Flags().GetInt(repeatFlag); err != nil {
		return p, err
	}
	if p.TopN, err = cmd.Flags().GetInt(topFlag); err != nil {
		return p, err
	}
	if p.Lines, err = cmd.Flags().GetInt(linesFlag); err != nil {
		return p, err
	}
	if p.CorpusSize, err = cmd.Flags().GetString(corpusSizeFlag); err != nil {
		return p, err
	}
	if p.CorpusLang, err = cmd.Flags().GetString(corpusLangFlag); err != nil {
		return p, err
	}
	if p.CorpusYear, err = cmd.Flags().GetString(corpusYearFlag); err != nil {
		return p, err
	}
	if p.CorpusSource, err = cmd.Flags().GetString(corpusSourceFlag); err != nil {
		return p, err
	}
	if p.CorpusLocalPath, err = cmd.Flags().GetString(corpusLocalPathFlag); err != nil {
		return p, err
	}

	corpusType := corpus.NoType
	corpusTypeStr, err := cmd.Flags().GetString(corpusFlag)
	if err != nil {
		return p, err
	}
	if subject == "" && corpusTypeStr != "" {
		if err := corpusType.Set(corpusTypeStr); err != nil {
			return p, err
		}
	}
	p.Corpus = corpusType
	return p, nil
}

// openPerfOutput creates the Output and a closer for the destination file.
func openPerfOutput(cmd *cobra.Command) (*output.Output, func(), error) {
	wantedOutput, err := cmd.Flags().GetString(outputTypeFlag)
	if err != nil {
		return nil, func() {}, err
	}
	outFilename, err := cmd.Flags().GetString(outFileFlag)
	if err != nil {
		return nil, func() {}, err
	}

	if outFilename == "" {
		return output.NewOutput(wantedOutput, cmd.OutOrStdout()), func() {}, nil
	}
	f, err := os.OpenFile(outFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, func() {}, err
	}
	return output.NewOutput(wantedOutput, f), func() { _ = f.Close() }, nil
}
```

Note on `--subject` + corpus mode: when `--subject` is empty the corpus is used (default `leipzig`). When `--subject` is set, the corpus is skipped; combining it with an explicit `--corpus` flag is rejected.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./cmd/regex/ -run TestPerfCmdTestSuite -v`
Expected: PASS (3 subtests). Ensure the illustrative `newCmd`/`cobraRoot` stub was removed from the test file.

- [ ] **Step 6: Commit**

```bash
git add cmd/regex/regex.go cmd/regex/perf.go cmd/regex/perf_test.go
git commit -m "feat(cmd): add regex perf subcommand"
```

---

## Task 8: Register the command on the root

**Files:**
- Modify: `cmd/root.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/regex_wiring_test.go` (package `cmd`, alongside `root.go`):

```go
// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
)

func TestRegexCommandRegistered(t *testing.T) {
	rootCmd := NewRootCommand(internal.NewCommandContext())
	// Manually add subcommands the way Execute does, then assert "regex" exists.
	addSubcommands(rootCmd, internal.NewCommandContext())

	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "regex" {
			found = true
			break
		}
	}
	require.True(t, found, "expected 'regex' command to be registered")
}
```

This test references a new helper `addSubcommands`. In Step 3 you will refactor `Execute` to use it so the test (and `Execute`) share one registration path.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestRegexCommandRegistered -v`
Expected: FAIL — `undefined: addSubcommands`.

- [ ] **Step 3: Implement the wiring**

In `cmd/root.go`, add the import:

```go
	regex "github.com/coreruleset/go-ftw/v2/cmd/regex"
```

Replace the body of `Execute` so registration lives in a reusable helper:

```go
// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) error {
	cmdContext := internal.NewCommandContext()
	rootCmd := NewRootCommand(cmdContext)
	addSubcommands(rootCmd, cmdContext)
	// Setting Version creates a `--version` flag
	rootCmd.Version = version

	return rootCmd.ExecuteContext(context.Background())
}

// addSubcommands registers all child commands on rootCmd.
func addSubcommands(rootCmd *cobra.Command, cmdContext *internal.CommandContext) {
	rootCmd.AddCommand(
		check.New(cmdContext),
		run.New(cmdContext),
		quantitative.New(cmdContext),
		regex.New(cmdContext),
		selfUpdate.New(cmdContext),
	)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run TestRegexCommandRegistered -v`
Expected: PASS.

- [ ] **Step 5: Verify the command is reachable end-to-end**

Run:
```bash
go run . regex perf --pattern '(?i)select' --subject "UNION SELECT 1" -o json
```
Expected: a single-line JSON report containing `"subjectCount":1` and `"matchCount":1`.

- [ ] **Step 6: Commit**

```bash
git add cmd/root.go cmd/regex_wiring_test.go
git commit -m "feat(cmd): register regex command on root"
```

---

## Task 9: Full verification and docs

**Files:**
- Modify: `CLAUDE.md` (Common Commands → add a `regex perf` example) — only if the repo's existing `CLAUDE.md` documents commands (it does).

- [ ] **Step 1: Run the full test suite with race detector**

Run: `go test -race ./...`
Expected: PASS across all packages. Investigate and fix any failure before proceeding.

- [ ] **Step 2: Lint and format**

Run:
```bash
gofumpt -l .
golangci-lint run
go vet ./...
```
Expected: `gofumpt -l .` prints nothing for the new files; `golangci-lint` and `go vet` report no issues. Fix everything (zero-warnings policy).

- [ ] **Step 3: Supply-chain checks for the new dependency**

Run:
```bash
go mod verify
govulncheck ./...
```
Expected: `go mod verify` prints `all modules verified`; `govulncheck` reports no vulnerabilities in called code. If `govulncheck` flags the new dependency, note it and surface to the user before merging.

- [ ] **Step 4: Add a usage example to `CLAUDE.md`**

In `CLAUDE.md` under "Common Commands", add after the quantitative examples:

```bash
# Benchmark a regex from a .ra file against the corpus
./ftw regex perf --file rules/942100.ra -C /path/to/coreruleset -s 10K

# Benchmark a raw pattern against a single subject
./ftw regex perf --pattern '(?i)union\s+select' --subject "' UNION SELECT 1,2,3"
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document regex perf command"
```

---

## Self-Review

**Spec coverage:**
- `.ra` input via assembler → Task 1 (`AssembleFile`).
- Raw pattern input → Task 1 (`Compile`) + Task 5 (`resolveRegex`).
- Corpus subjects (Leipzig/raw) → Task 5/6 (`runCorpus`, `newCorpus`).
- Single inline subject → Task 5 (`Run` subject branch).
- Aggregate + slowest-subjects report → Task 3/4.
- min-of-K timing → Task 5 (`timeMatch`).
- normal + json output → Task 4.
- CLI shape `regex perf` with mutual-exclusion validation → Task 7/8.
- crs-toolchain dependency + supply-chain checks → Task 1/9.
- Memory bound (top-N heap, per-subject ns slice) → Task 3.
- Error handling (missing file, assembler error, compile error, empty corpus, flag validation) → Tasks 1,2,5,7.

**Resolved open items:** config filename `"toolchain.yaml"`, corpus reuse via local `newCorpus` (no Coraza pull), report flag `--out-file` — all reflected in tasks.

**Added beyond spec (justified):** Task 2 preflight guard against the assembler's `os.Exit` on missing includes — a robustness gap discovered while verifying the API. The spec will get a short addendum noting this.

**Placeholder scan:** the only illustrative stubs (the `var _ = fmt.Sprintf` safety net in Task 4; the `newCmd`/`cobraRoot` stub in Task 7) carry explicit removal instructions. No TBDs.

**Type consistency:** `Params`, `Stats`, `Sample`, `report`, `Run`, `AssembleFile`, `Compile`, `NewStats`, `timeMatch`, `newCorpus`, `addSubcommands` are used with identical signatures across tasks.
