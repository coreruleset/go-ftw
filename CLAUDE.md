# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-ftw is a Go-based framework for testing Web Application Firewalls (WAFs), primarily focused on the OWASP ModSecurity Core Rule Set. It executes YAML-defined test cases that send HTTP requests to a WAF and validates responses against expected behavior, either through log file analysis or HTTP status codes.

## Common Commands

### Building and Running
```bash
# Build the binary
go build -o ftw

# Run from source
go run main.go <command>

# Install locally
go install
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -coverprofile coverage.out ./...

# Run tests for a specific package
go test ./runner
go test ./ftwhttp

# Run a specific test
go test -run TestName ./path/to/package
```

### Linting
```bash
# Run golangci-lint (configured in .golangci.yml)
golangci-lint run

# Pre-commit hooks (includes linting)
pre-commit run --all-files
```

### Running FTW Tests
```bash
# Basic test run (requires .ftw.yaml config)
./ftw run -d tests/

# Run with time tracking
./ftw run -d tests/ -t

# Run specific tests by pattern
./ftw run -d tests/ -i "^920"

# Check YAML syntax
./ftw check -d tests/

# Run quantitative tests
./ftw quantitative -C /path/to/coreruleset -s 10K

# Benchmark a regex from a .ra file against the corpus
./ftw regex perf --file rules/942100.ra -C /path/to/coreruleset -s 10K

# Benchmark a raw pattern against a single subject
./ftw regex perf --pattern '(?i)union\s+select' --subject "' UNION SELECT 1,2,3"
```

### Release
```bash
# Release handled by goreleaser (see .goreleaser.yml)
goreleaser release --snapshot --clean
```

## Architecture Overview

### Core Package Relationships

The codebase follows a modular architecture with clear separation of concerns:

```text
CLI Layer (cmd/)
    ↓ orchestrates
Runner Layer (runner/)
    ↓ uses
HTTP Client (ftwhttp/) + WAF Log Reader (waflog/)
    ↓ validates using
Result Validation (runner/check_*.go)
    ↓ reports through
Output Formatters (output/)
```

### Key Components

**1. Command Layer (`cmd/`)**
- Entry point is `main.go` which calls `cmd.Execute()`
- Uses Cobra for CLI structure with subcommands: `run`, `check`, `quantitative`, `regex` (with `regex perf`), `self_update`
- `cmd/internal/types.go` defines `CommandContext` that carries configuration across commands
- Persistent flags (debug, trace, cloud mode, config file) apply to all subcommands

**2. Test Execution (`runner/`)**
- `runner.Run()` is the main orchestrator
- Creates `TestRunContext` containing: HTTP client, log reader, stats, filters
- For each test file, iterates through test cases and stages
- `RunStage()` executes individual test stages with marker-based log isolation
- Supports override system: ignore tests, force pass/fail, platform-specific input modifications

**3. HTTP Client (`ftwhttp/`)**
- `Client` is the top-level abstraction with `ClientConfig` (timeouts, TLS, rate limiting)
- `Connection` manages protocol-specific transport (HTTP/HTTPS over TCP)
- `Request` builds HTTP requests from test specs (normal or raw base64-encoded mode)
- Supports header autocomplete, cookie management, and connection reuse
- Protocol support: HTTP/1.1, HTTPS with TLS 1.2+, configurable InsecureSkipVerify

**4. Test Parsing (`test/`)**
- `GetTestsFromFiles()` and `GetTestFromYaml()` parse YAML test definitions
- Post-load processing: extracts rule IDs from filenames, normalizes headers, handles deprecated fields
- `FTWTest` wraps schema types and adds filename tracking
- Template evaluation: supports Go templates with Sprig v3 functions in request data

**5. WAF Log Analysis (`waflog/`)**
- `FTWLogLines` manages log file reading with state tracking
- **Marker-based isolation**: Injects unique headers (X-CRS-Test) to identify test boundaries
- Reverse-scans log files to find start/end markers
- Extracts triggered rule IDs using flexible regex (supports multiple log formats)
- Caches marked lines and triggered rules per test stage
- Cloud mode: skips log analysis, relies only on HTTP status codes

**6. Result Validation (`runner/check_*.go`)**
- `FTWCheck` orchestrates validation pipeline
- Sequential checks: expected errors → status code → response content → log analysis
- Override handling: force-ignore, force-pass, force-fail via regex matching
- Cloud mode special logic: 403 = WAF block (pass when expecting matches), 200/404/405 = pass (when expecting no matches)

### Data Flow

```text
YAML Test File
  ↓ Unmarshal (test package)
schema.Test with stages
  ↓ Apply overrides (runner)
Modified Input
  ↓ Build HTTP request (ftwhttp)
Raw HTTP bytes
  ↓ Send/Receive (ftwhttp)
Response + Logs
  ↓ Validate (runner/check_*.go)
TestResult (Success/Failed/Skipped/etc)
  ↓ Accumulate (runner)
RunStats with summary
  ↓ Format (output)
Console/JSON/GitHub output
```

### Critical Patterns

**Marker-Based Log Isolation**
Tests inject unique markers (via X-CRS-Test header) into WAF logs before and after each stage. The log reader reverse-scans to find these markers, isolating only the relevant log lines for each test. This enables accurate validation without global state assumptions and supports concurrent testing.

**Two Execution Modes**
- **Default mode**: Validates WAF behavior by parsing log files for triggered rules and messages
- **Cloud mode**: No log file access required; relies solely on HTTP status codes (403 = block, 2xx = allow)

**Override System**
Rather than modifying test files, apply regex-based overrides in config:
- `input`: Override global test parameters (dest_addr, port, headers, etc.)
- `ignore`: Skip tests matching regex patterns
- `forcepass`/`forcefail`: Override test results regardless of actual outcome

**Configuration Layering**
Config file → Environment variables → CLI flags (CLI flags take precedence)

**Template Evaluation**
Test data fields support Go templates with Sprig v3 functions:
```yaml
data: 'foo=%3d{{ "+" | repeat 34 }}'
data: 'username={{ env "USERNAME" }}'
```

## Working with Tests

### Test File Structure
Tests are defined in YAML with this structure:
```yaml
tests:
  - test_id: 123456-1
    rule_id: 123456
    stages:
      - stage:
          input:
            dest_addr: "127.0.0.1"
            port: 80
            method: "GET"
            uri: "/test"
            headers:
              User-Agent: "test"
          output:
            status: [403]
            log_contains: "id \"123456\""
```

### Running Single Tests
Use include/exclude regex flags:
```bash
# Run only test 123456-1
./ftw run -d tests/ -i "^123456-1$"

# Exclude tests starting with 91
./ftw run -d tests/ -e "^91"
```

### Debugging Tests
```bash
# Enable debug output
./ftw run -d tests/ --debug

# Enable trace (very verbose)
./ftw run -d tests/ --trace

# Show only failures
./ftw run -d tests/ --show-failures-only
```

## Code Organization

- `cmd/`: CLI commands and flag definitions
- `runner/`: Test execution engine and validation logic
- `ftwhttp/`: HTTP client implementation
- `test/`: YAML test parsing and schema handling
- `waflog/`: Log file parsing and marker management
- `config/`: Configuration file handling
- `output/`: Result formatting (normal, plain, JSON, GitHub)
- `utils/`: Shared utilities (logging, random generation)
- `internal/`: Internal packages (quantitative testing, corpus management)

## Module Path

The module is versioned at v2: `github.com/coreruleset/go-ftw/v2`

When importing packages:
```go
import "github.com/coreruleset/go-ftw/v2/runner"
import "github.com/coreruleset/go-ftw/v2/ftwhttp"
```

## Testing Approach

- Unit tests located alongside source files with `_test.go` suffix
- Test files often use `testdata/` subdirectories for fixtures
- Coverage tracked via `go test -coverprofile coverage.out`
- CI runs tests on Ubuntu and Windows (see `.github/workflows/test.yml`)
- Self-updater tests require `GH_TOKEN` environment variable
- Always use 'github.com/stretchr/testify/suite' pattern for writing tests

## Important Notes

- The binary is named `ftw`, not `go-ftw`
- Configuration file `.ftw.yaml` can be in PWD or HOME directory
- Log marker header defaults to `X-CRS-Test` (configurable via `logmarkerheadername`)
- Cloud mode requires setting `mode: "cloud"` in config
- Rule IDs can be extracted from test filenames (e.g., `920100.yaml` → rule 920100)
- Template functions from Sprig v3 library are available in test data fields
- The marker rule for CRS must be configured in the WAF (id:999999) to enable log-based testing

## Library Usage

go-ftw can be used as a library. Key entry points:
- `test.GetTestFromYaml()`: Parse test YAML
- `runner.Run()`: Execute tests programmatically
- `config.NewConfigFromFile()`: Load configuration
- `output.NewOutput()`: Create output formatter

See README.md "Library usage" section for detailed example.
