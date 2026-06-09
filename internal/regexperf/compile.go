// Copyright 2026 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

// Package regexperf benchmarks the runtime performance of regular expressions
// generated from OWASP CRS regex-assembly (.ra) files, or supplied directly,
// against a corpus of input subjects.
package regexperf

import (
	"fmt"
	"os"
	"path/filepath"
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

// includeDirectivePattern matches `include`/`include-except` directives and
// captures the (first) referenced fragment name.
var includeDirectivePattern = regexp.MustCompile(`(?m)^\s*include(?:-except)?\s+(\S+)`)

// preflightAssembly guards against the crs-toolchain assembler's use of
// logger.Fatal() (which calls os.Exit) when an included fragment cannot be
// opened. For each top-level include directive it verifies the referenced
// fragment exists under <crsRoot>/regex-assembly/include or .../exclude
// (mirroring the assembler's own resolution: a missing ".ra" extension is
// appended, absolute paths are used as-is). It returns an actionable error
// instead of letting the process exit.
//
// Limitation: only top-level includes in this file are validated. A missing
// include referenced transitively by another fragment will still cause the
// assembler to abort.
func preflightAssembly(content string, crsRoot string) error {
	matches := includeDirectivePattern.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	assemblyDir := filepath.Join(crsRoot, "regex-assembly")
	if info, err := os.Stat(assemblyDir); err != nil || !info.IsDir() {
		return fmt.Errorf(
			"regex-assembly file uses include directives but %q has no regex-assembly/ directory; pass --crs-path pointing at a coreruleset checkout",
			crsRoot)
	}
	includeDir := filepath.Join(assemblyDir, "include")
	excludeDir := filepath.Join(assemblyDir, "exclude")
	for _, match := range matches {
		name := match[1]
		if filepath.Ext(name) != ".ra" {
			name += ".ra"
		}
		if filepath.IsAbs(name) {
			if fileExists(name) {
				continue
			}
			return fmt.Errorf("regex-assembly include %q not found; check the include path", match[1])
		}
		if fileExists(filepath.Join(includeDir, name)) || fileExists(filepath.Join(excludeDir, name)) {
			continue
		}
		return fmt.Errorf(
			"regex-assembly include %q not found under %s or %s; check the include name and --crs-path",
			match[1], includeDir, excludeDir)
	}
	return nil
}

// fileExists reports whether path exists and is a regular file (not a directory).
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
