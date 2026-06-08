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

// preflightAssembly is implemented in Task 2.
func preflightAssembly(_ string, _ string) error { return nil }
