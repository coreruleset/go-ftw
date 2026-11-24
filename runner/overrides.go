// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"slices"
	"strings"

	schema "github.com/coreruleset/ftw-tests-schema/v3/types"

	"github.com/coreruleset/go-ftw/v2/config"
)

// overrideFor returns the forced result and the reason if the test is overridden.
// Forcing a failure takes precedence over forcing a pass.
func overrideFor(cfg *config.RunnerConfig, testCase *schema.Test) (TestResult, string, bool) {
	if reason, found := forcedReason(cfg.TestOverride.ForceFail, testCase); found {
		return ForceFail, reason, true
	}
	if reason, found := forcedReason(cfg.TestOverride.ForcePass, testCase); found {
		return ForcePass, reason, true
	}
	return Success, "", false
}

// forcedReason returns the reason of the override that matches the test. If multiple overrides
// match, the one with the alphabetically first pattern (and then reason) is used, so that the
// result does not depend on the iteration order of the map.
func forcedReason(overrides map[*config.FTWRegexp]string, testCase *schema.Test) (string, bool) {
	type match struct{ pattern, reason string }
	var matches []match
	for re, reason := range overrides {
		if re.MatchString(testCase.IdString()) {
			matches = append(matches, match{pattern: re.String(), reason: reason})
		}
	}
	if len(matches) == 0 {
		return "", false
	}
	slices.SortFunc(matches, func(a, b match) int {
		if c := strings.Compare(a.pattern, b.pattern); c != 0 {
			return c
		}
		return strings.Compare(a.reason, b.reason)
	})
	return matches[0].reason, true
}
