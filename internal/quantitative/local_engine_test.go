// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-getter/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

const (
	crsTestVersion = "4.6.0"
)

var crsUrl = fmt.Sprintf(
	"https://github.com/coreruleset/coreruleset/releases/download/v%s/coreruleset-%s-minimal.tar.gz",
	crsTestVersion,
	crsTestVersion)

type localEngineTestSuite struct {
	suite.Suite
	dir    string
	engine LocalEngine
}

func (s *localEngineTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestLocalEngineTestSuite(t *testing.T) {
	suite.Run(t, new(localEngineTestSuite))
}

func (s *localEngineTestSuite) SetupTest() {
	s.dir = path.Join(os.TempDir())
	s.Require().NoError(os.MkdirAll(s.dir, 0755))
	request := &getter.Request{
		Src:     crsUrl,
		Dst:     s.dir,
		GetMode: getter.ModeAny,
	}
	client := &getter.Client{
		Getters: []getter.Getter{
			new(getter.HttpGetter),
		},
	}

	_, err := client.Get(context.Background(), request)
	s.Require().NoError(err)
	s.engine = &localEngine{}
	s.engine = s.engine.Create(path.Join(s.dir, fmt.Sprintf("coreruleset-%s", crsTestVersion)), 1)
	s.Require().NotNil(s.engine)
}

func (s *localEngineTestSuite) TeardownTest() {
	err := os.RemoveAll(s.dir)
	s.Require().NoError(err)
}

// TestCRSCall For this test you will need to have the Core Rule Set repository cloned in the parent directory as the project.
func (s *localEngineTestSuite) TestCrsCall() {
	s.Require().NotNil(s.engine)

	// simple payload, no matches
	matchedRules := s.engine.CrsCall("this is a test")
	s.Require().Empty(matchedRules)

	// this payload will match a few rules
	matchedRules = s.engine.CrsCall("' OR 1 = 1")
	s.Require().NotEmpty(matchedRules)

	expected := []int{942100 /* libinjection match */}
	var keys []int
	for k := range matchedRules {
		keys = append(keys, k)
	}
	s.Require().Equal(expected, keys)
	s.Require().Equal(1, matchedRules[942100].ParanoiaLevel)
}

func (s *localEngineTestSuite) TestExtractParanoiaLevel() {
	tests := []struct {
		name       string
		rawRule    string
		expectedPL int
	}{
		{
			name: "PL1",
			rawRule: `SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:1, phase:1,\
					tag:'paranoia-level/1', deny, severity:'CRITICAL'"`,
			expectedPL: 1,
		},
		{
			name:       "PL2",
			rawRule:    `SecRule ARGS "@rx <script" "id:941200, tag:'paranoia-level/2', tag:'another-tag'"`,
			expectedPL: 2,
		},
		{
			name:       "PL3",
			rawRule:    `SecRule ARGS "@rx dangerous" "id:941300, tag:'paranoia-level/3'"`,
			expectedPL: 3,
		},
		{
			name:       "PL4",
			rawRule:    `SecRule ARGS "@rx verystrict" "id:941400, tag:'paranoia-level/4'"`,
			expectedPL: 4,
		},
		{
			name:       "multi-digits PL",
			rawRule:    `SecRule ARGS "@rx hello" "id:911, tag:'paranoia-level/999'"`,
			expectedPL: 999,
		},
		{
			name:       "no paranoia level tag",
			rawRule:    `SecRule ARGS "@rx test" "id:999999, tag:'OWASP_CRS'"`,
			expectedPL: 0,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			s.Require().Equal(tt.expectedPL, extractParanoiaLevel(tt.rawRule))
		})
	}
}

// TestCrsCallPlacement checks that the payload reaches targets other than ARGS when requested.
func (s *localEngineTestSuite) TestCrsCallPlacement() {
	crs := path.Join(s.dir, fmt.Sprintf("coreruleset-%s", crsTestVersion))
	engineFor := func(placement string) LocalEngine {
		p, err := ParsePlacement(placement)
		s.Require().NoError(err)
		e := &localEngine{placement: p}
		return e.Create(crs, 1)
	}

	// 920440 (restricted file extension) only looks at REQUEST_BASENAME: invisible from ARGS.
	s.Require().Empty(engineFor("args").CrsCall("index.bak"))
	s.Require().Contains(engineFor("path").CrsCall("index.bak"), 920440)

	// 942100 (libinjection) inspects REQUEST_HEADERS:Referer.
	s.Require().Contains(engineFor("header:Referer").CrsCall("' OR 1 = 1"), 942100)
}
