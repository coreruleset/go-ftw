// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-getter"
	"github.com/stretchr/testify/suite"
)

const (
	crsUrl         = "https://github.com/coreruleset/coreruleset/releases/download/v4.6.0/coreruleset-4.6.0-minimal.tar.gz"
	crsTestVersion = "4.6.0"
)

type localEngineTestSuite struct {
	suite.Suite
	dir    string
	engine *LocalEngine
}

func TestLocalEngineTestSuite(t *testing.T) {
	suite.Run(t, new(localEngineTestSuite))
}

func (s *localEngineTestSuite) SetupTest() {
	s.dir = path.Join(os.TempDir())
	s.Require().NoError(os.MkdirAll(s.dir, 0755))
	client := &getter.Client{
		Mode: getter.ClientModeAny,
		Src:  crsUrl,
		Dst:  s.dir,
	}

	err := client.Get()
	s.Require().NoError(err)
	s.engine = NewEngine(path.Join(s.dir, fmt.Sprintf("coreruleset-%s", crsTestVersion)), 1)
	s.Require().NotNil(s.engine)
}

func (s *localEngineTestSuite) TeardownTest() {
	err := os.RemoveAll(s.dir)
	s.Require().NoError(err)
}

// TestCRSCall For this test you will need to have the Core Rule Set repository cloned in the parent directory as the project.
func (s *localEngineTestSuite) TestCrsCall() {
	// simple payload, no matches
	status, matchedRules := s.engine.CRSCall("this is a test")
	s.Require().Equal(http.StatusOK, status)
	s.Require().Empty(matchedRules)

	// this payload will match a few rules
	status, matchedRules = s.engine.CRSCall("' OR 1 = 1")
	s.Require().Equal(http.StatusForbidden, status)
	s.Require().NotEmpty(matchedRules)

	expected := []int{942100 /* libinjection match */}
	var keys []int
	for k := range matchedRules {
		keys = append(keys, k)
	}
	s.Require().Equal(expected, keys)
}
