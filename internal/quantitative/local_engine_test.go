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
}
