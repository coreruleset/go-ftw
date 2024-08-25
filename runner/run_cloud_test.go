// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"text/template"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/test"
)

type runCloudTestSuite struct {
	suite.Suite
	cfg          *config.FTWConfiguration
	ftwTests     []*test.FTWTest
	out          *output.Output
	ts           *httptest.Server
	dest         *ftwhttp.Destination
	tempFileName string
}

func TestRunCloudTestSuite(t *testing.T) {
	suite.Run(t, new(runCloudTestSuite))
}

func (s *runCloudTestSuite) SetupTest() {
	s.newTestCloudServer()
	s.out = output.NewOutput("normal", os.Stdout)
}

func (s *runCloudTestSuite) TearDownTest() {
	s.ts.Close()
	if s.tempFileName != "" {
		err := os.Remove(s.tempFileName)
		s.Require().NoError(err, "cannot remove test file")
		s.tempFileName = ""
	}
}

func (s *runCloudTestSuite) BeforeTest(_ string, name string) {
	var err error

	// if we have a destination for this test, use it
	// else use the default destination
	if s.dest == nil {
		s.dest, err = ftwhttp.DestinationFromString(destinationMap[name])
		s.Require().NoError(err)
	}

	log.Info().Msgf("Using port %d and addr '%s'", s.dest.Port, s.dest.DestAddr)

	// set up variables for template
	vars := map[string]interface{}{
		"TestPort": s.dest.Port,
		"TestAddr": s.dest.DestAddr,
	}

	s.cfg = config.NewCloudConfig()
	// get tests template from file
	tmpl, err := template.ParseFiles(fmt.Sprintf("testdata/%s.yaml", name))
	s.Require().NoError(err)
	// create a temporary file to hold the test
	testdataDir, err := os.MkdirTemp(s.Suite.T().TempDir(), "testdata")
	s.Require().NoError(err)
	testFileContents, err := os.CreateTemp(testdataDir, "mock-test-*.yaml")
	s.Require().NoError(err, "cannot create temporary file")
	err = tmpl.Execute(testFileContents, vars)
	s.Require().NoError(err, "cannot execute template")
	err = testFileContents.Close()
	s.Require().NoError(err)
	// get tests from file
	s.ftwTests, err = test.GetTestsFromFiles(testFileContents.Name())
	s.Require().NoError(err, "cannot get tests from file")
	// save the name of the temporary file so we can delete it later
	s.tempFileName = testFileContents.Name()
}

// Error checking omitted for brevity
func (s *runCloudTestSuite) newTestCloudServer() {
	var err error

	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusCode := http.StatusOK
		if r.URL.Path != "/" {
			statusCode, err = strconv.Atoi(r.URL.Path[1:])
			if err != nil {
				statusCode = http.StatusBadRequest
			}
			log.Debug().Msgf("Mock cloud server returning status code: %d", statusCode)
		}
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte("Hello, client"))
	}))

	s.dest, err = ftwhttp.DestinationFromString((s.ts).URL)
	s.Require().NoError(err, "cannot get destination from string")
}

func (s *runCloudTestSuite) TestCloudRun() {
	s.Run("don't show time and execute all", func() {
		res, err := Run(s.cfg, s.ftwTests, RunnerConfig{
			ShowTime: true,
			Output:   output.Quiet,
		}, s.out)
		s.Require().NoError(err)
		s.Equalf(res.Stats.TotalFailed(), 0, "Oops, %d tests failed to run!", res.Stats.TotalFailed())
	})
}
