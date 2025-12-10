// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/coreruleset/go-ftw/v2/cmd/internal"
	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/utils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

var testFileContentsTemplate = `---
meta:
  author: "go-ftw"
  description: "Test file for go-ftw"
rule_id: 1
tests:
  - # Standard GET request
    test_id: 1234
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: {{ .Port }}
          headers:
            User-Agent: "OWASP CRS test agent"
            Host: "localhost"
            Accept: "*/*"
          protocol: "http"
          uri: "/"
          version: "HTTP/1.1"
        output:
          status: 200
`

type runCmdTestSuite struct {
	suite.Suite
	tempDir        string
	cmd            *cobra.Command
	cmdContext     *internal.CommandContext
	testHTTPServer *httptest.Server
}

func (s *runCmdTestSuite) setupMockHTTPServer() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := new(bytes.Buffer)
		for key, value := range r.Header {
			_, err := fmt.Fprintf(resp, "%s=%s,", key, value)
			s.Require().NoError(err)
		}

		_, err := w.Write(resp.Bytes())
		s.Require().NoError(err)
	}))
	return server
}

func (s *runCmdTestSuite) SetupTest() {
	// This directory will be cleaned up automatically after the test completes
	s.tempDir = s.T().TempDir()

	s.testHTTPServer = s.setupMockHTTPServer()
	testUrl, err := url.Parse(s.testHTTPServer.URL)
	s.Require().NoError(err)
	port, err := strconv.Atoi(testUrl.Port())
	s.Require().NoError(err)
	vars := map[string]int{
		"Port": port,
	}
	testFileContents, err := os.CreateTemp(s.tempDir, "mock-test-*.yaml")
	s.Require().NoError(err)
	tmpl, err := template.New("mock-test").Parse(testFileContentsTemplate)
	s.Require().NoError(err)
	err = tmpl.Execute(testFileContents, vars)
	s.Require().NoError(err)
	err = testFileContents.Close()
	s.Require().NoError(err)

	s.cmdContext = internal.NewCommandContext()
	s.cmd = New(s.cmdContext)
}

func (s *runCmdTestSuite) TearDownTest() {
	s.testHTTPServer.Close()
}

func TestRunRunCmdTestSuite(t *testing.T) {
	suite.Run(t, new(runCmdTestSuite))
}

func (s *runCmdTestSuite) TestHTTPCommandInvalidAddress() {
	s.cmd.SetArgs([]string{"-d", s.tempDir, "--" + waitForHostFlag, "http://local host"})
	cmd, err := s.cmd.ExecuteContextC(context.Background())

	s.Equal("run", cmd.Name())
	s.Error(err)
	s.ErrorContains(err, "invalid character \" \" in host name")
}

func (s *runCmdTestSuite) TestHTTPConnectionSuccess() {
	s.cmdContext.CloudMode = true
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"--" + waitForHostFlag, s.testHTTPServer.URL})
	_, err := s.cmd.ExecuteContextC(context.Background())

	s.Require().NoError(err)
}

func (s *runCmdTestSuite) TestHTTPConnectionFail() {
	s.cmdContext.CloudMode = true
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"--" + waitForTimeoutFlag, "2s",
		"--" + waitForHostFlag, "http://not-exists-doomain.tld"})
	_, err := s.cmd.ExecuteContextC(context.Background())

	s.Equal(context.DeadlineExceeded, err)
}

func (s *runCmdTestSuite) TestHTTPRequestHeaderSuccess() {
	s.cmdContext.CloudMode = true
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"--" + waitForHostFlag, s.testHTTPServer.URL,
		"--" + waitForExpectBodyRegexFlag, `.*User-Agent=\[Go-http-client/1\.1\].*`,
	})
	_, err := s.cmd.ExecuteContextC(context.Background())

	s.Require().NoError(err)
}

func (s *runCmdTestSuite) TestFlags() {
	s.cmd.SetArgs([]string{
		"--" + excludeFlag, "123456",
		"--" + includeFlag, "789012",
		"--" + includeTagsFlag, "^a-tag.*$",
		"--" + dirFlag, "/foo/bar",
		"--" + globFlag, "*.yyy*l",
		"--" + outputFlag, "github",
		"--" + fileFlag, "out.out",
		"--" + logFileFlag, "/path/to/log.log",
		"--" + timeFlag,
		"--" + showFailuresOnlyFlag,
		"--" + connectTimeoutFlag, "4s",
		"--" + readTimeoutFlag, "5s",
		"--" + maxMarkerRetriesFlag, "6",
		"--" + maxMarkerLogLinesFlag, "7",
		"--" + skipTlsVerificationFlag,
		"--" + waitForHostFlag, "https://some-host.com",
		"--" + waitDelayFlag, "9s",
		"--" + waitForTimeoutFlag, "10s",
		"--" + waitForExpectStatusCodeFlag, "204",
		"--" + waitForExpectBodyRegexFlag, "^some-body$",
		"--" + waitForExpectBodyJsonFlag, `{"some": "attribute"}`,
		"--" + waitForExpectBodyXpathFlag, "count(//p)",
		"--" + waitForExpectHeaderFlag, "X-Some-Header",
		"--" + waitForConnectionTimeoutFlag, "11s",
		"--" + waitForNoRedirectFlag,
		"--" + rateLimitFlag, "12s",
		"--" + failFastFlag,
	})
	cmd, _ := s.cmd.ExecuteC()

	exclude, err := cmd.Flags().GetString(excludeFlag)
	s.NoError(err)
	include, err := cmd.Flags().GetString(includeFlag)
	s.NoError(err)
	includeTags, err := cmd.Flags().GetString(includeTagsFlag)
	s.NoError(err)
	dir, err := cmd.Flags().GetString(dirFlag)
	s.NoError(err)
	filenameGlob, err := cmd.Flags().GetString(globFlag)
	s.NoError(err)
	output, err := cmd.Flags().GetString(outputFlag)
	s.NoError(err)
	file, err := cmd.Flags().GetString(fileFlag)
	s.NoError(err)
	logFile, err := cmd.Flags().GetString(logFileFlag)
	s.NoError(err)
	_time, err := cmd.Flags().GetBool(timeFlag)
	s.NoError(err)
	showFailuresOnly, err := cmd.Flags().GetBool(showFailuresOnlyFlag)
	s.NoError(err)
	connectTimeout, err := cmd.Flags().GetDuration(connectTimeoutFlag)
	s.NoError(err)
	readTimeout, err := cmd.Flags().GetDuration(readTimeoutFlag)
	s.NoError(err)
	maxMarkerRetries, err := cmd.Flags().GetUint(maxMarkerRetriesFlag)
	s.NoError(err)
	maxMarkerLogLines, err := cmd.Flags().GetUint(maxMarkerLogLinesFlag)
	s.NoError(err)
	waitForInsecureSkipTlsVerify, err := cmd.Flags().GetBool(skipTlsVerificationFlag)
	s.NoError(err)
	waitForHost, err := cmd.Flags().GetString(waitForHostFlag)
	s.NoError(err)
	waitDelay, err := cmd.Flags().GetDuration(waitDelayFlag)
	s.NoError(err)
	waitForTimeout, err := cmd.Flags().GetDuration(waitForTimeoutFlag)
	s.NoError(err)
	waitForExpectStatusCode, err := cmd.Flags().GetInt(waitForExpectStatusCodeFlag)
	s.NoError(err)
	waitForExpectBodyRegex, err := cmd.Flags().GetString(waitForExpectBodyRegexFlag)
	s.NoError(err)
	waitForExpectBodyJson, err := cmd.Flags().GetString(waitForExpectBodyJsonFlag)
	s.NoError(err)
	waitForeExpectBodyXpath, err := cmd.Flags().GetString(waitForExpectBodyXpathFlag)
	s.NoError(err)
	waitForExpectHeader, err := cmd.Flags().GetString(waitForExpectHeaderFlag)
	s.NoError(err)
	waitForConnectionTimeout, err := cmd.Flags().GetDuration(waitForConnectionTimeoutFlag)
	s.NoError(err)
	waitForNoRedirect, err := cmd.Flags().GetBool(waitForNoRedirectFlag)
	s.NoError(err)
	rateLimit, err := cmd.Flags().GetDuration(rateLimitFlag)
	s.NoError(err)
	failFast, err := cmd.Flags().GetBool(failFastFlag)
	s.NoError(err)

	s.Equal("123456", exclude)
	s.Equal("789012", include)
	s.Equal("^a-tag.*$", includeTags)
	s.Equal("/foo/bar", dir)
	s.Equal("*.yyy*l", filenameGlob)
	s.Equal("github", output)
	s.Equal("out.out", file)
	s.Equal("/path/to/log.log", logFile)
	s.Equal(true, _time)
	s.Equal(true, showFailuresOnly)
	s.Equal(4*time.Second, connectTimeout)
	s.Equal(5*time.Second, readTimeout)
	s.Equal(uint(6), maxMarkerRetries)
	s.Equal(uint(7), maxMarkerLogLines)
	s.Equal("https://some-host.com", waitForHost)
	s.Equal(9*time.Second, waitDelay)
	s.Equal(10*time.Second, waitForTimeout)
	s.Equal(204, waitForExpectStatusCode)
	s.Equal("^some-body$", waitForExpectBodyRegex)
	s.Equal(`{"some": "attribute"}`, waitForExpectBodyJson)
	s.Equal("count(//p)", waitForeExpectBodyXpath)
	s.Equal("X-Some-Header", waitForExpectHeader)
	s.Equal(11*time.Second, waitForConnectionTimeout)
	s.Equal(true, waitForInsecureSkipTlsVerify)
	s.Equal(true, waitForNoRedirect)
	s.Equal(12*time.Second, rateLimit)
	s.Equal(true, failFast)
}

func (s *runCmdTestSuite) TestGlobalInclude() {
	configYaml := `---
include: '^9.*'
`
	configFile, err := utils.CreateTempFileWithContent(s.tempDir, configYaml, "global-config-*.yaml")
	s.Require().NoError(err)
	cfg, err := config.NewConfigFromFile(configFile)
	s.Require().NoError(err)

	s.cmdContext.Configuration = cfg
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
	})
	cmd, _ := s.cmd.ExecuteC()

	runnerConfig, err := buildRunnerConfig(cmd, s.cmdContext)
	s.Require().NoError(err)

	s.NotNil(runnerConfig.Include)
	s.Equal("^9.*", runnerConfig.Include.String())
}

func (s *runCmdTestSuite) TestGlobalIncludeOverriddenByCmdLineFlag() {
	configYaml := `---
include: '^9.*'
`
	configFile, err := utils.CreateTempFileWithContent(s.tempDir, configYaml, "global-config.yaml")
	s.Require().NoError(err)
	cfg, err := config.NewConfigFromFile(configFile)
	s.Require().NoError(err)

	s.cmdContext.Configuration = cfg
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"--include", "^1.*",
	})
	cmd, _ := s.cmd.ExecuteC()

	runnerConfig, err := buildRunnerConfig(cmd, s.cmdContext)
	s.Require().NoError(err)

	s.NotNil(runnerConfig.Include)
	s.Equal("^1.*", runnerConfig.Include.String())
}

func (s *runCmdTestSuite) TestGlobalExclude() {
	configYaml := `---
exclude: '^9.*'
`
	configFile, err := utils.CreateTempFileWithContent(s.tempDir, configYaml, "global-config.yaml")
	s.Require().NoError(err)
	cfg, err := config.NewConfigFromFile(configFile)
	s.Require().NoError(err)

	s.cmdContext.Configuration = cfg
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
	})
	cmd, _ := s.cmd.ExecuteC()

	runnerConfig, err := buildRunnerConfig(cmd, s.cmdContext)
	s.Require().NoError(err)

	s.NotNil(runnerConfig.Exclude)
	s.Equal("^9.*", runnerConfig.Exclude.String())
}

func (s *runCmdTestSuite) TestGlobalExcludeOverriddenByCmdLineFlag() {
	configYaml := `---
exclude: '^9.*'
`
	configFile, err := utils.CreateTempFileWithContent(s.tempDir, configYaml, "global-config.yaml")
	s.Require().NoError(err)
	cfg, err := config.NewConfigFromFile(configFile)
	s.Require().NoError(err)

	s.cmdContext.Configuration = cfg
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"--exclude", "^1.*",
	})
	cmd, _ := s.cmd.ExecuteC()

	runnerConfig, err := buildRunnerConfig(cmd, s.cmdContext)
	s.Require().NoError(err)

	s.NotNil(runnerConfig.Exclude)
	s.Equal("^1.*", runnerConfig.Exclude.String())
}

func (s *runCmdTestSuite) TestGlobalIncludeTags() {
	configYaml := `---
include_tags: '^springfield.*'
`
	configFile, err := utils.CreateTempFileWithContent(s.tempDir, configYaml, "global-config.yaml")
	s.Require().NoError(err)
	cfg, err := config.NewConfigFromFile(configFile)
	s.Require().NoError(err)

	s.cmdContext.Configuration = cfg
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
	})
	cmd, _ := s.cmd.ExecuteC()

	runnerConfig, err := buildRunnerConfig(cmd, s.cmdContext)
	s.Require().NoError(err)

	s.NotNil(runnerConfig.IncludeTags)
	s.Equal("^springfield.*", runnerConfig.IncludeTags.String())
}

func (s *runCmdTestSuite) TestGlobalIncludeTagsOverriddenByCmdLineFlag() {
	configYaml := `---
include_tags: '^springfield.*'
`
	configFile, err := utils.CreateTempFileWithContent(s.tempDir, configYaml, "global-config.yaml")
	s.Require().NoError(err)
	cfg, err := config.NewConfigFromFile(configFile)
	s.Require().NoError(err)

	s.cmdContext.Configuration = cfg
	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"--include-tags", "^powerplant.*",
	})
	cmd, _ := s.cmd.ExecuteC()

	runnerConfig, err := buildRunnerConfig(cmd, s.cmdContext)
	s.Require().NoError(err)

	s.NotNil(runnerConfig.IncludeTags)
	s.Equal("^powerplant.*", runnerConfig.IncludeTags.String())
}

func (s *runCmdTestSuite) TestFilenameGlobFlag() {
	baseFiles, err := filepath.Glob(fmt.Sprintf("%s/*.yaml", s.tempDir))
	s.Require().NoError(err)
	s.Len(baseFiles, 1)
	base, err := os.Open(baseFiles[0])
	s.Require().NoError(err)

	for _, name := range []string{
		"matching_file.yyyml",
		"matching_file.yyyxl",
		"matching_file.yyyl",
		"non_matching_file.yyl",
		"yyyml",
	} {
		target, err := os.OpenFile(path.Join(s.tempDir, name), os.O_CREATE|os.O_WRONLY, os.ModePerm)
		s.Require().NoError(err)
		_, err = base.Seek(0, 0)
		s.Require().NoError(err)
		_, err = io.Copy(target, base)
		s.Require().NoError(err)
		s.Require().NoError(target.Close())
	}
	s.Require().NoError(base.Close())
	s.Require().NoError(os.Remove(base.Name()))

	s.cmd.SetArgs([]string{
		"-d", s.tempDir,
		"-g", "*.yyy*l",
	})
	cmd, _ := s.cmd.ExecuteC()
	tests, err := loadTests(cmd)
	s.Require().NoError(err)
	s.Len(tests, 3)

	testFileNames := []string{}
	for _, test := range tests {
		testFileNames = append(testFileNames, filepath.Base(test.FileName))
	}
	s.Contains(testFileNames, "matching_file.yyyml")
	s.Contains(testFileNames, "matching_file.yyyxl")
	s.Contains(testFileNames, "matching_file.yyyl")
}
