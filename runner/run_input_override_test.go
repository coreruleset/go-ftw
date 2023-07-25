// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/test"
)

type inputOverrideTestSuite struct {
	suite.Suite
	cfg         *config.FTWConfiguration
	logFilePath string
}

var configTemplate = `
---
testoverride:
  input:
    {{ with .StopMagic }}stop_magic: {{ . }}{{ end }}
    {{ with .AutocompleteHeaders }}autocomplete_headers: {{ . }}{{ end }}
    {{ with .BrokenConfig }}this_does_not_exist: "test"{{ end }}
    {{ with .Port }}port: {{ . }}{{ end }}
    {{ with .DestAddr }}dest_addr: {{ . }}{{ end }}
    {{ with .Version }}version: {{ . }}{{ end }}
    {{ with .URI }}uri: {{ . }}{{ end }}
    {{ with .Method }}method: {{ . }}{{ end }}
    {{ with .Protocol }}protocol: {{ . }}{{ end }}
    {{ with .Data }}data: {{ . }}{{ end }}
    {{ with .EncodedRequest }}encoded_request: {{ . }}{{ end }}
    {{ with .RawRequest }}raw_request: {{ . }}{{ end }}
    {{ with .Headers }}
    headers:
      {{ with .Host }}Host: {{ . }}{{ end }}
      {{ with .UniqueID }}unique_id: {{ . }}{{ end }}
    {{ end }}
    {{ with .OverrideEmptyHostHeader }}override_empty_host_header: {{ . }}{{ end }}
`

var overrideConfigMap = map[string]interface{}{
	"TestSetHostFromDestAddr": map[string]interface{}{
		"DestAddr": "address.org",
		"Port":     80,
	},
	"TestSetHostFromHostHeaderOverride": map[string]interface{}{
		"DestAddr": "wrong.org",
		"Headers": map[string]string{
			"Host": "override.com",
		},
		"OverrideEmptyHostHeader": true,
	},
	"TestSetHeaderOverridingExistingOne": map[string]interface{}{
		"Headers": map[string]string{
			"Host":     "address.org",
			"UniqueID": "override",
		},
	},
	"TestApplyInputOverrides": map[string]interface{}{
		"Headers": map[string]string{
			"Host":     "address.org",
			"UniqueID": "override",
		},
	},
	"TestApplyInputOverrideURI": map[string]interface{}{
		"URI": "/override",
	},
	"TestApplyInputOverrideVersion": map[string]interface{}{
		"Version": "HTTP/1.1",
	},
	"TestApplyInputOverrideMethod": map[string]interface{}{
		"Method": "MERGE",
	},
	"TestApplyInputOverrideData": map[string]interface{}{
		"Data": "override",
	},
	"TestApplyInputOverrideEncodedRequest": map[string]interface{}{
		"EncodedRequest": "overrideb64",
	},
	"TestApplyInputOverrideRAWRequest": map[string]interface{}{
		"RawRequest": "overrideraw",
	},
	"TestApplyInputOverrideProtocol": map[string]interface{}{
		"Protocol": "HTTP/1.1",
	},
	"TestApplyInputOverrideStopMagic": map[string]interface{}{
		"StopMagic": "true",
	},
	"TestApplyInputOverrideAutocompleteHeaders": map[string]interface{}{
		"AutocompleteHeaders": "true",
	},
}

// getOverrideConfigValue is useful to not repeat the text in the test itself
func getOverrideConfigValue(key string) (string, error) {
	pc, _, _, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		caller := strings.Split(details.Name(), ".")
		name := caller[len(caller)-1]
		if overrideConfigMap[name] == nil {
			return "", errors.New("cannot get override config value: be sure the caller is a test function, and the key is correct")
		}
		if strings.Contains(key, ".") {
			keyParts := strings.Split(key, ".")
			return overrideConfigMap[name].(map[string]interface{})[keyParts[0]].(map[string]string)[keyParts[1]], nil
		}
		value, ok := overrideConfigMap[name].(map[string]interface{})[key]
		if !ok {
			return "", fmt.Errorf("Key '%s' not found four test '%s'", key, name)
		}

		return value.(string), nil
	}
	return "", errors.New("failed to determine calling function")
}

func TestInputOverrideTestSuite(t *testing.T) {
	suite.Run(t, new(inputOverrideTestSuite))
}

func (s *inputOverrideTestSuite) SetupTest() {
}

func (s *inputOverrideTestSuite) BeforeTest(_ string, name string) {
	var err error

	// set up configuration from template
	tmpl := template.New("input-override").Funcs(sprig.TxtFuncMap())
	configTmpl, err := tmpl.Parse(configTemplate)
	s.Require().NoError(err, "cannot parse template")
	buf := &bytes.Buffer{}
	err = configTmpl.Execute(buf, overrideConfigMap[name])
	s.Require().NoError(err, "cannot execute template")
	s.cfg, err = config.NewConfigFromString(buf.String())
	s.Require().NoError(err, "cannot get config from string")
	if s.logFilePath != "" {
		s.cfg.WithLogfile(s.logFilePath)
	}
}

func (s *inputOverrideTestSuite) TestSetHostFromDestAddr() {
	originalHost := "original.com"
	overrideHost, err := getOverrideConfigValue("DestAddr")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		DestAddr: &originalHost,
	}
	cfg := &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Overrides: test.Overrides{
				DestAddr:                &overrideHost,
				OverrideEmptyHostHeader: func() *bool { b := true; return &b }(),
			},
		},
	}

	test.ApplyInputOverrides(&cfg.TestOverride.Overrides, &testInput)

	s.Equal(overrideHost, *testInput.DestAddr, "`dest_addr` should have been overridden")

	s.NotNil(testInput.Headers, "Header map must exist after overriding `dest_addr`")

	hostHeader := testInput.Headers.Get("Host")
	s.NotEqual("", hostHeader, "Host header must be set after overriding `dest_addr`")
	s.Equal(overrideHost, hostHeader, "Host header must be identical to `dest_addr` after overrding `dest_addr`")
}

func (s *inputOverrideTestSuite) TestSetHostFromHostHeaderOverride() {
	originalDestAddr := "original.com"
	overrideHostHeader, err := getOverrideConfigValue("Headers.Host")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		DestAddr: &originalDestAddr,
	}

	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	hostHeader := testInput.Headers.Get("Host")
	s.NotEqual("", hostHeader, "Host header must be set after overriding the `Host` header")
	if hostHeader == overrideHostHeader {
		s.Equal(overrideHostHeader, hostHeader, "Host header override must take precence over OverrideEmptyHostHeader")
	} else {
		s.Equal(overrideHostHeader, hostHeader, "Host header must be identical to overridden `Host` header.")
	}
}

func (s *inputOverrideTestSuite) TestSetHeaderOverridingExistingOne() {
	originalHeaderValue := "original"
	overrideHeaderValue, err := getOverrideConfigValue("Headers.UniqueID")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	overriddenHeader := testInput.Headers.Get("unique_id")
	s.NotEqual("", overriddenHeader, "unique_id header must be set after overriding it")
	s.Equal(overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrides() {
	originalHeaderValue := "original"
	overrideHeaderValue, err := getOverrideConfigValue("Headers.UniqueID")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	overriddenHeader := testInput.Headers.Get("unique_id")
	s.NotEqual("", overriddenHeader, "unique_id header must be set after overriding it")
	s.Equal(overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideURI() {
	originalURI := "/original"
	overrideURI, err := getOverrideConfigValue("URI")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		URI: &originalURI,
	}

	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	s.Equal(overrideURI, *testInput.URI, "`URI` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideVersion() {
	originalVersion := "HTTP/0.9"
	overrideVersion, err := getOverrideConfigValue("Version")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		Version: &originalVersion,
	}
	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	s.Equal(overrideVersion, *testInput.Version, "`Version` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideMethod() {
	originalMethod := "POST"
	overrideMethod, err := getOverrideConfigValue("Method")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		Method: &originalMethod,
	}
	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	s.Equal(overrideMethod, *testInput.Method, "`Method` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideData() {
	originalData := "data"
	overrideData, err := getOverrideConfigValue("Data")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		Data: &originalData,
	}
	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	s.Equal(overrideData, *testInput.Data, "`Data` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideStopMagic() {
	stopMagicBool, err := getOverrideConfigValue("StopMagic")
	s.Require().NoError(err, "cannot get override value")
	overrideStopMagic, err := strconv.ParseBool(stopMagicBool)
	s.Require().NoError(err, "Failed to parse `StopMagic` override value")
	testInput := test.Input{
		StopMagic: func() *bool { b := false; return &b }(),
	}
	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	// nolint
	s.Equal(overrideStopMagic, *testInput.StopMagic, "`StopMagic` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideAutocompleteHeaders() {
	autocompleteHeadersBool, err := getOverrideConfigValue("AutocompleteHeaders")
	s.NoError(err, "cannot get override value")
	overrideAutocompleteHeaders, err := strconv.ParseBool(autocompleteHeadersBool)
	s.NoError(err, "Failed to parse `AutocompleteHeaders` override value")
	testInput := test.Input{
		AutocompleteHeaders: func() *bool { b := false; return &b }(),
	}
	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	// nolint
	s.Equal(overrideAutocompleteHeaders, *testInput.AutocompleteHeaders, "`AutocompleteHeaders` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideEncodedRequest() {
	originalEncodedRequest := "originalbase64"
	overrideEncodedRequest, err := getOverrideConfigValue("EncodedRequest")
	s.Require().NoError(err, "cannot get override value")
	testInput := test.Input{
		EncodedRequest: originalEncodedRequest,
	}
	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideEncodedRequest, testInput.EncodedRequest, "`EncodedRequest` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideRAWRequest() {
	originalRAWRequest := "original"
	overrideRAWRequest, err := getOverrideConfigValue("RawRequest")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.Input{
		RAWRequest: originalRAWRequest,
	}

	test.ApplyInputOverrides(&s.cfg.TestOverride.Overrides, &testInput)

	s.Equal(overrideRAWRequest, testInput.RAWRequest, "`RAWRequest` should have been overridden")
}
