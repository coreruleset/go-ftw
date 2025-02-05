// Copyright 2024 OWASP CRS Project
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

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/coreruleset/go-ftw/config"
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

	testInput := test.NewInput(&schema.Input{
		DestAddr: &originalHost,
	})
	cfg := &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Overrides: config.Overrides{
				DestAddr:                &overrideHost,
				OverrideEmptyHostHeader: func() *bool { b := true; return &b }(),
			},
		},
	}

	test.ApplyInputOverrides(cfg, testInput)

	s.Equal(overrideHost, *testInput.DestAddr, "`dest_addr` should have been overridden")

	s.NotNil(testInput.Headers, "Header map must exist after overriding `dest_addr`")

	hostHeaders := testInput.GetHeaders().GetAll("Host")
	s.Len(hostHeaders, 1)
	s.Equal(overrideHost, hostHeaders[0].Value, "Host header must be identical to `dest_addr` after overriding `dest_addr`")
}

func (s *inputOverrideTestSuite) TestSetHostFromHostHeaderOverride() {
	originalDestAddr := "original.com"
	overrideHostHeader, err := getOverrideConfigValue("Headers.Host")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		DestAddr: &originalDestAddr,
	})

	test.ApplyInputOverrides(s.cfg, testInput)

	hostHeaders := testInput.GetHeaders().GetAll("Host")
	s.Len(hostHeaders, 1)
	if hostHeaders[0].Value == overrideHostHeader {
		s.Equal(overrideHostHeader, hostHeaders[0].Value, "Host header override must take precence over OverrideEmptyHostHeader")
	} else {
		s.Equal(overrideHostHeader, hostHeaders[0].Value, "Host header must be identical to overridden `Host` header.")
	}
}

func (s *inputOverrideTestSuite) TestSetHeaderOverridingExistingOne() {
	originalHeaderValue := "original"
	overrideHeaderValue, err := getOverrideConfigValue("Headers.UniqueID")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		Headers: map[string]string{"unique_id": originalHeaderValue},
	})

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	test.ApplyInputOverrides(s.cfg, testInput)

	overriddenHeaders := testInput.GetHeaders().GetAll("unique_id")
	s.Len(overriddenHeaders, 1)
	s.Equal(overrideHeaderValue, overriddenHeaders[0].Value)
}

func (s *inputOverrideTestSuite) TestApplyInputOverrides() {
	originalHeaderValue := "original"
	overrideHeaderValue, err := getOverrideConfigValue("Headers.UniqueID")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		Headers: map[string]string{"unique_id": originalHeaderValue},
	})

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	test.ApplyInputOverrides(s.cfg, testInput)

	overriddenHeaders := testInput.GetHeaders().GetAll("unique_id")
	s.Len(overriddenHeaders, 1)
	s.Equal(overrideHeaderValue, overriddenHeaders[0].Value)
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideURI() {
	originalURI := "/original"
	overrideURI, err := getOverrideConfigValue("URI")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		URI: &originalURI,
	})

	test.ApplyInputOverrides(s.cfg, testInput)

	s.Equal(overrideURI, *testInput.URI, "`URI` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideVersion() {
	originalVersion := "HTTP/0.9"
	overrideVersion, err := getOverrideConfigValue("Version")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		Version: &originalVersion,
	})
	test.ApplyInputOverrides(s.cfg, testInput)

	s.Equal(overrideVersion, *testInput.Version, "`Version` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideMethod() {
	originalMethod := "POST"
	overrideMethod, err := getOverrideConfigValue("Method")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		Method: &originalMethod,
	})
	test.ApplyInputOverrides(s.cfg, testInput)

	s.Equal(overrideMethod, *testInput.Method, "`Method` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideData() {
	originalData := "data"
	overrideData, err := getOverrideConfigValue("Data")
	s.Require().NoError(err, "cannot get override value")

	testInput := test.NewInput(&schema.Input{
		Data: &originalData,
	})
	test.ApplyInputOverrides(s.cfg, testInput)

	s.Equal(overrideData, *testInput.Data, "`Data` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideStopMagic() {
	stopMagicBool, err := getOverrideConfigValue("StopMagic")
	s.Require().NoError(err, "cannot get override value")
	overrideStopMagic, err := strconv.ParseBool(stopMagicBool)
	s.Require().NoError(err, "Failed to parse `StopMagic` override value")
	testInput := test.NewInput(&schema.Input{
		StopMagic: func() *bool { b := false; return &b }(),
	})
	test.ApplyInputOverrides(s.cfg, testInput)

	// nolint
	s.Equal(overrideStopMagic, *testInput.StopMagic, "`StopMagic` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideAutocompleteHeaders() {
	autocompleteHeadersBool, err := getOverrideConfigValue("AutocompleteHeaders")
	s.NoError(err, "cannot get override value")
	overrideAutocompleteHeaders, err := strconv.ParseBool(autocompleteHeadersBool)
	s.NoError(err, "Failed to parse `AutocompleteHeaders` override value")
	testInput := test.NewInput(&schema.Input{
		AutocompleteHeaders: func() *bool { b := false; return &b }(),
	})
	test.ApplyInputOverrides(s.cfg, testInput)

	// nolint
	s.Equal(overrideAutocompleteHeaders, *testInput.AutocompleteHeaders, "`AutocompleteHeaders` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideNoAutocompleteHeaders() {
	testInput := test.NewInput(&schema.Input{
		AutocompleteHeaders: func() *bool { b := false; return &b }(),
	})
	s.Nil(s.cfg.TestOverride.Overrides.AutocompleteHeaders)
	//nolint:staticcheck
	s.Nil(s.cfg.TestOverride.Overrides.StopMagic)
	test.ApplyInputOverrides(s.cfg, testInput)

	s.False(*testInput.AutocompleteHeaders, "`AutocompleteHeaders` should not have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideNoStopMagic() {
	testInput := test.NewInput(&schema.Input{
		StopMagic: func() *bool { b := true; return &b }(),
	})
	s.Nil(s.cfg.TestOverride.Overrides.AutocompleteHeaders)
	//nolint:staticcheck
	s.Nil(s.cfg.TestOverride.Overrides.StopMagic)
	test.ApplyInputOverrides(s.cfg, testInput)

	//nolint:staticcheck
	s.True(*testInput.StopMagic, "`AutocompleteHeaders` should not have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideEncodedRequest() {
	originalEncodedRequest := "originalbase64"
	overrideEncodedRequest, err := getOverrideConfigValue("EncodedRequest")
	s.Require().NoError(err, "cannot get override value")
	testInput := test.NewInput(&schema.Input{
		EncodedRequest: originalEncodedRequest,
	})
	test.ApplyInputOverrides(s.cfg, testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideEncodedRequest, testInput.EncodedRequest, "`EncodedRequest` should have been overridden")
}
