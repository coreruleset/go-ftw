package runner

import (
	"bytes"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/ftwhttp"
	"github.com/coreruleset/go-ftw/test"
	"github.com/stretchr/testify/suite"
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
		return overrideConfigMap[name].(map[string]interface{})[key].(string), nil
	}
	return "", errors.New("cannot caller function name")
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
	s.NoError(err, "cannot parse template")
	buf := &bytes.Buffer{}
	err = configTmpl.Execute(buf, overrideConfigMap[name])
	s.NoError(err, "cannot execute template")
	s.cfg, err = config.NewConfigFromString(buf.String())
	s.NoError(err, "cannot get config from string")
	if s.logFilePath != "" {
		s.cfg.WithLogfile(s.logFilePath)
	}
}

func (s *inputOverrideTestSuite) TestSetHostFromDestAddr() {
	originalHost := "original.com"
	overrideHost, err := getOverrideConfigValue("DestAddr")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		DestAddr: &originalHost,
	}
	cfg := &config.FTWConfiguration{
		TestOverride: config.FTWTestOverride{
			Overrides: test.Overrides{
				DestAddr:                &overrideHost,
				OverrideEmptyHostHeader: true,
			},
		},
	}

	err = applyInputOverride(cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	s.Equal(overrideHost, *testInput.DestAddr, "`dest_addr` should have been overridden")

	s.NotNil(testInput.Headers, "Header map must exist after overriding `dest_addr`")

	hostHeader := testInput.Headers.Get("Host")
	s.NotEqual("", hostHeader, "Host header must be set after overriding `dest_addr`")
	s.Equal(overrideHost, hostHeader, "Host header must be identical to `dest_addr` after overrding `dest_addr`")
}

func (s *inputOverrideTestSuite) TestSetHostFromHostHeaderOverride() {
	originalDestAddr := "original.com"
	overrideHostHeader, err := getOverrideConfigValue("Headers.Host")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		DestAddr: &originalDestAddr,
	}

	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

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
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	overriddenHeader := testInput.Headers.Get("unique_id")
	s.NotEqual("", overriddenHeader, "unique_id header must be set after overriding it")
	s.Equal(overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrides() {
	originalHeaderValue := "original"
	overrideHeaderValue, err := getOverrideConfigValue("Headers.UniqueID")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		Headers: ftwhttp.Header{"unique_id": originalHeaderValue},
	}

	s.NotNil(testInput.Headers, "Header map must exist before overriding any header")

	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")

	overriddenHeader := testInput.Headers.Get("unique_id")
	s.NotEqual("", overriddenHeader, "unique_id header must be set after overriding it")
	s.Equal(overrideHeaderValue, overriddenHeader, "Host header must be identical to overridden `Host` header.")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideURI() {
	originalURI := "/original"
	overrideURI, err := getOverrideConfigValue("URI")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		URI: &originalURI,
	}

	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideURI, *testInput.URI, "`URI` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideVersion() {
	originalVersion := "HTTP/0.9"
	overrideVersion, err := getOverrideConfigValue("Version")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		Version: &originalVersion,
	}
	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideVersion, *testInput.Version, "`Version` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideMethod() {
	originalMethod := "POST"
	overrideMethod, err := getOverrideConfigValue("Method")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		Method: &originalMethod,
	}
	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideMethod, *testInput.Method, "`Method` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideData() {
	originalData := "data"
	overrideData, err := getOverrideConfigValue("Data")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		Data: &originalData,
	}
	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideData, *testInput.Data, "`Data` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideStopMagic() {
	stopMagicBool, err := getOverrideConfigValue("StopMagic")
	s.NoError(err, "cannot get override value")
	overrideStopMagic, err := strconv.ParseBool(stopMagicBool)
	s.NoError(err, "Failed to parse `StopMagic` override value")
	testInput := test.Input{
		StopMagic: false,
	}
	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideStopMagic, testInput.StopMagic, "`StopMagic` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideEncodedRequest() {
	originalEncodedRequest := "originalbase64"
	overrideEncodedRequest, err := getOverrideConfigValue("EncodedRequest")
	s.NoError(err, "cannot get override value")
	testInput := test.Input{
		EncodedRequest: originalEncodedRequest,
	}
	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideEncodedRequest, testInput.EncodedRequest, "`EncodedRequest` should have been overridden")
}

func (s *inputOverrideTestSuite) TestApplyInputOverrideRAWRequest() {
	originalRAWRequest := "original"
	overrideRAWRequest, err := getOverrideConfigValue("RawRequest")
	s.NoError(err, "cannot get override value")

	testInput := test.Input{
		RAWRequest: originalRAWRequest,
	}

	err = applyInputOverride(s.cfg.TestOverride, &testInput)
	s.NoError(err, "Failed to apply input overrides")
	s.Equal(overrideRAWRequest, testInput.RAWRequest, "`RAWRequest` should have been overridden")
}
