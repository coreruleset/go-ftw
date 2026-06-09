// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"net/http"
	"testing"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/coreruleset/go-ftw/v2/ftwhttp"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type redirectTestSuite struct {
	suite.Suite
}

func (s *redirectTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestRedirectTestSuite(t *testing.T) {
	suite.Run(t, new(redirectTestSuite))
}

func (s *redirectTestSuite) TestExtractRedirectLocation_AbsoluteURL() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 302,
			Header: http.Header{
				"Location": []string{"https://newdomain.com:8443/newpath?query=value"},
			},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.NoError(err)
	s.NotNil(result)
	s.Equal("https", result.Protocol)
	s.Equal("newdomain.com", result.Host)
	s.Equal(8443, result.Port)
	s.Equal("/newpath?query=value", result.URI)
}

func (s *redirectTestSuite) TestExtractRedirectLocation_AbsoluteURLWithDefaultPort() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 301,
			Header: http.Header{
				"Location": []string{"https://newdomain.com/newpath"},
			},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.NoError(err)
	s.NotNil(result)
	s.Equal("https", result.Protocol)
	s.Equal("newdomain.com", result.Host)
	s.Equal(443, result.Port)
	s.Equal("/newpath", result.URI)
}

func (s *redirectTestSuite) TestExtractRedirectLocation_RelativeURLAbsolutePath() {
	protocol := "http"
	destAddr := "example.com"
	port := 8080
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 302,
			Header: http.Header{
				"Location": []string{"/newpath"},
			},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.NoError(err)
	s.NotNil(result)
	s.Equal("http", result.Protocol)
	s.Equal("example.com", result.Host)
	s.Equal(8080, result.Port)
	s.Equal("/newpath", result.URI)
}

func (s *redirectTestSuite) TestExtractRedirectLocation_RelativeURLRelativePath() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/path/to/resource"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 302,
			Header: http.Header{
				"Location": []string{"newresource"},
			},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.NoError(err)
	s.NotNil(result)
	s.Equal("http", result.Protocol)
	s.Equal("example.com", result.Host)
	s.Equal(80, result.Port)
	s.Equal("/path/to/newresource", result.URI)
}

func (s *redirectTestSuite) TestExtractRedirectLocation_NoResponse() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	result, err := extractRedirectLocation(nil, baseInput)
	s.Error(err)
	s.Nil(result)
	s.Contains(err.Error(), "no previous response available")
}

func (s *redirectTestSuite) TestExtractRedirectLocation_NotRedirectStatus() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Location": []string{"/newpath"},
			},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.Error(err)
	s.Nil(result)
	s.Contains(err.Error(), "not a redirect")
}

func (s *redirectTestSuite) TestExtractRedirectLocation_NoLocationHeader() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 302,
			Header:     http.Header{},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.Error(err)
	s.Nil(result)
	s.Contains(err.Error(), "no Location header")
}

func (s *redirectTestSuite) TestExtractRedirectLocation_HTTPToHTTPS() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	response := &ftwhttp.Response{
		Parsed: http.Response{
			StatusCode: 301,
			Header: http.Header{
				"Location": []string{"https://example.com/secure"},
			},
		},
	}

	result, err := extractRedirectLocation(response, baseInput)
	s.NoError(err)
	s.NotNil(result)
	s.Equal("https", result.Protocol)
	s.Equal("example.com", result.Host)
	s.Equal(443, result.Port)
	s.Equal("/secure", result.URI)
}

func (s *redirectTestSuite) TestApplyRedirectToInput() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	input := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	redirect := &RedirectLocation{
		Protocol: "https",
		Host:     "newdomain.com",
		Port:     8443,
		URI:      "/newpath",
	}

	applyRedirectToInput(input, redirect)

	s.Equal("https", input.GetProtocol())
	s.Equal("newdomain.com", input.GetDestAddr())
	s.Equal(8443, input.GetPort())
	s.Equal("/newpath", input.GetURI())

	// Check Host header was updated (should include port for non-default ports)
	headers := input.GetHeaders()
	hostHeaders := headers.GetAll("Host")
	s.Len(hostHeaders, 1)
	s.Equal("newdomain.com:8443", hostHeaders[0].Value)
}

func (s *redirectTestSuite) TestExtractRedirectLocation_Various3xxCodes() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	redirectCodes := []int{300, 301, 302, 303, 307, 308}

	for _, code := range redirectCodes {
		response := &ftwhttp.Response{
			Parsed: http.Response{
				StatusCode: code,
				Header: http.Header{
					"Location": []string{"/redirect"},
				},
			},
		}

		result, err := extractRedirectLocation(response, baseInput)
		s.NoError(err, "Failed for status code %d", code)
		s.NotNil(result, "Result is nil for status code %d", code)
		s.Equal("/redirect", result.URI)
	}
}

func (s *redirectTestSuite) TestExtractRedirectLocation_NonRedirect3xxCodes() {
	protocol := "http"
	destAddr := "example.com"
	port := 80
	uri := "/original"

	baseInput := test.NewInput(&schema.Input{
		Protocol: &protocol,
		DestAddr: &destAddr,
		Port:     &port,
		URI:      &uri,
	})

	// Test non-redirect 3xx codes that should be rejected
	nonRedirectCodes := []int{304, 305, 306}

	for _, code := range nonRedirectCodes {
		response := &ftwhttp.Response{
			Parsed: http.Response{
				StatusCode: code,
				Header: http.Header{
					"Location": []string{"/somewhere"},
				},
			},
		}

		result, err := extractRedirectLocation(response, baseInput)
		s.Error(err, "Should reject status code %d", code)
		s.Nil(result, "Result should be nil for status code %d", code)
		s.Contains(err.Error(), "not a redirect", "Error message should indicate it's not a redirect for code %d", code)
	}
}
