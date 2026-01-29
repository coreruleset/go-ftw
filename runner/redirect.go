// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/coreruleset/go-ftw/v2/ftwhttp"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/rs/zerolog/log"
)

// RedirectLocation represents a parsed redirect location
type RedirectLocation struct {
	Protocol string
	Host     string
	Port     int
	URI      string
}

// extractRedirectLocation parses the Location header from a redirect response
// and returns the parsed components (protocol, host, port, URI).
// It handles both absolute and relative URLs.
func extractRedirectLocation(response *ftwhttp.Response, baseInput *test.Input) (*RedirectLocation, error) {
	if response == nil {
		return nil, fmt.Errorf("no previous response available for redirect")
	}

	// Check if status code is a redirect
	statusCode := response.Parsed.StatusCode
	switch statusCode {
	case 300, 301, 302, 303, 307, 308:
		// valid redirect status codes
	default:
		return nil, fmt.Errorf("previous response status code %d is not a redirect", statusCode)
	}

	// Get Location header
	location := response.Parsed.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("previous response is a redirect but has no Location header")
	}

	log.Debug().Msgf("Following redirect to: %s", location)

	// Parse the location URL
	locationURL, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Location header '%s': %w", location, err)
	}

	result := &RedirectLocation{}

	// Build base URL from the previous request for resolving relative redirects
	baseURL := &url.URL{
		Scheme: baseInput.GetProtocol(),
		Host:   baseInput.GetDestAddr(),
		Path:   baseInput.GetURI(),
	}
	
	// Add port to host if it's not a default port
	port := baseInput.GetPort()
	isDefaultPort := (baseURL.Scheme == "https" && port == 443) ||
		(baseURL.Scheme == "http" && port == 80)
	if !isDefaultPort {
		baseURL.Host = fmt.Sprintf("%s:%d", baseURL.Host, port)
	}

	// Resolve the location URL against the base URL
	resolvedURL := baseURL.ResolveReference(locationURL)

	// Extract components from resolved URL
	result.Protocol = resolvedURL.Scheme
	result.Host = resolvedURL.Hostname()

	// Extract port
	portStr := resolvedURL.Port()
	if portStr != "" {
		parsedPort, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in Location header: %s", portStr)
		}
		result.Port = parsedPort
	} else {
		// Use default port based on scheme
		if result.Protocol == "https" {
			result.Port = 443
		} else {
			result.Port = 80
		}
	}

	// Construct URI (path + query); fragments are not included in RequestURI
	result.URI = resolvedURL.RequestURI()

	log.Debug().Msgf("Parsed redirect: protocol=%s, host=%s, port=%d, uri=%s",
		result.Protocol, result.Host, result.Port, result.URI)

	return result, nil
}

// applyRedirectToInput modifies the test input to follow a redirect
func applyRedirectToInput(input *test.Input, redirect *RedirectLocation) {
	// Override destination with redirect location
	input.Protocol = &redirect.Protocol
	input.DestAddr = &redirect.Host
	input.Port = &redirect.Port
	input.URI = &redirect.URI

	// Update Host header to match the new destination, including non-default ports
	headers := input.GetHeaders()

	hostHeader := redirect.Host
	if redirect.Port != 0 {
		isDefaultPort := (redirect.Protocol == "https" && redirect.Port == 443) ||
			(redirect.Protocol == "http" && redirect.Port == 80)
		if !isDefaultPort {
			hostHeader = fmt.Sprintf("%s:%d", redirect.Host, redirect.Port)
		}
	}

	headers.Set("Host", hostHeader)

	log.Debug().Msgf("Applied redirect to input: %s://%s:%d%s",
		redirect.Protocol, redirect.Host, redirect.Port, redirect.URI)
}
