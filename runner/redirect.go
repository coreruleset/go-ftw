// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

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

	// Check if status code is a redirect (3xx)
	statusCode := response.Parsed.StatusCode
	if statusCode < 300 || statusCode >= 400 {
		return nil, fmt.Errorf("previous response status code %d is not a redirect (3xx)", statusCode)
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

	// If the URL is relative (no scheme/host), use the base URL from the original request
	if !locationURL.IsAbs() {
		result.Protocol = baseInput.GetProtocol()
		result.Host = baseInput.GetDestAddr()
		result.Port = baseInput.GetPort()

		// Handle relative URIs
		if strings.HasPrefix(location, "/") {
			result.URI = location
		} else {
			// Relative to current path - merge with base URI
			baseURI := baseInput.GetURI()
			lastSlash := strings.LastIndex(baseURI, "/")
			if lastSlash >= 0 {
				result.URI = baseURI[:lastSlash+1] + location
			} else {
				result.URI = "/" + location
			}
		}
	} else {
		// Absolute URL - extract all components
		result.Protocol = locationURL.Scheme
		result.Host = locationURL.Hostname()

		// Extract port
		portStr := locationURL.Port()
		if portStr != "" {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port in Location header: %s", portStr)
			}
			result.Port = port
		} else {
			// Use default port based on scheme
			if result.Protocol == "https" {
				result.Port = 443
			} else {
				result.Port = 80
			}
		}

		// Construct URI (path + query + fragment)
		result.URI = locationURL.RequestURI()
	}

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

	// Update Host header to match the new destination
	headers := input.GetHeaders()
	headers.Set("Host", redirect.Host)

	log.Debug().Msgf("Applied redirect to input: %s://%s:%d%s",
		redirect.Protocol, redirect.Host, redirect.Port, redirect.URI)
}
