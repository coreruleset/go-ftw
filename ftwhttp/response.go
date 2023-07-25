// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package ftwhttp

// GetFullResponse gives the full response as string, or nil if there was some error
func (r *Response) GetFullResponse() string {
	return string(r.RAW)
}
