// Copyright 2023 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"reflect"
)

// IsNotEmpty helper that returns true when a type is not empty
func IsNotEmpty(data interface{}) bool {
	switch t := data.(type) {
	case string:
		if data != "" {
			return true
		}
	case []byte:
		if len(t) > 0 {
			return true
		}
	case *string:
		if !reflect.ValueOf(data).IsNil() {
			return true
		}
	default:
		fmt.Printf("data has unknown type %s", t)
	}
	return false
}

// IsEmpty helper that returns true when a type is empty
func IsEmpty(data interface{}) bool {
	switch t := data.(type) {
	case string:
		if data == "" {
			return true
		}
	case []byte:
		if len(t) == 0 {
			return true
		}
	case *string:
		if reflect.ValueOf(data).IsNil() {
			return true
		}
	default:
		fmt.Printf("data has unknown type %s", t)
	}
	return false
}
