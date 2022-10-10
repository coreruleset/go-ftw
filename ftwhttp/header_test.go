// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ftwhttp

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

var headerWriteTests = []struct {
	h        Header
	expected string
}{
	{Header{}, ""},
	{
		Header{
			"Content-Type":   "text/html; charset=UTF-8",
			"Content-Length": "0",
		},
		"Content-Length: 0\r\nContent-Type: text/html; charset=UTF-8\r\n",
	},
	{
		Header{
			"Content-Length": "1",
		},
		"Content-Length: 1\r\n",
	},
	{
		Header{
			"Expires":          "-1",
			"Content-Length":   "0",
			"Content-Encoding": "gzip",
		},
		"Content-Encoding: gzip\r\nContent-Length: 0\r\nExpires: -1\r\n",
	},
	{
		Header{
			"Blank": "",
		},
		"Blank: \r\n",
	},
}

func TestHeaderWriteBytes(t *testing.T) {
	var buf bytes.Buffer
	for i, test := range headerWriteTests {
		_ = test.h.WriteBytes(&buf)
		assert.Equalf(t, test.expected, buf.String(), "#%d:\n got: %q\nwant: %q", i, buf.String(), test.expected)
		buf.Reset()
	}
}

func TestHeaderWrite(t *testing.T) {
	for _, test := range headerWriteTests {
		_ = test.h.Write(io.Discard)
	}
}

func TestHeaderSetGet(t *testing.T) {
	h := Header{
		"Custom": "Value",
	}
	h.Add("Other", "Value")
	value := h.Get("Other")
	assert.Equalf(t, "Value", value, "got: %s, want: %s\n", value, "Value")
}

func TestHeaderClone(t *testing.T) {
	h := Header{
		"Custom": "Value",
	}

	clone := h.Clone()

	value := clone.Get("Custom")

	assert.Equalf(t, "Value", value, "got: %s, want: %s\n", value, "Value")

}

var testHeader = Header{
	"Content-Length": "123",
	"Content-Type":   "text/plain",
	"Date":           "some date at some time Z",
	"Server":         "DefaultUserAgent",
}

var buf bytes.Buffer

func BenchmarkHeaderWrite(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = testHeader.Write(&buf)
	}
}
