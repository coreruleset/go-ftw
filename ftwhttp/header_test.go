// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ftwhttp

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/suite"
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

type BadWriter struct {
	err error
}

func (bw BadWriter) Write(_ []byte) (n int, err error) {
	return 0, bw.err
}

type headerTestSuite struct {
	suite.Suite
}

func TestHeaderTestSuite(t *testing.T) {
	suite.Run(t, new(headerTestSuite))
}

func (s *headerTestSuite) TestHeaderWrite() {
	for _, test := range headerWriteTests {
		err := test.h.Write(io.Discard)
		s.Require().NoError(err)
		err = test.h.Write(BadWriter{err: errors.New("fake error")})
		if len(test.h) > 0 {
			s.EqualErrorf(err, "fake error", "Write: got %v, want %v", err, "fake error")
		} else {
			s.Require().NoErrorf(err, "Write: got %v", err)
		}
	}
}

func (s *headerTestSuite) TestHeaderWriteBytes() {
	for i, test := range headerWriteTests {
		var buf bytes.Buffer

		n, err := test.h.WriteBytes(&buf)
		w := buf.String()
		s.Lenf(w, n, "#%d: WriteBytes: got %d, want %d", i, n, len(w))
		s.Require().NoErrorf(err, "#%d: WriteBytes: got %v", i, err)
		s.Equalf(test.expected, w, "#%d: WriteBytes: got %q, want %q", i, w, test.expected)
		buf.Reset()
	}
}

func (s *headerTestSuite) TestHeaderWriteString() {
	sw := stringWriter{io.Discard}

	for i, test := range headerWriteTests {
		expected := test.h.Get("Content-Type")
		n, err := sw.WriteString(expected)
		s.Require().NoErrorf(err, "#%d: WriteString: %v", i, err)
		s.Equalf(len(expected), n, "#%d: WriteString: got %d, want %d", i, n, len(expected))
	}
}

func (s *headerTestSuite) TestHeaderSetGet() {
	h := Header{
		"Custom": "Value",
	}
	h.Add("Other", "Value")
	value := h.Get("Other")
	s.Equalf("Value", value, "got: %s, want: %s\n", value, "Value")
}

func (s *headerTestSuite) TestHeaderDel() {
	for i, test := range headerWriteTests {
		// we clone it because we are modifying the original
		headerCopy := test.h.Clone()
		expected := headerCopy.Get("Content-Type")
		if expected != "" {
			headerCopy.Del("Content-Type")
			value := headerCopy.Get("Content-Type")
			s.Equalf("", value, "#%d: got: %s, want: %s\n", i, value, "")
		}
	}
}

func (s *headerTestSuite) TestHeaderClone() {
	h := Header{
		"Custom": "Value",
	}

	clone := h.Clone()

	value := clone.Get("Custom")

	s.Equalf("Value", value, "got: %s, want: %s\n", value, "Value")

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
