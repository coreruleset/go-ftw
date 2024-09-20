package ftwhttp

import (
	"bytes"
	"github.com/stretchr/testify/suite"
	"strings"
	"testing"
)

type headerTestSuite struct {
	suite.Suite
}

func TestHeaderNewTestSuite(t *testing.T) {
	suite.Run(t, new(headerTestSuite))
}

func (s *headerTestSuite) TestHeaderAdd() {
	h := NewHeader(nil)

	key1 := "key1"
	h.Get(key1)

	h.Add(key1, []string{"Value1"})
	values := h.Get(key1)
	s.Lenf(values, 1, "got: %d, want: 1\n", len(values))
	s.Equalf([]string{"Value1"}, values[key1], "got: %s, want: %s\n", strings.Join(values[key1], ", "), `["Value1"]`)

	// Append value to the previous added under key1
	h.Add(key1, []string{"Value2"})
	values = h.Get(key1)
	s.Lenf(values, 1, "got: %d, want: 1\n", len(values))
	s.Equalf([]string{"Value1", "Value2"}, values[key1], "got: %s, want: %s\n", strings.Join(values[key1], ", "), `["Value1", "Value2"]`)

	// Add value under the key matching canonicalised key1
	key2 := "KEY1"
	h.Add(key2, []string{"Value3"})
	values = h.Get(key2)
	s.Lenf(values, 2, "got: %d, want: 2\n", len(values))
	s.Equalf([]string{"Value3"}, values[key2], "got: %s, want: %s\n", values[key2], `["Value3"]`)

	// The method is case-insensitive
	s.Lenf(h.Get("KEY1"), 2, "got: %d, want: 2\n", len(h.Get("key1")))
}

func (s *headerTestSuite) TestHeaderSet() {
	h := NewHeader(nil)

	key1 := "key1"
	h.Set(key1, []string{"Value1"})

	values := h.Get(key1)
	s.Lenf(values, 1, "got: %d, want: 1\n", len(values))
	s.Equalf([]string{"Value1"}, values[key1], "got: %s, want: %s\n", strings.Join(values[key1], ", "), `["Value1"]`)

	h.Set(key1, []string{"Value2"})

	values = h.Get(key1)
	s.Lenf(values, 1, "got: %d, want: 1\n", len(values))
	s.Equalf([]string{"Value2"}, values[key1], "got: %s, want: %s\n", strings.Join(values[key1], ", "), `["Value2"]`)
}

func (s *headerTestSuite) TestHeaderHasAny() {
	h := NewHeader(nil)
	key := "key"

	s.False(h.HasAny(key))

	h.Add(key, []string{"Value"})
	s.True(h.HasAny(key))
	s.True(h.HasAny("KEY"))
	s.False(h.HasAny("key1"))
}

func (s *headerTestSuite) TestHeaderHasAnyNonEmpty() {
	h := NewHeader(nil)
	key := "key"

	s.Empty(h.First(key))

	h.Add(key, []string{""})
	s.Empty(h.First(key))

	h.Add(key, []string{"Value", "Value2"})
	s.Equal(h.First("key"), "Value")
	s.Empty(h.First("key1"))
}

func (s *headerTestSuite) TestHeaderWrite() {
	var headerWriteTests = []struct {
		headers  map[string][]string
		expected string
	}{

		{
			headers:  map[string][]string{},
			expected: "",
		},
		{
			headers: map[string][]string{
				"Blank": {""},
			},
			expected: "Blank: \r\n",
		},
		{
			headers: map[string][]string{
				"Content-Length": {"1"},
			},
			expected: "Content-Length: 1\r\n",
		},
		{
			headers: map[string][]string{
				"Content-Length": {"1", "2"},
			},
			expected: "Content-Length: 1\r\nContent-Length: 2\r\n",
		},
		{
			headers: map[string][]string{
				"Content-Type":   {"text/html; charset=UTF-8"},
				"Content-Length": {"0"},
			},
			expected: "Content-Length: 0\r\nContent-Type: text/html; charset=UTF-8\r\n",
		},
		{
			headers: map[string][]string{
				"Expires":          {"-1"},
				"Content-Length":   {"0"},
				"Content-Encoding": {"gzip"},
			},
			expected: "Content-Encoding: gzip\r\nContent-Length: 0\r\nExpires: -1\r\n",
		},
		{
			headers: map[string][]string{
				"Content-Encoding": {"gzip"},
				"content-ENCoding": {"deflate"},
			},
			expected: "Content-Encoding: gzip\r\ncontent-ENCoding: deflate\r\n",
		},
		{
			headers: map[string][]string{
				"Content-Encoding": {"gzip", "zstd"},
				"Expires":          {"-1"},
				"content-ENCoding": {"deflate", "compress"},
			},
			expected: "Content-Encoding: gzip\r\nContent-Encoding: zstd\r\ncontent-ENCoding: deflate\r\ncontent-ENCoding: compress\r\nExpires: -1\r\n",
		},
	}

	for i, test := range headerWriteTests {
		var buf bytes.Buffer

		h := NewHeader(nil)
		for k, v := range test.headers {
			h.Add(k, v)
		}
		n, err := h.WriteBytes(&buf)
		w := buf.String()
		s.Lenf(w, n, "#%d: WriteBytes: got %d, want %d", i, n, len(w))
		s.Require().NoErrorf(err, "#%d: WriteBytes: got %v", i, err)
		s.Equalf(test.expected, w, "#%d: WriteBytes: got %q, want %q", i, w, test.expected)
		buf.Reset()
	}
}

func (s *headerTestSuite) TestHeaderClone() {
	key := "Custom"
	h := NewHeader(map[string][]string{
		key: {"Value"},
	})

	clone := h.Clone()

	values := clone.Get("Custom")
	s.Lenf(values, 1, "got: %d, want: 1\n", len(values))
	s.Equalf([]string{"Value"}, values[key], "got: %s, want: %s\n", strings.Join(values[key], ", "), `["Value"]`)
}

var bufNew bytes.Buffer

func BenchmarkHeaderNewWrite(b *testing.B) {
	b.ReportAllocs()
	testHeaderNew := NewHeader(map[string][]string{
		"Content-Length": {"123"},
		"Content-Type":   {"text/plain"},
		"Date":           {"some date at some time Z"},
		"Server":         {"DefaultUserAgent"},
	})
	for i := 0; i < b.N; i++ {
		bufNew.Reset()
		_, _ = testHeaderNew.WriteBytes(&bufNew)
	}
}
