package ftwhttp

import (
	"bytes"
	"testing"

	header_names "github.com/coreruleset/go-ftw/ftwhttp/header_names"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

var headerWriteTests = []struct {
	h        *Header
	expected string
}{
	{
		NewHeader(), "",
	},
	{
		NewHeaderFromMap(map[string]string{
			header_names.ContentType:   "text/html; charset=UTF-8",
			header_names.ContentLength: "0",
		}),
		"Content-Length: 0\r\nContent-Type: text/html; charset=UTF-8\r\n",
	},
	{
		NewHeaderFromMap(map[string]string{
			header_names.ContentLength: "1",
		}),
		"Content-Length: 1\r\n",
	},
	{
		NewHeaderFromMap(map[string]string{
			"Expires":                  "-1",
			header_names.ContentLength: "0",
			"Content-Encoding":         "gzip",
		}),
		"Content-Encoding: gzip\r\nContent-Length: 0\r\nExpires: -1\r\n",
	},
	{
		NewHeaderFromMap(map[string]string{
			"Blank": "",
		}),
		"Blank: \r\n",
	},
}

type headerTestSuite struct {
	suite.Suite
}

func TestHeaderTestSuite(t *testing.T) {
	suite.Run(t, new(headerTestSuite))
}

func (s *headerTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func (s *headerTestSuite) TestNewHeader() {
	newHeader := NewHeader()
	s.NotNil(newHeader.canonicalNames)
	s.Empty(newHeader.canonicalNames)
	s.NotNil(newHeader.entries)
	s.Empty(newHeader.entries)
}

func (s *headerTestSuite) TestNewHeaderFromMap() {
	entries := map[string]string{
		"Header-Two": "value-2",
		"Header-One": "value-1",
		"header-two": "something else",
	}
	newHeader := NewHeaderFromMap(entries)
	s.Len(newHeader.canonicalNames, 2)
	s.Len(newHeader.entries, 3)
	// Alphabetically sorted for consistency
	s.Equal("Header-One", newHeader.entries[0].Name)
	s.Equal("Header-Two", newHeader.entries[1].Name)
	s.Equal("header-two", newHeader.entries[2].Name)
}

func (s *headerTestSuite) TestWrite() {
	for _, test := range headerWriteTests {
		buf := &bytes.Buffer{}
		err := test.h.Write(buf)
		s.Require().NoError(err)
		s.Equal(test.expected, buf.String())
	}
}

func (s *headerTestSuite) TestAdd() {
	h := NewHeader()
	h.Add("CustOm", "Value")
	h.Add("OtheR", "Value")
	h.Add("mIXedCa-se", "mIX-ed")
	h.Add("MixEDcA-SE", "mIX-ed")

	s.Len(h.entries, 4)
	s.Equal("CustOm", h.entries[0].Name)
	s.Equal("Value", h.entries[0].Value)
	s.Equal("OtheR", h.entries[1].Name)
	s.Equal("Value", h.entries[1].Value)
	s.Equal("mIXedCa-se", h.entries[2].Name)
	s.Equal("mIX-ed", h.entries[2].Value)
	s.Equal("MixEDcA-SE", h.entries[3].Name)
	s.Equal("mIX-ed", h.entries[3].Value)

	s.Contains(h.canonicalNames, "Custom")
	s.Equal(h.canonicalNames["Custom"], uint(1))
	s.Contains(h.canonicalNames, "Other")
	s.Equal(h.canonicalNames["Other"], uint(1))
	s.Contains(h.canonicalNames, "Mixedca-Se")
	s.Equal(h.canonicalNames["Mixedca-Se"], uint(2))
}

func (s *headerTestSuite) TestSet() {
	h := NewHeader()
	h.Add("one", "one")
	h.Add("two", "two")
	h.Add("One", "one-one")
	h.Add("TWo", "two-two")
	s.Len(h.entries, 4)

	h.Set("new", "new")
	s.Len(h.entries, 5)

	h.Set("onE", "new-one")
	s.Len(h.entries, 4)
	s.Equal("two", h.entries[0].Name)
	s.Equal("TWo", h.entries[1].Name)
	s.Equal("new", h.entries[2].Name)
	s.Equal("onE", h.entries[3].Name)
}

func (s *headerTestSuite) TestHasAny() {
	h := NewHeader()
	s.False(h.HasAny("Homer"))

	h.Add("Homer", "Simpson")
	s.True(h.HasAny("Homer"))
	s.True(h.HasAny("hoMeR"))

	h.Add("homEr", "loves doughnuts")
	s.True(h.HasAny("Homer"))
	s.True(h.HasAny("hoMeR"))
}

func (s *headerTestSuite) TestHasAnyValue() {
	h := NewHeader()
	s.False(h.HasAnyValue("homer", "simpson"))

	h.Add("Homer", "Simpson")
	s.True(h.HasAnyValue("Homer", "Simpson"))
	s.True(h.HasAnyValue("hoMeR", "sImPsOn"))
	s.False(h.HasAnyValue("homer", "doughnuts"))

	h.Add("homEr", "loves doughnuts")
	s.True(h.HasAnyValue("Homer", "Simpson"))
	s.True(h.HasAnyValue("hoMeR", "sImPsOn"))
	s.True(h.HasAnyValue("hoMeR", "loves doughnuts"))
	s.True(h.HasAnyValue("hoMeR", "LOVES DOUGHNUTS"))
	s.False(h.HasAnyValue("homer", "loves"))
	s.False(h.HasAnyValue("homer", "doughnuts"))
}

func (s *headerTestSuite) TestHasAnyValueContaining() {
	h := NewHeader()
	s.False(h.HasAnyValueContaining("homer", "simpson"))

	h.Add("Homer", "Simpson")
	s.True(h.HasAnyValueContaining("Homer", "Simpson"))
	s.True(h.HasAnyValueContaining("hoMeR", "sImPs"))
	s.False(h.HasAnyValueContaining("homer", "doughnuts"))

	h.Add("homEr", "loves doughnuts")
	s.True(h.HasAnyValueContaining("Homer", "Simpson"))
	s.True(h.HasAnyValueContaining("hoMeR", "sImPs"))
	s.True(h.HasAnyValueContaining("hoMeR", "loves doughnut"))
	s.True(h.HasAnyValueContaining("hoMeR", "OVES DOUGHNUTS"))
	s.True(h.HasAnyValueContaining("homer", "loves"))
	s.True(h.HasAnyValueContaining("homer", "doughnuts"))
}

func (s *headerTestSuite) TestGetAll() {
	h := NewHeader()
	s.Empty(h.GetAll("homer"))

	h.Add("Homer", "Simpson")
	s.Len(h.GetAll("Homer"), 1)
	s.Len(h.GetAll("hoMeR"), 1)
	s.Len(h.GetAll("homer"), 1)
	s.Empty(h.GetAll("Bart"))
}

func (s *headerTestSuite) TestClone() {
	h := NewHeader()
	h.Add("Homer", "Simpson")
	h.Add("Bart", "SimPson")
	h.Add("barT", "simpsoN")

	clone := h.Clone()
	s.Len(clone.canonicalNames, 2)
	s.Len(clone.entries, 3)
	s.Equal("Homer", clone.entries[0].Name)
	s.Equal("Bart", clone.entries[1].Name)
	s.Equal("barT", clone.entries[2].Name)
	s.Equal("Simpson", clone.entries[0].Value)
	s.Equal("SimPson", clone.entries[1].Value)
	s.Equal("simpsoN", clone.entries[2].Value)
}

func (s *headerTestSuite) TestCloneEmptyHeader() {
	h := NewHeader()
	clone := h.Clone()
	s.Empty(clone.canonicalNames)
	s.Empty(clone.entries)
}

func (s *headerTestSuite) TestCloneNilHeader() {
	var h Header
	clone := h.Clone()
	s.Empty(clone.canonicalNames)
	s.Empty(clone.entries)
}

func BenchmarkHeaderWrite(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	header := NewHeaderFromMap(map[string]string{
		"Host":                     "coreruleset.org",
		header_names.ContentLength: "123",
		header_names.ContentType:   "text/plain",
		"Date":                     "some date at some time Z",
		"Server":                   "DefaultUserAgent",
	})
	buf := &bytes.Buffer{}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = header.Write(buf)
	}
}
