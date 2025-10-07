// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"bufio"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/experimental/corpus"
)

// RawCorpus represents a corpus from a raw text file with one payload per line.
type RawCorpus struct {
	filePath string
	size     string
	year     string
	source   string
	language string
}

// NewRawCorpus returns a new raw corpus instance
func NewRawCorpus() corpus.Corpus {
	return &RawCorpus{
		filePath: "",
		size:     "unknown",
		year:     "unknown",
		source:   "file",
		language: "unknown",
	}
}

// URL returns the file path (used as URL for raw corpus)
func (c *RawCorpus) URL() string {
	return c.filePath
}

// WithURL sets the file path for the raw corpus
func (c *RawCorpus) WithURL(url string) corpus.Corpus {
	c.filePath = url
	return c
}

// FetchCorpusFile returns a File interface for the raw corpus file.
// Since raw files are local, no downloading is needed.
func (c *RawCorpus) FetchCorpusFile() corpus.File {
	if c.filePath == "" {
		log.Fatal().Msg("Raw corpus file path is empty")
	}

	// Check if file exists
	if _, err := os.Stat(c.filePath); os.IsNotExist(err) {
		log.Fatal().Err(err).Msgf("Raw corpus file does not exist: %s", c.filePath)
	}

	return NewFile().WithFileName(c.filePath)
}

// GetIterator returns an iterator for the raw corpus
func (c *RawCorpus) GetIterator(cache corpus.File) corpus.Iterator {
	filePath := cache.FilePath()
	if filePath == "" {
		log.Fatal().Msg("Raw corpus file path is empty")
	}

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Could not open the file %s", filePath)
	}

	scanner := bufio.NewScanner(file)
	return NewIterator(scanner)
}

// Size returns the size of the corpus
func (c *RawCorpus) Size() string {
	return c.size
}

// WithSize sets the size of the corpus (informational only for raw corpus)
func (c *RawCorpus) WithSize(size string) corpus.Corpus {
	c.size = size
	return c
}

// Year returns the year of the corpus
func (c *RawCorpus) Year() string {
	return c.year
}

// WithYear sets the year of the corpus (informational only for raw corpus)
func (c *RawCorpus) WithYear(year string) corpus.Corpus {
	c.year = year
	return c
}

// Source returns the source of the corpus
func (c *RawCorpus) Source() string {
	return c.source
}

// WithSource sets the source of the corpus (informational only for raw corpus)
func (c *RawCorpus) WithSource(source string) corpus.Corpus {
	c.source = source
	return c
}

// Language returns the language of the corpus
func (c *RawCorpus) Language() string {
	return c.language
}

// WithLanguage sets the language of the corpus (informational only for raw corpus)
func (c *RawCorpus) WithLanguage(lang string) corpus.Corpus {
	c.language = lang
	return c
}
