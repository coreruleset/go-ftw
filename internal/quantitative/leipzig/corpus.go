// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-getter/v2"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/go-ftw/experimental/corpus"
)

// LeipzigCorpus represents a corpus of text data
// Original files are available at https://wortschatz.uni-leipzig.de/en/download
const (
	defaultCorpusSite     = "https://downloads.wortschatz-leipzig.de/corpora"
	defaultCorpusLanguage = "eng"
	defaultCorpusSize     = "100K"
	defaultCorpusYear     = "2023"
	defaultCorpusSource   = "news"
	defaultCorpusExt      = "tar.gz"
	defaultCorpusType     = "sentences.txt"
)

// LeipzigCorpus is a corpus of text data.
// Implements the Corpus interface.
type LeipzigCorpus struct {
	// url_ is the URL of the corpus
	url_ string
	// lang is the language of the corpus
	lang string
	// corpusFile is the original file name that contains the corpus file
	corpusFile string
	// filename is the file name of the corpus
	filename string
	// size is the size of the corpus
	size string
	// source is the source of the corpus
	source string
	// year is the year of the corpus
	year string
}

func (c *LeipzigCorpus) regenerateFileNames() {
	size := strings.ToUpper(c.size)

	c.corpusFile = fmt.Sprintf("%s_%s_%s_%s.%s",
		c.lang, c.source, c.year, size,
		defaultCorpusExt)
	c.filename = fmt.Sprintf("%s_%s_%s_%s-%s",
		c.lang, c.source, c.year, size,
		defaultCorpusType)
}

// NewLeipzigCorpus returns a new Leipzig corpus
func NewLeipzigCorpus() corpus.Corpus {
	leipzig := &LeipzigCorpus{
		url_:       defaultCorpusSite,
		corpusFile: "",
		filename:   "",
		lang:       defaultCorpusLanguage,
		source:     defaultCorpusSource,
		year:       defaultCorpusYear,
		size:       defaultCorpusSize,
	}

	leipzig.regenerateFileNames()

	return leipzig
}

// Size returns the size of the corpus
func (c *LeipzigCorpus) Size() string {
	return c.size
}

// WithSize sets the size of the corpus
func (c *LeipzigCorpus) WithSize(size string) corpus.Corpus {
	c.size = size
	c.regenerateFileNames()
	return c
}

// Year returns the year of the corpus
func (c *LeipzigCorpus) Year() string {
	return c.year
}

// WithYear sets the year of the corpus
func (c *LeipzigCorpus) WithYear(year string) corpus.Corpus {
	c.year = year
	c.regenerateFileNames()
	return c
}

// URL returns the URL of the corpus
func (c *LeipzigCorpus) URL() string {
	return c.url_
}

// WithURL sets the URL of the corpus
// The URL corresponds to the base URI where the corpus is stored. Then the corpusFile will be added.
func (c *LeipzigCorpus) WithURL(url string) corpus.Corpus {
	c.url_ = url
	return c
}

// Source returns the source of the corpus
func (c *LeipzigCorpus) Source() string {
	return c.source
}

// WithSource sets the source of the corpus
func (c *LeipzigCorpus) WithSource(source string) corpus.Corpus {
	c.source = source
	c.regenerateFileNames()
	return c
}

// Language returns the language of the corpus
func (c *LeipzigCorpus) Language() string {
	return c.lang
}

// WithLanguage sets the language of the corpus
func (c *LeipzigCorpus) WithLanguage(lang string) corpus.Corpus {
	c.lang = lang
	c.regenerateFileNames()
	return c
}

// GetIterator returns an iterator for the corpus
func (c *LeipzigCorpus) GetIterator(cache corpus.File) corpus.Iterator {
	// open cache file
	cached := cache.FilePath()
	if cached == "" {
		log.Fatal().Msg("Cache file path is empty")
	}
	file, err := os.Open(cached)
	if err != nil {
		log.Fatal().Err(err).Msgf("Could not open the file %s", cached)
	}
	scanner := bufio.NewScanner(file)
	it := &LeipzigIterator{
		scanner: scanner,
	}
	return it
}

// FetchCorpusFile gets the file from the remote url.
// We assume that the file is compressed somehow, and we want to get a file from the container.
func (c *LeipzigCorpus) FetchCorpusFile() corpus.File {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal().Err(err).Msg("Could not get home directory")
	}

	url := fmt.Sprintf("%s/%s", c.url_, c.corpusFile)

	cacheDir := path.Join(home, ".ftw")

	log.Debug().Msgf("Preparing download of corpus file from %s", url)
	dest := path.Join(cacheDir, "extracted")
	if err := os.MkdirAll(dest, os.ModePerm); err != nil {
		log.Fatal().Err(err).Msg("Could not create destination directory")
	}

	cache := NewFile().WithCacheDir(cacheDir).WithFilePath(c.filename)

	if cache.FilePath() == "" {
		log.Fatal().Msg("Cache file path is empty")
	}

	if info, err := os.Stat(path.Join(home, ".ftw", cache.FilePath())); err == nil {
		log.Debug().Msgf("filename %s already exists", info.Name())
		cache = cache.WithFilePath(path.Join(home, ".ftw", c.filename))
		return cache
	}

	request := &getter.Request{
		Src:     url,
		Dst:     dest,
		GetMode: getter.ModeAny,
	}
	client := &getter.Client{
		Getters: []getter.Getter{
			new(getter.HttpGetter),
		},
	}

	log.Info().Msgf("Downloading corpus file from %s", url)
	_, err = client.Get(context.Background(), request)
	if err != nil {
		log.Fatal().Msgf("download failed: %v", err)
	}

	err = filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("Error walking:", err)
			return err
		}

		if info.IsDir() {
			return nil // Skip directories
		}

		log.Trace().Msgf("Checking file %s", info.Name())

		if info.Name() == c.filename {
			newPath := filepath.Join(cacheDir, info.Name())
			err = os.Rename(path, newPath)
			if err != nil {
				fmt.Println("Error moving:", err)
				return err
			}
			fmt.Println("Moved", path, "to", newPath)
			cache = cache.WithFilePath(newPath)
		}

		return nil
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Could not walk the path")
	}

	return cache
}
