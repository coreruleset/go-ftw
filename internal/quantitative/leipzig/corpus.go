// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/hashicorp/go-getter/v2"
	"github.com/rs/zerolog/log"
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
	// corpusFilename is the original file name that contains the corpus file
	corpusFilename string
	// filename is the file name of the corpus
	filename string
	// corpusLocalPath is the local path to the corpus
	corpusLocalPath string
	// size is the size of the corpus
	size string
	// source is the source of the corpus
	source string
	// year is the year of the corpus
	year string
}

func (c *LeipzigCorpus) regenerateFileNames() {
	size := strings.ToUpper(c.size)

	c.corpusFilename = fmt.Sprintf("%s_%s_%s_%s.%s",
		c.lang, c.source, c.year, size,
		defaultCorpusExt)
	c.filename = fmt.Sprintf("%s_%s_%s_%s-%s",
		c.lang, c.source, c.year, size,
		defaultCorpusType)
}

// NewLeipzigCorpus returns a new Leipzig corpus
func NewLeipzigCorpus(corpusLocalPath string) corpus.Corpus {
	leipzig := &LeipzigCorpus{
		url_:            defaultCorpusSite,
		corpusFilename:  "",
		filename:        "",
		corpusLocalPath: corpusLocalPath,
		lang:            defaultCorpusLanguage,
		source:          defaultCorpusSource,
		year:            defaultCorpusYear,
		size:            defaultCorpusSize,
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

func (c *LeipzigCorpus) LocalPath() string {
	return c.corpusLocalPath
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
	url := fmt.Sprintf("%s/%s", c.url_, c.corpusFilename)

	cacheDir := c.corpusLocalPath
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal().Err(err).Msg("Could not get home directory")
		}
		cacheDir = filepath.Join(home, ".ftw")
		log.Debug().Msgf("Using default corpus cache directory: %s", cacheDir)
	}

	log.Debug().Msgf("Preparing download of corpus file from %s", url)
	dest := filepath.Join(cacheDir, "extracted")
	if err := os.MkdirAll(dest, os.ModePerm); err != nil {
		log.Fatal().Err(err).Msg("Could not create destination directory")
	}

	cache := NewFile().WithCacheDir(cacheDir).WithFileName(c.filename)

	if cache.FilePath() == "" {
		log.Fatal().Msg("Cache file path is empty")
	}

	if info, err := os.Stat(cache.FilePath()); err == nil {
		log.Debug().Msgf("filename %s already exists", info.Name())
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
	_, err := client.Get(context.Background(), request)
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
			if path == cache.FilePath() {
				// During tests, concurrent fetching may get us here even though the cache
				// file already exists. On Windows this will cause errors because a file can
				// only be opened for writing by a single proccess.
				log.Info().Msgf("Cache already exists for %s", c.filename)
				return filepath.SkipAll
			}

			err = os.Rename(path, cache.FilePath())
			if err != nil {
				fmt.Println("Error moving:", err)
				return err
			}
			fmt.Println("Moved", path, "to cache", cache.FilePath())
		}

		return nil
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Could not walk the path")
	}

	return cache
}
