package leipzig

import (
	"bufio"
	"fmt"
	"github.com/coreruleset/go-ftw/experimental/corpus"
	"github.com/hashicorp/go-getter"
	"github.com/rs/zerolog/log"
	"os"
	"path"
	"path/filepath"
	"strings"
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
	// File is the file name of the corpus
	Filename string
	// size is the size of the corpus
	size string
	// source is the source of the corpus
	source string
	// year is the year of the corpus
	year string
}

func (c *LeipzigCorpus) regenerateFileNames() {
	c.corpusFile = fmt.Sprintf("%s_%s_%s_%s.%s",
		c.lang, c.source, c.year, c.size,
		defaultCorpusExt)
	c.File = fmt.Sprintf("%s_%s_%s_%s-%s",
		c.lang, c.source, c.year, c.size,
		defaultCorpusType)
}

// NewLeipzigCorpus returns a new Leipzig corpus
func NewLeipzigCorpus() corpus.Corpus {
	leipzig := &LeipzigCorpus{
		url_:       defaultCorpusSite,
		corpusFile: "",
		File:       "",
		lang:       defaultCorpusLanguage,
		source:     defaultCorpusSource,
		year:       defaultCorpusYear,
		size:       defaultCorpusSize,
	}

	leipzig.regenerateFileNames()

	return leipzig
}

// size returns the size of the corpus
func (c *LeipzigCorpus) Size() string {
	return c.size
}

func (c *LeipzigCorpus) WithSize(size string) corpus.Corpus {
	c.size = size
	c.regenerateFileNames()
	return c
}

// year returns the year of the corpus
func (c *LeipzigCorpus) Year() string {
	return c.year
}

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

func (c *LeipzigCorpus) WithSource(source string) corpus.Corpus {
	c.source = source
	c.regenerateFileNames()
	return c
}

// Lang returns the language of the corpus
func (c *LeipzigCorpus) Lang() string {
	return c.lang
}

func (c *LeipzigCorpus) WithLanguage(lang string) corpus.Corpus {
	c.lang = lang
	c.regenerateFileNames()
	return c
}

// GetIterator returns an iterator for the corpus
func (c *LeipzigCorpus) GetIterator(cache corpus.CorpusFile) corpus.Iterator {
	// open cache file
	if cache.FilePath == "" {
		log.Fatal().Msg("Cache file path is empty")
	}
	file, err := os.Open(cache.FilePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Could not open the file %s", cache.FilePath)
	}
	scanner := bufio.NewScanner(file)
	it := &LeipzigIterator{
		scanner: scanner,
	}
	return it
}

// GetPayload returns the payload from the line
// We assume that the first word is the line number,
// and we want the rest
func (c *LeipzigCorpus) GetPayload(line string) string {
	return strings.Join(strings.Split(line, "\t")[1:], " ")
}

// GetCorpusFile gets the file from the remote url.
// We assume that the file is compressed somehow, and we want to get a file from the container.
func (c *LeipzigCorpus) GetCorpusFile() corpus.CorpusFile {
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

	cache := corpus.CorpusFile{
		CacheDir: cacheDir,
		FilePath: "",
	}

	if info, err := os.Stat(path.Join(home, ".ftw", c.File)); err == nil {
		log.Debug().Msgf("File %s already exists", info.Name())
		cache.FilePath = path.Join(home, ".ftw", c.File)
		return cache
	}

	client := &getter.Client{
		Mode: getter.ClientModeAny,
		Src:  url,
		Dst:  dest,
	}

	log.Info().Msgf("Downloading corpus file from %s", url)
	err = client.Get()
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

		if info.Name() == c.File {
			newPath := filepath.Join(cacheDir, info.Name())
			err = os.Rename(path, newPath)
			if err != nil {
				fmt.Println("Error moving:", err)
				return err
			}
			fmt.Println("Moved", path, "to", newPath)
			cache.FilePath = newPath
		}

		return nil
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Could not walk the path")
	}

	return cache
}
