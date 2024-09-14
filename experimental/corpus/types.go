// Package corpus provides functionality for creating and managing corpora.
//
// A corpus is a collection of text documents that are used for training and testing machine learning models.
// The documents in a corpus are typically sentences or paragraphs of text.
//
// The corpus package provides an interface for working with corpora, as well as a set of built-in corpora
// that can be used for detecting which text will generate false positives in WAF rules.
//
// This interface includes methods for getting the URL of the corpus, getting the file from the remote URL,
// getting an iterator for the corpus, getting the payload given a line from the corpus iterator. Each corpus
// will have a size, year, source, and language.
// The iterator interface includes methods for getting the next sentence from the corpus and checking if there
// is another sentence in the corpus.
// Each corpus will need its own implementation of the Corpus interface. As this is an experimental package, this
// interface is subject to change.
package corpus

// CorpusFile contains the cache directory and file name
type CorpusFile struct {
	// CacheDir is the directory where files are cached
	CacheDir string
	// FilePath is the path to the cached file
	FilePath string
}

// Corpus is the interface that needs to be implemented for getting the payload from a corpus
type Corpus interface {
	// URL returns the URL of the corpus
	URL() string

	// WithURL sets the URL of the corpus
	WithURL(url string) Corpus

	// GetCorpusFile gets the file from the remote url.
	// It returns the local file path were the corpus is stored.
	GetCorpusFile() CorpusFile

	// GetIterator returns an iterator for the corpus
	GetIterator(c CorpusFile) Iterator

	// GetPayload returns the payload given a line from the Corpus Iterator
	GetPayload(line string) string

	// Size returns the size of the corpus
	Size() string
	// WithSize sets the size of the corpus
	// Most corpus will have a size like "100K", "1M", etc., related to the amount of sentences in the corpus
	WithSize(size string) Corpus

	// Year returns the year of the corpus
	Year() string
	// WithYear sets the year of the corpus
	// Most corpus will have a year like "2023", "2022", etc.
	WithYear(year string) Corpus

	// Source returns the source of the corpus
	Source() string
	// WithSource sets the source of the corpus
	// Most corpus will have a source like "news", "web", "wikipedia", etc.
	WithSource(source string) Corpus

	// Lang returns the language of the corpus
	Lang() string
	// WithLanguage sets the language of the corpus
	// Most corpus will have a language like "eng", "de", etc.
	WithLanguage(lang string) Corpus
}

// Iterator is an interface for iterating over a corpus
type Iterator interface {
	// Next returns the next sentence from the corpus
	Next() string
	// HasNext returns true if there is another sentence in the corpus
	// false otherwise
	HasNext() bool
}
