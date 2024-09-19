// Package corpus provides functionality for creating and managing corpora.
//
// A corpus is a collection of text documents that are used for training and testing machine learning models.
// The documents in a corpus are typically sentences or paragraphs of text.
//
// The corpus package provides an interface for working with corpora, as well as a set of built-in corpora
// that can be used for detecting which text will generate false positives in WAF rules.
//
// This interface includes methods for retrieving the URL of a corpus, fetching the file from the remote URL,
// creating an iterator for the corpus, and retrieving the payload of a given a line from the corpus iterator. Each corpus
// will have a size, year, source, and language.
// The iterator interface includes methods for fetching the next sentence from the corpus and checking whether there
// is another sentence in the corpus.
// Each corpus must implement the corpus interface. As this is an experimental package, this
// interface is subject to change.
package corpus

// CorpusFile contains the cache directory and file name
type CorpusFile struct {
	// CacheDir is the directory where files are cached
	CacheDir string
	// FilePath is the path to the cached file
	FilePath string
}

// Corpus is the interface that must be implemented to make a corpus available to clients
type Corpus interface {
	// URL returns the URL of the corpus
	URL() string

	// WithURL sets the URL of the corpus
	WithURL(url string) Corpus

	// FetchCorpusFile fetches the corpus file from the remote URL and returns a CorpusFile for interaction with the file.
    FetchCorpusFile() CorpusFile

	// GetIterator returns an iterator for the corpus
	GetIterator(c CorpusFile) Iterator

	// GetPayload returns the payload given a line from the Corpus Iterator
	GetPayload(line string) string

	// Size returns the size of the corpus
	Size() string
	
	// WithSize sets the size of the corpus
	// Most corpora will have a sizes like "100K", "1M", etc., related to the amount of sentences in the corpus
	WithSize(size string) Corpus

	// Year returns the year of the corpus
	Year() string
	
	// WithYear sets the year of the corpus
	// Most corpora will have a year like "2023", "2022", etc.
	WithYear(year string) Corpus

	// Source returns the source of the corpus
	Source() string

	// WithSource sets the source of the corpus
	// Most corpora will have a source like "news", "web", "wikipedia", etc.
	WithSource(source string) Corpus

	// Language returns the language of the corpus
	Language() string

	// WithLanguage sets the language of the corpus
	// Most corpora will have a language like "eng", "de", etc.
	WithLanguage(lang string) Corpus
}

// Iterator is an interface for iterating over a corpus
type Iterator interface {
	// Next returns the next sentence from the corpus
	Next() string
	// HasNext returns true unless the end of the corpus has been reached
	// false otherwise
	HasNext() bool
}
