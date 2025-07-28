// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"github.com/coreruleset/go-ftw/experimental/corpus"
)

// File implements the corpus.File interface for raw corpus files.
// Raw corpus files are local files, so no caching is needed.
type File struct {
	filePath string
}

// NewFile returns a new File instance
func NewFile() corpus.File {
	return &File{}
}

// CacheDir returns empty string since raw files don't use caching
func (f *File) CacheDir() string {
	return ""
}

// FilePath returns the path to the raw corpus file
func (f *File) FilePath() string {
	return f.filePath
}

// WithCacheDir is a no-op for raw files since they don't use caching
func (f *File) WithCacheDir(cacheDir string) corpus.File {
	return f
}

// WithFileName sets the file path for the raw corpus file
func (f *File) WithFileName(fileName string) corpus.File {
	f.filePath = fileName
	return f
}
