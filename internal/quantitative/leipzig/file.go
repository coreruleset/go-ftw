// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import "github.com/coreruleset/go-ftw/experimental/corpus"

// File implements the corpus.File interface.
type File struct {
	cacheDir string
	filePath string
}

// NewFile returns a new File
func NewFile() corpus.File {
	return File{}
}

// CacheDir is the directory where files are cached
func (f File) CacheDir() string {
	return f.cacheDir
}

// FilePath is the path to the cached file
func (f File) FilePath() string {
	return f.filePath
}

// WithCacheDir sets the cache directory
func (f File) WithCacheDir(cacheDir string) corpus.File {
	f.cacheDir = cacheDir
	return f
}

// WithFilePath sets the file path
func (f File) WithFilePath(filePath string) corpus.File {
	f.filePath = filePath
	return f
}
