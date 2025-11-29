// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"path/filepath"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
)

// File implements the corpus.File interface.
type File struct {
	cacheDir string
	fileName string
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
	return filepath.Join(f.cacheDir, f.fileName)
}

// WithCacheDir sets the cache directory
func (f File) WithCacheDir(cacheDir string) corpus.File {
	f.cacheDir = cacheDir
	return f
}

// WithFileName sets the filename
func (f File) WithFileName(fileName string) corpus.File {
	f.fileName = fileName
	return f
}
