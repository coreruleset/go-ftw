// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package leipzig

import (
	"reflect"
	"testing"

	"github.com/coreruleset/go-ftw/experimental/corpus"
)

func TestFile_CacheDir(t *testing.T) {
	type fields struct {
		cacheDir string
		filePath string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test 1",
			fields: fields{
				cacheDir: "cacheDir",
				filePath: "filePath",
			},
			want: "cacheDir",
		},
		{
			name: "Test 2",
			fields: fields{
				cacheDir: "cacheDir2",
				filePath: "filePath2",
			},
			want: "cacheDir2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := File{
				cacheDir: tt.fields.cacheDir,
				filePath: tt.fields.filePath,
			}
			if got := f.CacheDir(); got != tt.want {
				t.Errorf("CacheDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFile_FilePath(t *testing.T) {
	type fields struct {
		cacheDir string
		filePath string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Test 1",
			fields: fields{
				cacheDir: "cacheDir",
				filePath: "filePath",
			},
			want: "filePath",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := File{
				cacheDir: tt.fields.cacheDir,
				filePath: tt.fields.filePath,
			}
			if got := f.FilePath(); got != tt.want {
				t.Errorf("FilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFile_WithCacheDir(t *testing.T) {
	type fields struct {
		cacheDir string
		filePath string
	}
	type args struct {
		cacheDir string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   corpus.File
	}{
		{
			name: "Test 1",
			fields: fields{
				cacheDir: "cacheDir1",
				filePath: "filePath",
			},
			args: args{
				cacheDir: "cacheDir10",
			},
			want: File{
				cacheDir: "cacheDir10",
				filePath: "filePath",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := File{
				cacheDir: tt.fields.cacheDir,
				filePath: tt.fields.filePath,
			}
			if got := f.WithCacheDir(tt.args.cacheDir); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithCacheDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFile_WithFilePath(t *testing.T) {
	type fields struct {
		cacheDir string
		filePath string
	}
	type args struct {
		filePath string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   corpus.File
	}{
		{
			name: "Test 1",
			fields: fields{
				cacheDir: "cacheDir",
				filePath: "filePath1",
			},
			args: args{
				filePath: "filePath2",
			},
			want: File{
				cacheDir: "cacheDir",
				filePath: "filePath2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := File{
				cacheDir: tt.fields.cacheDir,
				filePath: tt.fields.filePath,
			}
			if got := f.WithFilePath(tt.args.filePath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithFilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFile(t *testing.T) {
	tests := []struct {
		name string
		want corpus.File
	}{
		{
			name: "Test 1",
			want: File{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewFile(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
