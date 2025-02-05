// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"errors"
	"os"
	"path"

	"github.com/rs/zerolog/log"
	"github.com/yargevad/filepathx"
)

// GetTestsFromFiles will get the files to be processed.
// If some file has yaml error, will stop processing and
// return the error with the partial list of files read.
func GetTestsFromFiles(globPattern string) ([]*FTWTest, error) {
	var tests []*FTWTest
	var err error

	log.Trace().Msgf("ftw/test: using glob pattern %s", globPattern)
	testFiles, err := filepathx.Glob(globPattern)

	log.Trace().Msgf("ftw/test: found %d files matching pattern", len(testFiles))
	if err != nil {
		log.Info().Msgf("ftw/test: error getting test files from %s", globPattern)
		return tests, err
	}

	for _, filePath := range testFiles {
		fileName := path.Base(filePath)
		log.Trace().Msgf("Loading %s", fileName)
		yamlString, err := readFileContents(filePath)
		if err != nil {
			return tests, err
		}
		ftwTest, err := GetTestFromYaml(yamlString, fileName)
		if err != nil {
			log.Warn().Msgf("Problem detected in file %s:\n%v\n",
				filePath, err)
			continue
		}

		tests = append(tests, ftwTest)
	}

	if len(tests) == 0 {
		return tests, errors.New("no tests found")
	}
	return tests, nil
}

func readFileContents(fileName string) (contents []byte, err error) {
	contents, err = os.ReadFile(fileName)
	if err != nil {
		log.Info().Caller().Err(err).Msgf("Failed to read contents of test file %s", fileName)
	}
	return contents, err
}
