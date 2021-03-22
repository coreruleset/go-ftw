package test

import (
	"io/ioutil"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"gopkg.in/yaml.v2"
)

// GetTestsFromFiles will get the files to be processed. If some file has yaml error, will stop processing and return the error with the partial list of files read.
func GetTestsFromFiles(globPattern string) ([]FTWTest, error) {
	var tests []FTWTest
	var err error

	testFiles, err := filepath.Glob(globPattern)

	if err != nil {
		log.Info().Msgf("ftw/test: error getting test files from %s", globPattern)
		return tests, err
	}

	for _, test := range testFiles {
		t, err := readTest(test)
		if err != nil {
			log.Debug().Msgf("ftw/test: error reading %s file. Is it patched?", test)
			return tests, err
		}
		tests = append(tests, *t)
	}

	return tests, nil
}

func readTest(filename string) (t *FTWTest, err error) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Info().Msgf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &t)

	// Set Defaults
	return t, err
}
