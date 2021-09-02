package test

import (
	"io/ioutil"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"
	"github.com/yargevad/filepathx"
)

// GetTestsFromFiles will get the files to be processed. If some file has yaml error, will stop processing and return the error with the partial list of files read.
func GetTestsFromFiles(globPattern string) ([]FTWTest, error) {
	var tests []FTWTest
	var err error

	log.Trace().Msgf("ftw/test: using glob pattern %s", globPattern)
	testFiles, err := filepathx.Glob(globPattern)

	log.Trace().Msgf("ftw/test: found %d files matching pattern", len(testFiles))
	if err != nil {
		log.Info().Msgf("ftw/test: error getting test files from %s", globPattern)
		return tests, err
	}

	for _, test := range testFiles {
		t, err := readTest(test)
		if err != nil {
			log.Info().Msgf(yaml.FormatError(err, true, true))
			return tests, err
		}
		log.Trace().Msgf("ftw/test: reading file %s", test)

		tests = append(tests, t)
	}

	return tests, nil
}

func readTest(filename string) (t FTWTest, err error) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Info().Msgf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &t)

	// Set Defaults
	return t, err
}
