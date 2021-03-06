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

	testFiles, _ := filepath.Glob(globPattern)

	for _, test := range testFiles {
		t, err := readTest(test)
		if err != nil {
			break
		} else {
			tests = append(tests, *t)
		}
	}

	return tests, err
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
