package test

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"gopkg.in/yaml.v2"
)

// GetTestsFromFiles will get the files to be processed
func GetTestsFromFiles(globPattern string) []FTWTest {
	currentDirectory, err := os.Getwd()
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}
	var tests []FTWTest

	testFiles, _ := filepath.Glob(currentDirectory + "/" + globPattern)

	for _, test := range testFiles {
		t, err := readTest(test)
		if err != nil {
			log.Info().Msgf("Fatal error parsing %s: %v\nSkipping file.\n", test, err)
		} else {
			tests = append(tests, *t)
		}
	}

	return tests
}

func readTest(filename string) (t *FTWTest, err error) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Info().Msgf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &t)
	if err != nil {
		log.Fatal().Msgf("Unmarshaling %s: %v", filename, err)
	}

	// Set Defaults
	return t, err
}
