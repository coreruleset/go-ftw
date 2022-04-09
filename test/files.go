package test

import (
	"errors"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"
	"github.com/yargevad/filepathx"
)

// GetTestsFromFiles will get the files to be processed.
// If some file has yaml error, will stop processing and
// return the error with the partial list of files read.
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

	for _, fileName := range testFiles {
		yamlString, err := readFileContents(fileName)
		if err != nil {
			return tests, err
		}
		ftwTest, err := GetTestFromYaml(yamlString)
		if err != nil {
			return tests, err
		}

		ftwTest.FileName = fileName
		tests = append(tests, ftwTest)
	}

	if len(tests) == 0 {
		return tests, errors.New("no tests found")
	}
	return tests, nil
}

// GetTestFromYaml will get the tests to be processed from a YAML string.
func GetTestFromYaml(testYaml []byte) (ftwTest FTWTest, err error) {
	ftwTest, err = readTestYaml(testYaml)
	if err != nil {
		log.Info().Msgf(yaml.FormatError(err, true, true))
		return FTWTest{}, err
	}

	return ftwTest, nil
}

func readTestYaml(testYaml []byte) (t FTWTest, err error) {
	err = yaml.Unmarshal([]byte(testYaml), &t)
	return t, err
}

func readFileContents(fileName string) (contents []byte, err error) {
	contents, err = os.ReadFile(fileName)
	if err != nil {
		log.Info().Caller().Err(err).Msgf("Failed to read contents of test file %s", fileName)
	}
	return contents, err
}
