package test

import (
	"errors"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"
)

// GetTestsFromFiles will get the tests to be processed from a YAML string.
// If some file has yaml error, will stop processing and return the error with the partial list of files read.
func GetTestsFromYaml(testYaml string) ([]FTWTest, error) {
	var tests []FTWTest
	var err error

	t, err := readTest(testYaml)
	if err != nil {
		log.Info().Msgf(yaml.FormatError(err, true, true))
		return tests, err
	}

	tests = append(tests, t)

	if len(tests) == 0 {
		return tests, errors.New("no tests found")
	}
	return tests, nil
}

func readTest(testYaml string) (t FTWTest, err error) {
	err = yaml.Unmarshal([]byte(testYaml), &t)
	t.FileName = t.Meta.Name + ".yaml"
	// Set Defaults
	return t, err
}
