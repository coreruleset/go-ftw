package test

import (
	"errors"
	"os"
	"regexp"

	"github.com/rs/zerolog/log"
	"github.com/yargevad/filepathx"
	"gopkg.in/yaml.v3"
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
			log.Error().Msgf("Problem detected in file %s:\n%s\n%s",
				fileName, err.Error(),
				describeYamlError(err))
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
		return FTWTest{}, err
	}

	return ftwTest, nil
}

func readTestYaml(testYaml []byte) (t FTWTest, err error) {
	err = yaml.Unmarshal(testYaml, &t)
	return t, err
}

func readFileContents(fileName string) (contents []byte, err error) {
	contents, err = os.ReadFile(fileName)
	if err != nil {
		log.Info().Caller().Err(err).Msgf("Failed to read contents of test file %s", fileName)
	}
	return contents, err
}

func describeYamlError(yamlError error) string {
	matched, err := regexp.MatchString(`.*int was used where sequence is expected.*`, yamlError.Error())
	if err != nil {
		return err.Error()
	}
	if matched {
		return "\nTip: This might refer to a \"status\" line being '200', where it should be '[200]'.\n" +
			"The default \"status\" is a list now.\n" +
			"A simple example would be like this:\n\n" +
			"status: 403\n" +
			"needs to be changed to:\n\n" +
			"status: [403]\n\n"
	}
	matched, err = regexp.MatchString(`.*cannot unmarshal \[]interface {} into Go struct field FTWTest.Tests of type string.*`, yamlError.Error())
	if err != nil {
		return err.Error()
	}
	if matched {
		return "\nTip: This might refer to \"data\" on the test being a list of strings instead of a proper YAML multiline.\n" +
			"To fix this, convert this \"data\" string list to a multiline YAML and this will be fixed.\n" +
			"A simple example would be like this:\n\n" +
			"data:\n" +
			"  - 'Hello'\n" +
			"  - 'World'\n" +
			"can be expressed as:\n\n" +
			"data: |\n" +
			"  Hello\n" +
			"  World\n\n" +
			"You can also remove single/double quotes from beggining and end of text, they are not needed. See https://yaml-multiline.info/ for additional help.\n"
	}

	return "We do not have an extended explanation of this error."
}
