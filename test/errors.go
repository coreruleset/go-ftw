package test

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	"github.com/rs/zerolog/log"
)

// GetLinesFromTest get the output lines from a test name, to show in errors
func (f *FTWTest) GetLinesFromTest(testName string) (int, error) {
	file, err := os.Open(f.FileName)
	if err != nil {
		log.Info().Msgf("yamlFile.Get err   #%v ", err)
	}
	match := fmt.Sprintf("test_title: %s", testName)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	line := 1

	for scanner.Scan() {
		log.Debug().Msgf("%d - %s\n", line, scanner.Text())
		got, err := regexp.Match(match, []byte(scanner.Text()))
		if err != nil {
			log.Fatal().Msgf("ftw/test/error: bad regexp %s", err.Error())
		}
		if got {
			log.Trace().Msgf("ftw/test/error: Found %s at %d", match, line)
			break
		}
		line++
	}

	return line, err
}
