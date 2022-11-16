package cmd

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
)

// cleanCmd represents the clean command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Tests",
	Long:  `Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.`,
	Run: func(cmd *cobra.Command, args []string) {
		exclude, _ := cmd.Flags().GetString("exclude")
		include, _ := cmd.Flags().GetString("include")
		id, _ := cmd.Flags().GetString("id")
		dir, _ := cmd.Flags().GetString("dir")
		showTime, _ := cmd.Flags().GetBool("time")
		showOnlyFailed, _ := cmd.Flags().GetBool("show-failures-only")
		wantedOutput, _ := cmd.Flags().GetString("output")
		connectTimeout, _ := cmd.Flags().GetDuration("connect-timeout")
		readTimeout, _ := cmd.Flags().GetDuration("read-timeout")
		maxMarkerRetries, _ := cmd.Flags().GetInt("max-marker-retries")
		maxMarkerLogLines, _ := cmd.Flags().GetInt("max-marker-log-lines")

		if wantedOutput == "" {
			wantedOutput = "normal"
		}
		if id != "" {
			log.Fatal().Msgf("--id is deprecated in favour of --include|-i")
		}
		if exclude != "" && include != "" {
			log.Fatal().Msgf("You need to choose one: use --include (%s) or --exclude (%s)", include, exclude)
		}
		files := fmt.Sprintf("%s/**/*.yaml", dir)
		tests, err := test.GetTestsFromFiles(files)

		if err != nil {
			log.Fatal().Err(err)
		}

		var includeRE *regexp.Regexp
		if include != "" {
			includeRE = regexp.MustCompile(include)
		}
		var excludeRE *regexp.Regexp
		if exclude != "" {
			excludeRE = regexp.MustCompile(exclude)
		}

		//TODO: pass --file parameter to change this file
		out := output.NewOutput(wantedOutput, os.Stdout)
		_ = out.Println("%s", out.Message("** Starting tests!"))

		currentRun, err := runner.Run(tests, runner.Config{
			Include:           includeRE,
			Exclude:           excludeRE,
			ShowTime:          showTime,
			ShowOnlyFailed:    showOnlyFailed,
			ConnectTimeout:    connectTimeout,
			ReadTimeout:       readTimeout,
			MaxMarkerRetries:  maxMarkerRetries,
			MaxMarkerLogLines: maxMarkerLogLines,
		}, out)
		if err != nil {
			log.Fatal().Err(err)
		}

		os.Exit(currentRun.Stats.TotalFailed())
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("exclude", "e", "", "exclude tests matching this Go regexp (e.g. to exclude all tests beginning with \"91\", use \"91.*\"). \nIf you want more permanent exclusion, check the 'testoverride' option in the config file.")
	runCmd.Flags().StringP("include", "i", "", "include only tests matching this Go regexp (e.g. to include only tests beginning with \"91\", use \"91.*\").")
	runCmd.Flags().StringP("id", "", "", "(deprecated). Use --include matching your test only.")
	runCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	runCmd.Flags().StringP("output", "o", "normal", "output type for ftw tests. \"normal\" is the default.")
	runCmd.Flags().BoolP("time", "t", false, "show time spent per test")
	runCmd.Flags().BoolP("show-failures-only", "", false, "shows only the results of failed tests")
	runCmd.Flags().Duration("connect-timeout", 3*time.Second, "timeout for connecting to endpoints during test execution")
	runCmd.Flags().Duration("read-timeout", 1*time.Second, "timeout for receiving responses during test execution")
	runCmd.Flags().Int("max-marker-retries", 20, "maximum number of times the search for log markers will be repeated; each time an additional request is sent to the web server, eventually forcing the log to be flushed")
	runCmd.Flags().Int("max-marker-log-lines", 500, "maximum number of lines to search for a marker before aborting")
}
