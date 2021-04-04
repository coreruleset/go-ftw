package cmd

import (
	"fmt"

	"github.com/kyokomi/emoji"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/fzipi/go-ftw/runner"
	"github.com/fzipi/go-ftw/test"
)

// cleanCmd represents the clean command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Tests",
	Long:  `Run all tests below a certain subdirectory. The command will search all y[a]ml files recursively and pass it to the test engine.`,
	Run: func(cmd *cobra.Command, args []string) {
		testid, _ := cmd.Flags().GetString("id")
		exclude, _ := cmd.Flags().GetString("exclude")
		dir, _ := cmd.Flags().GetString("dir")
		showTime, _ := cmd.Flags().GetBool("time")
		quiet, _ := cmd.Flags().GetBool("quiet")
		if !quiet {
			log.Info().Msgf(emoji.Sprintf(":hammer_and_wrench: Starting tests!\n"))
		} else {
			zerolog.SetGlobalLevel(zerolog.Disabled)
		}
		files := fmt.Sprintf("%s/**/*.yaml", dir)
		tests, err := test.GetTestsFromFiles(files)
		if err != nil {
			log.Error().Msg(err.Error())
		}
		runner.Run(testid, exclude, showTime, quiet, tests)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("id", "", "", "set test id to run")
	runCmd.Flags().StringP("exclude", "", "", "exclude tests matching this Go regexp (e.g. to exclude all tests beginning with \"91\", use \"91.*\"). If you want more permanent exclusion, check the 'testmodify' option in the config file.")
	runCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	runCmd.Flags().BoolP("quiet", "q", false, "do not show test by test, only results")
	runCmd.Flags().BoolP("time", "t", false, "show time spent per test")
}
