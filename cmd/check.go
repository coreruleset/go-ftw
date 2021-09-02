package cmd

import (
	"fmt"
	"os"

	"github.com/fzipi/go-ftw/test"
	"github.com/rs/zerolog/log"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Checks ftw test files for syntax errors.",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		dir, _ := cmd.Flags().GetString("dir")
		checkFiles(dir)
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
}

func checkFiles(dir string) {
	var exit int
	files := fmt.Sprintf("%s/**/*.yaml", dir)
	log.Trace().Msgf("ftw/check: checking files using glob pattern: %s", files)
	tests, err := test.GetTestsFromFiles(files)
	if err != nil {
		emoji.Printf("ftw/check: :collision: oops, found %s\n", err.Error())
		exit = 1
	} else {
		emoji.Printf("ftw/check: checked %d files, everything looks good!\n", len(tests))
		exit = 0
	}
	os.Exit(exit)
}
