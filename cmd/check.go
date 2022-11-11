package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/test"
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
		exit = 1
	} else {
		fmt.Printf("ftw/check: checked %d files, everything looks good!\n", len(tests))
		exit = 0
	}
	os.Exit(exit)
}
