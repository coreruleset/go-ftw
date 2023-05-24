package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/coreruleset/go-ftw/test"
)

// NewCheckCmd represents the check command
func NewCheckCommand() *cobra.Command {
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Checks ftw test files for syntax errors.",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			dir, _ := cmd.Flags().GetString("dir")
			checkFiles(dir)
		},
	}
	checkCmd.Flags().StringP("dir", "d", ".", "recursively find yaml tests in this directory")
	return checkCmd
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
