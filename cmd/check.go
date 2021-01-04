package cmd

import (
	"fmt"

	"github.com/fzipi/go-ftw/test"

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
	files := fmt.Sprintf("%s/**/*.y[a]ml", dir)
	tests := test.GetTestsFromFiles(files)
	emoji.Printf("ftw: checked %d files, everything looks good!\n", len(tests))
}
