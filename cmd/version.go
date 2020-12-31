package cmd

import (
	"ftw/version"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ftw version.",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		emoji.Printf(":fire::test_tube::globe_with_meridians: ftw version %s - %s, built on %s\n", version.Version, version.GitCommit, version.BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
