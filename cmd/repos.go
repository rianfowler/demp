package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:   "repos",
	Short: "List repos",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("run --help")
	},
}

func init() {
	rootCmd.AddCommand(reposCmd)
}
