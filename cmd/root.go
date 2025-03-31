package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "demp",
	Short: "Rian's CLI",
	// Default action when no subcommand is provided.
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("run --help")
	},
}

// Execute runs the root command.
func Execute() {
	rootCmd.AddCommand(NewGithubCmd())
	rootCmd.AddCommand(NewDaggerWorkflowCmd())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
