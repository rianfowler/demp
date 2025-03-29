package cmd-wip

import (
	"fmt"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Device authentication into GitHub",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("run --help")
	},
}

func init() {
	authCmd.AddCommand(pkceCmd)
	authCmd.AddCommand(deviceCmd)
	authCmd.AddCommand(azurePKCECmd)

	rootCmd.AddCommand(authCmd)
}
