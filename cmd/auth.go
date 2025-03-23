package cmd

import (
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Device authentication into GitHub",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("run --help")
	},
}

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Device authentication into GitHub"
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delegate the business logic to the handler.
		return handlers.HandleAuthDevice()
	},
}

var pkceCmd =&cobra.Command{
	Use: "pkce"
	Short: "Interactive authentication into Auth0"
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delegate the business logic to the handler.
		return handlers.HandleAuthPKCE()
	},
}

func init() {
	authCmd.AddCommand(pkce)
	authCmd.AddCommand(device)

	rootCmd.AddCommand(authCmd)
}
