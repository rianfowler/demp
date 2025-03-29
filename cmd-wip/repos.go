package cmd-wip

import (
	"fmt"
	"io"
	"net/http"

	keychain "github.com/rianfowler/demp/internal/keychain"
	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:   "repos",
	Short: "List repos",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delegate the business logic to the handler.
		return repos()
	},
}

func init() {
	rootCmd.AddCommand(reposCmd)
}

func repos() error {
	token, err := keychain.Token(keychain.GitHubTokenType)
	if err != nil {
		fmt.Println("No auth token. Run auth", err)
		return err
	}

	req, err := http.NewRequest("GET", "https://api.github.com/user/repos", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making API request:", err)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading API response:", err)
		return err
	}
	fmt.Println("Repos response:")
	fmt.Println(string(body))
	return nil
}
