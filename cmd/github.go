// cmd/github.go
package cmd

import (
	"context"
	"fmt"

	"github.com/rianfowler/demp/pkg/github"
	"github.com/spf13/cobra"
)

// NewGithubCmd returns a Cobra command for GitHub-related operations.
func NewGithubCmd() *cobra.Command {
	githubCmd := &cobra.Command{
		Use:   "github",
		Short: "Commands related to GitHub operations",
	}

	fetchCmd := &cobra.Command{
		Use:   "fetch-latest-tag [repo]",
		Short: "Fetch the latest release tag for the repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			tag, err := github.FetchLatestTag(ctx, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Latest tag: %s\n", tag)
			return nil
		},
	}

	githubCmd.AddCommand(fetchCmd)
	return githubCmd
}
