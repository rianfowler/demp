// cmd/github.go
package cmd

import (
	"context"
	"fmt"
	"os"

	"dagger.io/dagger"
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
		Use:   "latest-tag [repo]",
		Short: "Fetch the latest release tag for the repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			tag, err := github.FetchLatestTag(ctx, args[0])
			if err != nil {
				return err
			}
			fmt.Print(tag)
			return nil
		},
	}

	githubCmd.AddCommand(fetchCmd)
	githubCmd.AddCommand(newReleaseCmd())
	return githubCmd
}

func newReleaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new-release [version] [commit]",
		Short: "Create a new GitHub release using GH CLI via Dagger",
		Long: `This command creates a new GitHub release by running the GitHub CLI (gh) inside a container managed by Dagger.
It expects:
  - A version string (with or without a leading "v").
  - A target commit SHA (for example, from your GitHub workflow's github.sha).

It uses the GITHUB_TOKEN secret (provided via the environment variable) to authenticate with GitHub.
The release is created with a title "Release <version>" and default release notes.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			version := args[0]
			commit := args[1]
			title := fmt.Sprintf("Release %s", version)
			notes := fmt.Sprintf("Release notes for version %s", version)

			ctx := context.Background()

			// Connect to Dagger.
			client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stdout))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error connecting to Dagger:", err)
				os.Exit(1)
			}
			defer client.Close()

			// Get the GitHub token from environment variables.
			token := os.Getenv("GITHUB_TOKEN")
			if token == "" {
				fmt.Fprintln(os.Stderr, "GITHUB_TOKEN environment variable is not set")
				os.Exit(1)
			}

			// Set the secret using Dagger's secrets API.
			ghSecret := client.SetSecret("GITHUB_TOKEN", token)

			container := client.Container().
				From("ubuntu:20.04").
				// Set noninteractive mode for apt.
				WithEnvVariable("DEBIAN_FRONTEND", "noninteractive").
				// Update package lists.
				WithExec([]string{"apt-get", "update"}).
				// Install required packages.
				WithExec([]string{"apt-get", "install", "-y", "curl", "apt-transport-https", "gnupg"}).
				// Import the GitHub CLI GPG key.
				WithExec([]string{"bash", "-c", "curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /usr/share/keyrings/githubcli-archive-keyring.gpg > /dev/null"}).
				// Add the GitHub CLI repository.
				WithExec([]string{"bash", "-c", "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null"}).
				// Update package lists again.
				WithExec([]string{"apt-get", "update"}).
				// Install the GitHub CLI.
				WithExec([]string{"apt-get", "install", "-y", "gh"}).
				// Inject the GITHUB_TOKEN secret as an environment variable.
				WithSecretVariable("GITHUB_TOKEN", ghSecret).
				// Run the GH CLI command to create a release.
				WithExec([]string{
					"gh", "release", "create", version,
					"--title", title,
					"--notes", notes,
					"--target", commit,
					"--repo", "rianfowler/demp",
				})

			// Run the container command.
			output, err := container.Stdout(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error executing release creation command:", err)
				os.Exit(1)
			}

			fmt.Println("Release created successfully!")
			fmt.Println(output)
		},
	}

	return cmd
}
