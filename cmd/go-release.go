package cmd

import (
	"context"
	"fmt"
	"os"

	"dagger.io/dagger"
	"github.com/spf13/cobra"
)

func NewGoreleaserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "go-release [tag]",
		Short: "Run goreleaser to create a release for the given tag",
		Long: `This command runs the goreleaser CLI in a container using Dagger.
It mounts the current repository directory into the container (since goreleaser requires repo context)
and sets the GORELEASER_CURRENT_TAG environment variable to specify which tag to release.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tag := args[0]
			ctx := context.Background()

			// Connect to Dagger.
			client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stdout))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error connecting to Dagger:", err)
				os.Exit(1)
			}
			defer client.Close()

			// Mount the current repository directory.
			repo := client.Host().Directory(".", dagger.HostDirectoryOpts{})

			// Build a container from the official goreleaser image.
			container := client.Container().
				From("goreleaser/goreleaser:latest").
				// Mount the repository into the container at /src.
				WithDirectory("/src", repo).
				// Set the working directory so goreleaser finds your config and .git.
				WithWorkdir("/src").
				// Set the tag via an environment variable.
				WithEnvVariable("GORELEASER_CURRENT_TAG", tag).
				// Run the goreleaser release command.
				WithExec([]string{"goreleaser", "release", "--snapshot", "--clean"})

			// Execute the container command.
			output, err := container.Stdout(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error executing goreleaser release command:", err)
				os.Exit(1)
			}

			// Export the output directory (goreleaser typically outputs artifacts to /src/dist).
			distDir := container.Directory("/src/dist")
			if _, err := distDir.Export(ctx, "./dist"); err != nil {
				fmt.Fprintln(os.Stderr, "Error exporting dist directory:", err)
				os.Exit(1)
			}

			fmt.Println("Goreleaser output:")
			fmt.Println(output)
		},
	}
	return cmd
}
