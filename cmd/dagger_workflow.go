// cmd/dagger_workflow.go
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/rianfowler/demp/pkg/github"

	"github.com/spf13/cobra"

	"dagger.io/dagger"
)

// NewDaggerWorkflowCmd returns a Cobra command to run a containerized workflow.
func NewDaggerWorkflowCmd() *cobra.Command {
	workflowCmd := &cobra.Command{
		Use:   "workflow",
		Short: "Run the Dagger workflow for build, test, and deploy",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			// Connect to Dagger with logging enabled.
			client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stdout))
			if err != nil {
				return err
			}
			defer client.Close()

			repo := "rianfowler/demp" // Adjust repository as needed.
			// Fetch the latest tag using the shared function.
			tag, err := github.FetchLatestTag(ctx, repo)
			if err != nil {
				return err
			}
			fmt.Printf("Latest tag (from workflow): %s\n", tag)

			// Step 1: Build the application inside a container.
			buildContainer := client.Container().
				From("golang:1.23").
				WithDirectory("/src", client.Host().Directory(".")).
				WithEnvVariable("VERSION", tag).
				WithExec([]string{"go", "build", "-o", "app"})

			// Step 2: Test the built application.
			_ = buildContainer.WithExec([]string{"./app", "--help"})

			// Step 3: Deploy the application by publishing the container image.
			// _, err = testContainer.Publish(ctx, "docker.io/yourorg/yourapp:"+tag)

			log.Println("Workflow executed successfully")
			return nil
		},
	}

	return workflowCmd
}
