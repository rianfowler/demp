// cmd/github.go
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"
)

// NewGithubCmd returns a Cobra command for GitHub-related operations.
func NewSemverCmd() *cobra.Command {
	semverCmd := &cobra.Command{
		Use:   "semver",
		Short: "Commands related to managing semver",
	}

	incrementCmd := &cobra.Command{
		Use:   "increment [repo]",
		Short: "Increment a semantic version using Masterminds/semver",
		Long: `Increment a semantic version.
Provide a version string (with or without a leading "v") and the type of increment:
  - major: Increments the major version and resets minor and patch to 0.
  - minor: Increments the minor version and resets patch to 0.
  - patch: Increments the patch version.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			newVersion, err := incrementVersion(args[0], args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
			fmt.Println(newVersion)
		},
	}

	semverCmd.AddCommand(incrementCmd)
	return semverCmd
}

func incrementVersion(versionStr, kind string) (string, error) {
	prefix := ""
	// Preserve leading "v" if present.
	if strings.HasPrefix(versionStr, "v") {
		prefix = "v"
		versionStr = strings.TrimPrefix(versionStr, "v")
	}

	v, err := semver.NewVersion(versionStr)
	if err != nil {
		return "", err
	}

	var newVer *semver.Version
	switch kind {
	case "major":
		// Increment major and reset minor and patch.
		newVer, err = semver.NewVersion(
			fmt.Sprintf("%d.0.0", v.Major()+1),
		)
	case "minor":
		// Increment minor and reset patch.
		newVer, err = semver.NewVersion(
			fmt.Sprintf("%d.%d.0", v.Major(), v.Minor()+1),
		)
	case "patch":
		// Increment patch.
		newVer, err = semver.NewVersion(
			fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch()+1),
		)
	default:
		return "", fmt.Errorf("unknown increment type: %s", kind)
	}
	if err != nil {
		return "", err
	}
	return prefix + newVer.String(), nil
}
