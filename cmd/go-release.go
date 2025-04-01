package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"dagger.io/dagger"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/spf13/cobra"
)

// generateFakeGPGKey creates a dummy RSA key and returns its ASCII-armored version and fingerprint.
func generateFakeGPGKey() (string, string, error) {
	key, err := crypto.GenerateKey("Dummy User", "dummy@example.com", "rsa", 2048)
	if err != nil {
		return "", "", err
	}
	armored, err := key.Armor()
	if err != nil {
		return "", "", err
	}
	fingerprint := key.GetFingerprint()
	return armored, fingerprint, nil
}

func NewGoreleaserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "go-release [tag]",
		Short: "Run goreleaser to create a release for the given tag",
		Long: `This command runs the goreleaser CLI in a container using Dagger.
It mounts the current repository directory into the container, sets the GORELEASER_CURRENT_TAG environment variable,
and imports a GPG key for signing.
If GPG flags are provided, they will be used; otherwise, a fake key is generated for local testing.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tag := args[0]
			ctx := context.Background()

			// Pull flags from the command line.
			// Accept the GPG secret as a base64 encoded string.
			gpgSecretB64, _ := cmd.Flags().GetString("gpg-secret")
			var gpgSecret string
			if gpgSecretB64 != "" {
				decodedSecret, err := base64.StdEncoding.DecodeString(gpgSecretB64)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error decoding base64 GPG secret:", err)
					os.Exit(1)
				}
				gpgSecret = string(decodedSecret)
			}

			gpgPassphrase, _ := cmd.Flags().GetString("gpg-passphrase")
			gpgFingerprint, _ := cmd.Flags().GetString("gpg-fingerprint")

			// Connect to Dagger.
			client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stdout))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error connecting to Dagger:", err)
				os.Exit(1)
			}
			defer client.Close()

			// Mount the current repository directory.
			repo := client.Host().Directory(".", dagger.HostDirectoryOpts{})

			var container *dagger.Container
			usingFakeKey := false

			if gpgSecret != "" && gpgFingerprint != "" {
				// Use the provided real GPG key.
				container = client.Container().
					From("goreleaser/goreleaser:latest").
					WithDirectory("/src", repo).
					WithWorkdir("/src").
					WithEnvVariable("GORELEASER_CURRENT_TAG", tag).
					WithEnvVariable("GNUPGHOME", "/tmp/gpghome").
					WithEnvVariable("GPG_FINGERPRINT", gpgFingerprint).
					// Install GPG.
					WithExec([]string{"apk", "add", "--no-cache", "gnupg"}).
					// Create the isolated GNUPGHOME.
					WithExec([]string{"mkdir", "-p", "/tmp/gpghome"}).
					// Import the provided key.
					WithSecretVariable("GPG_SECRET", client.SetSecret("GPG_SECRET", gpgSecret)).
					WithExec([]string{"sh", "-c", "echo \"$GPG_SECRET\" > /tmp/gpgkey.asc"}).
					WithExec([]string{"gpg", "--batch", "--passphrase", gpgPassphrase, "--import", "/tmp/gpgkey.asc"}).
					// Run goreleaser.
					WithExec([]string{"goreleaser", "release", "--snapshot"})
			} else {
				usingFakeKey = true
				// Generate a fake key for local testing.
				fakeKey, fingerprint, err := generateFakeGPGKey()
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error generating fake GPG key:", err)
					os.Exit(1)
				}
				// Create a virtual directory containing the fake key.
				fakeKeyDir := client.Directory().WithNewFile("fakekey.asc", fakeKey)

				container = client.Container().
					From("goreleaser/goreleaser:latest").
					WithDirectory("/src", repo).
					WithDirectory("/fake/gpg", fakeKeyDir).
					WithWorkdir("/src").
					WithEnvVariable("GORELEASER_CURRENT_TAG", tag).
					WithEnvVariable("GNUPGHOME", "/tmp/gpghome").
					WithEnvVariable("GPG_FINGERPRINT", fingerprint).
					WithExec([]string{"apk", "add", "--no-cache", "gnupg"}).
					WithExec([]string{"mkdir", "-p", "/tmp/gpghome"}).
					WithExec([]string{"gpg", "--import", "/fake/gpg/fakekey.asc"}).
					WithExec([]string{"goreleaser", "release", "--snapshot"})
			}

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

			// If using a fake key, warn the user and provide a verification command.
			if usingFakeKey {
				fmt.Println("===================================================")
				fmt.Println("WARNING: A fake GPG key was generated and used to sign the binaries.")
				fmt.Println("This key is solely for testing purposes and cannot be used for product releases.")
				fmt.Println("Production releases must be signed via the GitHub Action process.")
				fmt.Println("===================================================")
				fmt.Println("Note: The signing process creates detached signatures. Look for files with a '.sig' extension in the dist folder.")
			} else {
				fmt.Println("Production GPG key was used to sign the binaries.")
			}
		},
	}

	// Define flags for the GPG parameters.
	cmd.Flags().String("gpg-secret", "", "The base64-encoded ASCII-armored GPG key to import")
	cmd.Flags().String("gpg-passphrase", "", "The passphrase for the GPG key")
	cmd.Flags().String("gpg-fingerprint", "", "The fingerprint for the GPG key")

	return cmd
}
