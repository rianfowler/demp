package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	keychain "github.com/keybase/go-keychain"
	"github.com/spf13/cobra"
)

const (
	// Replace with your OAuth app’s client ID
	clientID      = "Iv23lioNIN937L1ok0Rd"
	deviceCodeURL = "https://github.com/login/device/code"
	tokenURL      = "https://github.com/login/oauth/access_token"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	// You can also add "error_description" if needed
}

func authCommand(cmd *cobra.Command, args []string) {
	// Step 1: Request device code
	data := url.Values{}
	data.Set("client_id", clientID)
	// You can adjust the scope as needed (e.g., "repo", "read:user", etc.)
	data.Set("scope", "repo")

	req, err := http.NewRequest("POST", deviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Check if GitHub returned a non-200 status code.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: GitHub returned status %d: %s\n", resp.StatusCode, string(body))
		return
	}

	var deviceResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		fmt.Printf("Error decoding device code response: %s", err)
		return
	}

	// Inform the user to visit the URL and enter the code
	fmt.Printf("Please go to %s and enter the code: %s\n", deviceResp.VerificationURI, deviceResp.UserCode)

	// Step 2: Poll for token
	interval := time.Duration(deviceResp.Interval) * time.Second
	timeout := time.Duration(deviceResp.ExpiresIn) * time.Second
	deadline := time.Now().Add(timeout)

	var token string
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		token, err = pollForToken(deviceResp.DeviceCode)
		if err != nil {
			// Continue polling if authorization is still pending
			if err.Error() == "authorization_pending" {
				continue
			}
			fmt.Println("Error polling for token:", err)
			return
		}
		// Success: Echo the token (secure storage can be added later)
		saveToken(token)
		return
	}
	fmt.Println("Timed out waiting for authorization")
}

func pollForToken(deviceCode string) (string, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Error != "" {
		// For example, error might be "authorization_pending"
		return "", fmt.Errorf(tokenResp.Error)
	}
	return tokenResp.AccessToken, nil
}

func reposCommand(cmd *cobra.Command, args []string) {
	token, err := getToken()
	if err != nil {
		fmt.Println("No auth token. Run auth", err)
		return
	}

	req, err := http.NewRequest("GET", "https://api.github.com/user/repos", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making API request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading API response:", err)
		return
	}
	fmt.Println("Repos response:")
	fmt.Println(string(body))
}

func main() {
	rootCmd := &cobra.Command{Use: "ghcli"}

	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with GitHub using device flow",
		Run:   authCommand,
	}

	reposCmd := &cobra.Command{
		Use:   "repos",
		Short: "Get authenticated user's repositories",
		Run:   reposCommand,
	}

	rootCmd.AddCommand(authCmd, reposCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func saveToken(token string) {

	// Using the service "com.rianfowler.ri" (derived from your app's module path) and
	// account "gh-token" to identify the GitHub token.
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService("com.rianfowler.ri")
	item.SetAccount("gh-token")
	item.SetData([]byte(token))
	item.SetLabel("GitHub Token for ri CLI")
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	// Attempt to add the item to the keychain.
	err := keychain.AddItem(item)
	if err != nil {
		// If an item with the same attributes exists, update it instead.
		if err == keychain.ErrorDuplicateItem {
			// Build a query to find the existing item.
			query := keychain.NewItem()
			query.SetSecClass(keychain.SecClassGenericPassword)
			query.SetService("com.rianfowler.ri")
			query.SetAccount("gh-token")
			// Update the existing item with new data.
			err = keychain.UpdateItem(query, item)
			if err != nil {
				log.Fatalf("Failed to update existing keychain item: %v", err)
			}
			fmt.Println("Keychain item updated successfully.")
		} else {
			log.Fatalf("Failed to add keychain item: %v", err)
		}
	} else {
		fmt.Println("Keychain item added successfully.")
	}
}

func getToken() (string, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("com.rianfowler.ri")
	query.SetAccount("gh-token")
	query.SetReturnData(true)
	query.SetMatchLimit(keychain.MatchLimitOne)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", fmt.Errorf("no token found in keychain")
	}
	return string(results[0].Data), nil
}
