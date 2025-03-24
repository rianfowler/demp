package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	keychain "github.com/rianfowler/ri/internal/keychain"
	"github.com/spf13/cobra"
)

const (
	// Replace with your OAuth app’s client ID
	githubClientID       = "Iv23lioNIN937L1ok0Rd"
	githubDeviceCodeUrl  = "https://github.com/login/device/code"
	githubAccessTokenUrl = "https://github.com/login/oauth/access_token"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Device authentication into GitHub",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delegate the business logic to the handler.
		return authDevice()
	},
}

func authDevice() error {
	// Step 1: Request device code
	data := url.Values{}
	data.Set("client_id", githubClientID)
	// You can adjust the scope as needed (e.g., "repo", "read:user", etc.)
	data.Set("scope", "repo")

	req, err := http.NewRequest("POST", githubDeviceCodeUrl, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return err
	}
	defer resp.Body.Close()

	// Check if GitHub returned a non-200 status code.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: GitHub returned status %d: %s\n", resp.StatusCode, string(body))
		return err
	}

	var deviceResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		fmt.Printf("Error decoding device code response: %s", err)
		return err
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
			return err
		}
		// Success: Echo the token (secure storage can be added later)
		keychain.SaveToken(keychain.GitHubTokenType, token)
		return nil
	}
	fmt.Println("Timed out waiting for authorization")
	return nil
}

func pollForToken(deviceCode string) (string, error) {
	data := url.Values{}
	data.Set("client_id", githubClientID)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequest("POST", githubAccessTokenUrl, bytes.NewBufferString(data.Encode()))
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
