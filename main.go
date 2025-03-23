package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
	authDomain    = "burritops.us.auth0.com"           // e.g., "your-tenant.auth0.com"
	auth0clientID = "o71WB9il2dm4vBFBk6KSgTcSWCKYDStn" // Your Auth0 application's client ID
	redirectURI   = "http://localhost:8080/callback"
	// Scopes should include those needed for authentication and for GitHub access.
	scope = "openid profile email offline_access read:github"
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
	rootCmd := &cobra.Command{Use: "ri"}

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
	// authpkceCmd is the Cobra command for authentication via PKCE.
	authpkceCmd := &cobra.Command{
		Use:   "authpkce",
		Short: "Authenticate using interactive PKCE flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authPKCE()
		},
	}

	rootCmd.AddCommand(authCmd, reposCmd, authpkceCmd)
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

// generateCodeVerifier creates a random code verifier.
func generateCodeVerifier() (string, error) {
	// Generate 32 random bytes.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge computes the SHA256 code challenge for the given verifier.
func generateCodeChallenge(verifier string) string {
	sha := sha256.New()
	sha.Write([]byte(verifier))
	sum := sha.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// startLocalServer starts an HTTP server to listen for the OAuth callback.
func startLocalServer(ctx context.Context, codeChan chan<- string) error {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Handle the callback endpoint.
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code in the request", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Authentication successful. You can close this window.")
		codeChan <- code
		// Shutdown the server in a goroutine.
		go func() {
			_ = server.Shutdown(context.Background())
		}()
	})

	// Run the server in a goroutine.
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// If the context is canceled (e.g. timeout), shut down the server.
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()

	return nil
}

// authPKCE implements the interactive PKCE flow.
func authPKCE() error {
	// Generate PKCE verifier and challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		return fmt.Errorf("failed to generate code verifier: %w", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Build the Auth0 authorization URL with PKCE parameters.
	// https://burritops.us.auth0.com/authorize?response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&client_id=o71WB9il2dm4vBFBk6KSgTcSWCKYDStn&redirect_uri=http://localhost:8080/callback&scope=openid%20profile&state=xyzABC123
	/*

		open this url
		get the code back
		figure out how to et the github token
			maybe create an action that puts the github token on the claims
	*/
	baseURL := fmt.Sprintf("https://%s/authorize", authDomain)
	u, err := url.Parse(baseURL)
	if err != nil {
		panic(err)
	}

	// Build the query parameters.
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", auth0clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	// This is your fully constructed URL.
	authURL := u.String()

	// authURL := fmt.Sprintf("https://%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&code_challenge=%s&code_challenge_method=S256", authDomain, clientID, redirectURI, scope, challenge)

	// Open the user's browser.
	fmt.Println("Opening browser for authentication...")
	// Note: "open" works on macOS; on Linux you might use "xdg-open", on Windows "start".
	// TODO: add support for other OS's
	if err := exec.Command("open", authURL).Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	// Start a local HTTP server to wait for the callback.
	codeChan := make(chan string)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := startLocalServer(ctx, codeChan); err != nil {
		return fmt.Errorf("failed to start local server: %w", err)
	}

	// Wait for the authorization code or timeout.
	var code string
	select {
	case code = <-codeChan:
		// Received the code.
	case <-ctx.Done():
		return fmt.Errorf("authentication timed out")
	}
	fmt.Println("Received code:", code)

	// Exchange the code for tokens using the go-auth0 authentication package.
	// ctx = context.TODO()
	// authClient, err := authentication.New(ctx, "https://"+authDomain)
	// if err != nil {
	// 	return fmt.Errorf("failed to authentication New: %w", err)
	// }

	// // This function is assumed to exist; adapt parameters as needed.
	// token, err := authClient.ExchangeCodeForToken(clientID, verifier, code, redirectURI)
	// if err != nil {
	// 	return fmt.Errorf("failed to exchange code for token: %w", err)
	// }

	// // Print the access token.
	// fmt.Printf("Access Token: %s\n", token.AccessToken)
	// // If your Auth0 configuration returns a GitHub token as an extra claim, extract it:
	// if githubToken, ok := token.Extra("github_access_token").(string); ok && githubToken != "" {
	// 	fmt.Printf("GitHub Token: %s\n", githubToken)
	// } else {
	// 	fmt.Println("GitHub token not found in the token response")
	// }

	return nil
}
