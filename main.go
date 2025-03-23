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

	keychain "github.com/rianfowler/ri/internal/keychain"

	"github.com/dgrijalva/jwt-go"
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
		keychain.SaveToken(keychain.GitHubTokenType, token)
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
	token, err := keychain.Token(keychain.GitHubTokenType)
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

	// cmd.Execute()
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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

// UserProfile represents a simplified version of the Auth0 user profile.
// You can add more fields based on your needs.
type UserProfile struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	// Include other fields as needed.
}

func authPKCE() error {
	// Generate the PKCE code verifier and challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		return fmt.Errorf("generate code verifier: %w", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Construct the authorization URL.
	baseURL := fmt.Sprintf("https://%s/authorize", authDomain)
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base URL: %w", err)
	}
	query := parsedURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", auth0clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", scope)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	parsedURL.RawQuery = query.Encode()
	authURL := parsedURL.String()

	// Open the authorization URL in the user's default browser.
	// Note: "open" works on macOS; consider supporting other OS's (e.g., "xdg-open" for Linux, "start" for Windows).
	// TODO: add support for windows and better fallback
	if err := exec.Command("open", authURL).Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}

	// Start a local HTTP server to wait for the OAuth callback.
	codeChan := make(chan string)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := startLocalServer(ctx, codeChan); err != nil {
		return fmt.Errorf("start local server: %w", err)
	}

	// Wait for the authorization code or timeout.
	var authCode string
	select {
	case authCode = <-codeChan:
		// Received the code.
	case <-ctx.Done():
		return fmt.Errorf("authentication timed out")
	}

	// Prepare parameters for exchanging the authorization code for tokens.
	tokenURL := "https://burritops.us.auth0.com/oauth/token"
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", auth0clientID)
	params.Set("code_verifier", verifier)
	params.Set("code", authCode)
	params.Set("redirect_uri", "http://localhost:8080")
	params.Set("audience", "https://burritops.us.auth0.com/api/v2/")
	payload := params.Encode()

	// Create and send the HTTP request.
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	// Read and parse the token response.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read token response: %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("unmarshal token response: %w", err)
	}

	// Decode the ID token without verifying its signature.
	token, _, err := new(jwt.Parser).ParseUnverified(tokenResp.IDToken, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parse ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("convert token claims to MapClaims")
	}

	// Extract the GitHub access token from the JWT claims.
	ghToken, ok := claims["https://ri.rianfowler.com/github_access_token"].(string)
	if !ok {
		return fmt.Errorf("retrieve GitHub token from claims")
	}

	// Save the GitHub token.
	// keychain.SaveToken(keychain.GitHubToken, ghToken)
	keychain.SaveToken(keychain.GitHubTokenType, ghToken)
	return nil
}
