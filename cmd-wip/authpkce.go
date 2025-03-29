package cmd-wip

import (
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
	"os/exec"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	keychain "github.com/rianfowler/demp/internal/keychain"
	"github.com/spf13/cobra"
)

const (
	// Replace with your OAuth app’s client ID
	authDomain    = "burritops.us.auth0.com"           // e.g., "your-tenant.auth0.com"
	auth0clientID = "o71WB9il2dm4vBFBk6KSgTcSWCKYDStn" // Your Auth0 application's client ID
	// redirectURI   = "http://localhost:8080/callback"
	redirectURI = "http://localhost:8080"
	// Scopes should include those needed for authentication and for GitHub access.
	scope = "openid profile email offline_access read:github"
)

var pkceCmd = &cobra.Command{
	Use:   "pkce",
	Short: "Interactive authentication into Auth0",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delegate the business logic to the handler.
		return authPKCE()
	},
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
