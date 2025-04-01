package cmdwip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// Azure AD B2C configuration.
	// Replace these with your actual values.
	azureDomain   = "rianfowler.b2clogin.com"              // Your B2C domain.
	tenant        = "rianfowler.onmicrosoft.com"           // Your B2C tenant domain.
	policy        = "B2C_1_GitHubSignUpSignIn"             // Your sign-up/sign-in policy.
	azureClientID = "fe36fddf-1602-4e3e-afea-04a00763455d" // Your app's client ID in the B2C tenant.
	// Scopes: at minimum "openid" is required.
	// scope = "openid profile email offline_access"
)

var azurePKCECmd = &cobra.Command{
	Use:   "azure-pkce",
	Short: "Interactive authentication into Azure AD B2C",
	RunE: func(cmd *cobra.Command, args []string) error {
		return authAzurePKCE()
	},
}

// type TokenResponse struct {
// 	AccessToken  string `json:"access_token"`
// 	RefreshToken string `json:"refresh_token"`
// 	IDToken      string `json:"id_token"`
// 	TokenType    string `json:"token_type"`
// 	ExpiresIn    int    `json:"expires_in"`
// 	Scope        string `json:"scope"`
// 	Error        string `json:"error"`
// }

func authAzurePKCE() error {
	// Generate the PKCE code verifier and challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		return fmt.Errorf("generate code verifier: %w", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Construct the authorization URL.
	// For Azure AD B2C the URL format is:
	// https://{domain}/{tenant}/{policy}/oauth2/v2.0/authorize
	baseURL := fmt.Sprintf("https://%s/%s/oauth2/v2.0/authorize", azureDomain, tenant)
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base URL: %w", err)
	}
	query := parsedURL.Query()
	query.Set("p", policy)
	query.Set("client_id", azureClientID)
	query.Set("nonce", "defaultNonce")
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid")
	query.Set("response_type", "code")
	query.Set("prompt", "login")
	query.Set("code_challenge_method", "S256")
	query.Set("code_challenge", challenge)
	parsedURL.RawQuery = query.Encode()
	authURL := parsedURL.String()

	// Open the authorization URL in the user's default browser.
	// Adjust for your OS as needed.
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

	// Construct the token endpoint URL.
	// Format: https://{domain}/{tenant}/{policy}/oauth2/v2.0/token
	tokenURL := fmt.Sprintf("https://%s/%s/%s/oauth2/v2.0/token", azureDomain, tenant, policy)
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", azureClientID)
	params.Set("code_verifier", verifier)
	params.Set("code", authCode)
	params.Set("redirect_uri", redirectURI)
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
	fmt.Println(claims)

	// Extract the GitHub access token from the JWT claims.
	// (Assumes you've configured a claim mapping in your B2C custom policy)
	ghToken, ok := claims["idp_access_token"].(string)
	if !ok {
		return fmt.Errorf("retrieve GitHub token from claims")
	}

	// Save the GitHub token.
	keychain.SaveToken(keychain.GitHubTokenType, ghToken)
	return nil
}

// generateCodeVerifier creates a random code verifier.
// func generateCodeVerifier() (string, error) {
// 	b := make([]byte, 32)
// 	if _, err := rand.Read(b); err != nil {
// 		return "", err
// 	}
// 	return base64.RawURLEncoding.EncodeToString(b), nil
// }

// // generateCodeChallenge computes the SHA256 code challenge for the given verifier.
// func generateCodeChallenge(verifier string) string {
// 	sha := sha256.New()
// 	sha.Write([]byte(verifier))
// 	sum := sha.Sum(nil)
// 	return base64.RawURLEncoding.EncodeToString(sum)
// }

// // startLocalServer starts an HTTP server to listen for the OAuth callback.
// func startLocalServer(ctx context.Context, codeChan chan<- string) error {
// 	mux := http.NewServeMux()
// 	server := &http.Server{
// 		Addr:    ":8080",
// 		Handler: mux,
// 	}

// 	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
// 		code := r.URL.Query().Get("code")
// 		if code == "" {
// 			http.Error(w, "No code in the request", http.StatusBadRequest)
// 			return
// 		}
// 		fmt.Fprintf(w, "Authentication successful. You can close this window.")
// 		codeChan <- code
// 		go func() {
// 			_ = server.Shutdown(context.Background())
// 		}()
// 	})

// 	go func() {
// 		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
// 			log.Printf("HTTP server error: %v", err)
// 		}
// 	}()

// 	go func() {
// 		<-ctx.Done()
// 		_ = server.Shutdown(context.Background())
// 	}()

// 	return nil
// }
