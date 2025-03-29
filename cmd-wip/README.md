## Overview

Examples of CLI auth flows using GitHub, Auth0, and EntraID.

## authdevice

```mermaid
sequenceDiagram
    participant CLI as ri-cli
    participant GH as GitHub
    participant KC as MacOS Keychain
    participant U as User
    participant B as Browser

    %% Step 1: Request device code
    CLI->>GH: POST /login/device/code\n(client_id, scope)
    GH-->>CLI: DeviceCodeResponse\n(device_code, user_code,\nverification_uri, expires_in, interval)

    %% Step 2: Inform the user
    CLI->>U: Display message: "Go to <verification_uri> and enter <user_code>"
    U->>B: Open browser to <verification_uri>
    Note over U,B: User authorizes the application in the browser

    %% Step 3: Poll for token until success or timeout
    loop Poll for token (every interval)
        CLI->>GH: POST /login/oauth/access_token\n(client_id, device_code, grant_type)
        GH-->>CLI: "authorization_pending"\nor AccessToken if approved
    end

    %% Step 4: Save token once received
    CLI->>KC: SaveToken(token)
```

## authpkce

Assume a couple of things with this PKCE flow:

- User can only login with GitHub via Auth0
- Auth0 runs a post login action to save the GitHub access token as a custom claim on the Auth0 jwt

```mermaid
sequenceDiagram
    participant CLI as ri-cli
    participant Auth0 as Auth0
    participant KC as MacOS Keychain
    participant U as User
    participant B as Browser
    participant GH as GitHub

    %% Step 1: Generate PKCE challenge (internal)
    Note over CLI: Generate code verifier and challenge

    %% Step 2: Construct authorization URL and open browser
    CLI->>Auth0: Build /authorize URL with\nclient_id, redirect_uri,\nscope, code_challenge, etc.
    CLI->>B: Open Browser to Auth0 /authorize URL

    %% Step 3: Auth0 initiates GitHub login
    B->>Auth0: Request Auth0 login page
    Auth0->>B: Redirect to GitHub login page

    %% Step 4: User logs in to GitHub
    U->>B: Enter GitHub credentials
    B->>GH: Submit credentials
    GH-->>B: Return IdP tokens (GitHub tokens)
    B->>Auth0: Redirect back to Auth0 with GitHub tokens

    %% Step 5: Post-login Action in Auth0
    Note over Auth0: Use Auth0 Management API to extract\nGitHub token from IdP tokens and add it as a custom claim
    Auth0-->>B: Redirect to callback with auth code\n(ID token now includes GitHub token custom claim)

    %% Step 6: Local server receives the callback
    B->>CLI: Callback to http://localhost:8080/callback\n(with authorization code)

    %% Step 7: Exchange auth code for tokens
    CLI->>Auth0: POST /oauth/token with code, code_verifier, etc.
    Auth0-->>CLI: Return TokenResponse\n(id_token, access_token, refresh_token)

    %% Step 8: Extract GitHub token from the ID token
    Note over CLI: Parse ID token to extract\nGitHub access token from custom claim

    %% Step 9: Save the GitHub token
    CLI->>KC: SaveToken(GitHub token)
```