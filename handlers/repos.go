package handlers

import (
	"fmt"
	"io"
	"net/http"
)

func Repos() {
	token, err := Token(keychain.Token(keychain.TokenType.GitHubToken))
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
