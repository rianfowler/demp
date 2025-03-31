package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Release struct {
	TagName string `json:"tag_name"`
}

// FetchLatestTag retrieves the latest release tag from a given repository.
func FetchLatestTag(ctx context.Context, repo string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}

	// Fallback if no tag is found.
	if rel.TagName == "" || rel.TagName == "null" {
		return "v0.0.0", nil
	}
	return rel.TagName, nil
}
