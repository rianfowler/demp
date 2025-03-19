package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/keybase/go-keychain"
)

func main() {
	// Step 1: Call "gh auth token" to get the current GitHub token.
	cmd := exec.Command("gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Error executing 'gh auth token': %v", err)
	}

	// Step 2: Trim any whitespace and ensure we got a token.
	token := strings.TrimSpace(string(output))
	if token == "" {
		log.Fatalf("No token retrieved from gh CLI")
	}

	// (For demonstration only: printing the token. In production, avoid logging secrets.)
	fmt.Println("Retrieved token from gh CLI.")

	// Step 3: Create a new keychain item.
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
	err = keychain.AddItem(item)
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
