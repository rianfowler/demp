package keychain

import (
	"errors"
	"fmt"
	"log"

	keychain "github.com/keybase/go-keychain"
)

type TokenType int

const (
	GitHubTokenType TokenType = iota
	Auth0TokenType
)

type tokenData struct {
	account string
	label   string
}

var td = []tokenData{
	{
		account: "gh-token",
		label:   "GitHub token for the ri cli",
	},
	{
		account: "auth0-token",
		label:   "Auth0 token for the ri CLI",
	},
}

func (tt TokenType) data() (tokenData, error) {
	if int(tt) < 0 || int(tt) >= len(td) {
		return tokenData{}, errors.New("invalid token type")
	}
	return td[tt], nil
}

func SaveToken(tokenType TokenType, token string) error {
	ttd, err := tokenType.data()
	if err != nil {
		return err
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService("com.rianfowler.ri")
	item.SetAccount(ttd.account)
	item.SetData([]byte(token))
	item.SetLabel(ttd.label)
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
			query.SetAccount(ttd.account)
			// Update the existing item with new data.
			err = keychain.UpdateItem(query, item)
			// TODO: return logs as errors
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
	return nil
}

func Token(tokenType TokenType) (string, error) {
	ttd, err := tokenType.data()
	if err != nil {
		return "", err
	}

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("com.rianfowler.ri")
	query.SetAccount(ttd.account)
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
