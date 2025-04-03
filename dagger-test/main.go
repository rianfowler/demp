package main

import (
	"context"
	"fmt"
)

// Module is our Dagger module.
// Dagger CLI will look for exported methods on an exported type in package main.
type Module struct{}

// Hello returns a friendly greeting.
// You can call this with:
//
//	dagger call hello --name="World" --module=github.com/youruser/yourrepo@main
func (m *Module) Hello(ctx context.Context, name string) (string, error) {
	return fmt.Sprintf("Hello, %s!", name), nil
}

// SpicyArt prints out some ASCII art with a 90s flair.
// You can call this with:
//
//	dagger call spicy-art --name="Bart" --module=github.com/youruser/yourrepo@main
func (m *Module) HelloWorld(ctx context.Context, name string) (string, error) {
	// This ASCII art is inspired by a 90s vibe.
	// It's playful and references that classic "Don't have a cow, man!" sentiment.
	art := fmt.Sprintf(`
   ______
  /      \
 |  DON'T |
 |  HAVE  |
 | A COW, |
 | %s! |
  \______/
       \   ^__^
        \  (oo)\_______
           (__)\       )\/\
               ||----w |
               ||     ||
`, name)
	return art, nil
}
