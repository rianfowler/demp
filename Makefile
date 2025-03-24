i.PHONY: build
build:
	go build -o bin/ri

.PHONY: device
device:
	go run main.go auth device

.PHONY: authpkce
authpkce:
	go run main.go auth pkce


.PHONY: repos
repos:
	go run main.go repos