i.PHONY: build
build:
	go build -o bin/ri

.PHONY: auth
auth:
	go run main.go auth

.PHONY: authpkce
authpkce:
	go run main.go authpkce


.PHONY: repos
repos:
	go run main.go repos