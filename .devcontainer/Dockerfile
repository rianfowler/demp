# Use the official Go image as a base image
FROM golang:1.24

# Install required packages: git, make, zsh, and curl
RUN apt-get update && apt-get install -y \
  git \
  make \
  zsh \
  curl \
  tmux \
  gh \
  && rm -rf /var/lib/apt/lists/*

# Install Delve, a Go debugging tool
RUN go install github.com/go-delve/delve/cmd/dlv@latest

# Install Reflex, a watch task tool
RUN go install github.com/cespare/reflex@latest

# Install cobra-cli for scaffolding CLI applications
RUN go install github.com/spf13/cobra-cli@latest

# Install gotestsum, an alternate testing tool with prettier output
RUN go install gotest.tools/gotestsum@latest

# Install testing library
RUN go install gotest.tools/gotestsum@latest

# Install Oh My Zsh non-interactively
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

RUN curl -sL install.mob.sh | sh

# Set the working directory inside the container
WORKDIR /workspace