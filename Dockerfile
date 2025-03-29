FROM alpine:latest

# Install CA certificates (if your CLI needs HTTPS support)
RUN apk add --no-cache ca-certificates

# Copy the CLI binary into the container
COPY ri /usr/local/bin/ri

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/ri

# Set the entrypoint so that any container arguments are passed to the CLI
ENTRYPOINT ["/usr/local/bin/ri"]
