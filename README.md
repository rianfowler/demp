# Overview
Personal CLI of Rian Fowler

## Installation

### Using Homebrew

If you’re on macOS or Linux and prefer using Homebrew, you can install **demp** from my Homebrew tap:

```bash
brew tap rianfowler/demp
brew install demp
```

To upgrade to the latest version later, run:

```bash
brew update && brew upgrade demp
```

### Using go install

If you prefer to install from source using Go (requires Go 1.17 or later), you can run:

```bash
go install github.com/rianfowler/demp@latest
```

If you want to install a specific version, for example `v0.1.13`, run:

```bash
go install github.com/rianfowler/demp@v0.1.13
```

### Manual Installation Script

#### 1. Simple Installation (Basic)

This script downloads the release binary and installs it without any extra security checks. You can copy and paste it into your terminal:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Specify the version to install (e.g., "0.1.13")
VERSION="0.1.13"

OS=$(uname | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [[ "${ARCH}" == "x86_64" ]]; then
  ARCH="amd64"
fi

BASE_URL="https://github.com/rianfowler/demp/releases/download/v${VERSION}"
BINARY_NAME="demp_${VERSION}_${OS}_${ARCH}.tar.gz"

echo "Downloading binary from ${BASE_URL}/${BINARY_NAME}"
curl -sSL -o "${BINARY_NAME}" "${BASE_URL}/${BINARY_NAME}"

echo "Extracting binary..."
tar -xzf "${BINARY_NAME}"

# Assuming the tarball extracts a binary named "demp"
chmod +x demp
sudo mv demp /usr/local/bin/demp

echo "demp ${VERSION} installed successfully!"
```

#### 2. Secure Installation (With Checksum and Signature Verification)

This version adds an extra step to verify the integrity and authenticity of the release. It downloads the checksum file and its GPG signature, then verifies the signature. (For more details, please see the "Verifying Releases (Signatures + Checksums)" section below.)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Specify the version to install (e.g., "0.1.13")
# Also specify your public GPG key ID or fingerprint.
VERSION="0.1.13"
KEY_ID="092017BA1C395379"  # Your public key ID

OS=$(uname | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [[ "${ARCH}" == "x86_64" ]]; then
  ARCH="amd64"
fi

BASE_URL="https://github.com/rianfowler/demp/releases/download/v${VERSION}"
BINARY_NAME="demp_${VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUM_NAME="demp_${VERSION}_checksums.txt"
SIGNATURE_NAME="${CHECKSUM_NAME}.sig"

echo "Downloading binary from ${BASE_URL}/${BINARY_NAME}"
curl -sSL -o "${BINARY_NAME}" "${BASE_URL}/${BINARY_NAME}"

echo "Downloading checksum file from ${BASE_URL}/${CHECKSUM_NAME}"
curl -sSL -o "${CHECKSUM_NAME}" "${BASE_URL}/${CHECKSUM_NAME}"

echo "Downloading signature file from ${BASE_URL}/${SIGNATURE_NAME}"
curl -sSL -o "${SIGNATURE_NAME}" "${BASE_URL}/${SIGNATURE_NAME}"

echo "Verifying GPG signature for checksum file..."
if ! gpg --list-keys "${KEY_ID}" > /dev/null 2>&1; then
  echo "Public key ${KEY_ID} not found locally; fetching from keyserver..."
  gpg --keyserver keys.openpgp.org --recv-keys "${KEY_ID}"
fi

gpg --batch --no-tty --verify "${SIGNATURE_NAME}" "${CHECKSUM_NAME}" || {
  echo "ERROR: GPG signature verification failed for ${CHECKSUM_NAME}."
  exit 1
}
echo "GPG signature verification passed."

echo "Verifying binary checksum..."
EXPECTED_CHECKSUM=$(grep "${BINARY_NAME}" "${CHECKSUM_NAME}" | awk '{print $1}')
if [ -z "$EXPECTED_CHECKSUM" ]; then
  echo "ERROR: Checksum for ${BINARY_NAME} not found in ${CHECKSUM_NAME}."
  exit 1
fi

ACTUAL_CHECKSUM=$(sha256sum "${BINARY_NAME}" | awk '{print $1}')

if [ "${EXPECTED_CHECKSUM}" != "${ACTUAL_CHECKSUM}" ]; then
  echo "ERROR: Checksum verification failed. Expected ${EXPECTED_CHECKSUM} but got ${ACTUAL_CHECKSUM}."
  exit 1
fi

echo "Checksum verification passed."

echo "Extracting binary..."
tar -xzf "${BINARY_NAME}"
chmod +x demp
sudo mv demp /usr/local/bin/demp

echo "demp ${VERSION} installed successfully!"
```

## Verifying Releases (Signatures + Checksums)

All releases of **demp** are cryptographically signed and include checksums to help you verify their authenticity and integrity. You can use both the GPG signature and the SHA256 checksum to ensure that the files were published by me and haven't been tampered with.

### 🔐 GPG Signature Verification

Each release includes a detached signature file for the checksums file (e.g., `demp_0.1.13_checksums.txt.sig`).

- **GPG Key ID:** `092017BA1C395379`
- **GPG Fingerprint:** `B3596D99AED95A4831F8E9A1092017BA1C395379`

#### Steps:

1. **Import the Public Key:**

   ```bash
   gpg --keyserver keys.openpgp.org --recv-keys 092017BA1C395379
   ```

2. **Verify the Key Fingerprint (Optional but Recommended):**

   ```bash
   gpg --fingerprint 092017BA1C395379
   ```

   You should see:

   ```
   pub   rsa4096/092017BA1C395379 2025-03-30 [SC]
         B3596D99AED95A4831F8E9A1092017BA1C395379
   uid                 [ultimate] Rian Fowler <rianf@me.com>
   ```

3. **Verify the Signature:**

   After downloading the release assets (`.tar.gz`, `.txt`, and `.sig` files), verify that the checksum file was signed with the correct GPG key:

   ```bash
   gpg --verify demp_0.1.13_checksums.txt.sig demp_0.1.13_checksums.txt
   ```

   If the signature is valid, you’ll see a message like:

   ```
   gpg: Good signature from "Rian Fowler <rianf@me.com>"
   ```

### 📦 Checksum Validation

Each release also includes a SHA256 checksum file (e.g., `demp_0.1.13_checksums.txt`) that lists hashes for all artifacts.

After verifying the GPG signature, you can verify the binary integrity:

1. **Get the expected checksum:**

   ```bash
   grep demp_0.1.13_linux_amd64.tar.gz demp_0.1.13_checksums.txt
   ```

2. **Calculate the actual checksum:**

   ```bash
   sha256sum demp_0.1.13_linux_amd64.tar.gz
   ```

3. **Compare the two values:**
   If they match, the file hasn’t been tampered with.

---

## Installing with the GitHub Action

You can easily install and test **demp** using our official GitHub Action. Just add the following step to your workflow:

```yaml
install-demp:
  name: Install and Test demp CLI
  runs-on: ubuntu-latest
  steps:
    - name: Install demp CLI
      uses: rianfowler/actions-install-demp@v0.0.3
      with:
        version: '0.1.6'
```

This action downloads the specified version of the **demp** binary (in this case, version `0.1.6`), verifies it using checksums and GPG signatures, and installs it in your environment. It's a simple way to ensure you're running a verified and secure release of the CLI as part of your CI/CD pipeline.

---

## Running demp from Docker Hub

If you prefer using containerized workflows or simply want to run **demp** in an isolated environment, you can use the official Docker image available on Docker Hub:

```bash
docker run --rm rianfowler/demp:latest <command>
```

Replace `<command>` with the desired **demp** command. For example, to display help information:

```bash
docker run --rm rianfowler/demp:latest --help
```

This approach pulls the latest verified release of **demp** from Docker Hub, ensuring a consistent environment regardless of your host OS. Use this method for quick testing or when integrating **demp** into container-based workflows.

---