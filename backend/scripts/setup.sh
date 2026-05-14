#!/usr/bin/env bash
# Install security tools for AutoPentest (runs inside the container)
set -euo pipefail

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

echo "==> Installing security tools (OS=$OS ARCH=$ARCH)"

# Nuclei
NUCLEI_VERSION="3.2.4"
echo "  Installing nuclei $NUCLEI_VERSION..."
wget -qO /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${OS}_${ARCH}.zip"
unzip -qo /tmp/nuclei.zip -d /usr/local/bin/
rm /tmp/nuclei.zip
nuclei -version

# ffuf
FFUF_VERSION="2.1.0"
echo "  Installing ffuf $FFUF_VERSION..."
wget -qO /tmp/ffuf.tar.gz \
    "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf
rm /tmp/ffuf.tar.gz
ffuf -V

# Katana
KATANA_VERSION="1.1.0"
echo "  Installing katana $KATANA_VERSION..."
wget -qO /tmp/katana.zip \
    "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_${OS}_${ARCH}.zip"
unzip -qo /tmp/katana.zip -d /usr/local/bin/
rm /tmp/katana.zip
katana -version

# TruffleHog
TRUFFLEHOG_VERSION="3.79.0"
echo "  Installing trufflehog $TRUFFLEHOG_VERSION..."
wget -qO /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin/ trufflehog
rm /tmp/trufflehog.tar.gz
trufflehog --version

# Semgrep (Python)
echo "  Installing semgrep..."
pip install --quiet semgrep
semgrep --version

# pip-audit (Python)
echo "  Installing pip-audit..."
pip install --quiet pip-audit
pip-audit --version

echo "==> All security tools installed successfully"
