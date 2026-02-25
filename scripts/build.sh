#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="${1:-dev}"
LDFLAGS="-s -w -X github.com/dominikschlosser/ssi-debugger/cmd.Version=${VERSION}"

echo "Building ssi-debugger ${VERSION}..."
go build -ldflags "$LDFLAGS" -o ssi-debugger .
echo "Done: ./ssi-debugger"

# Detect current shell and install completions
CURRENT_SHELL="$(basename "$SHELL")"
BINARY="${PROJECT_DIR}/ssi-debugger"

case "$CURRENT_SHELL" in
  zsh)
    COMP_DIR="${HOME}/.zsh/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion zsh > "$COMP_DIR/_ssi-debugger"
    echo "Installed zsh completions to $COMP_DIR/_ssi-debugger"
    echo "Run 'source $COMP_DIR/_ssi-debugger' or add $COMP_DIR to your fpath and restart your shell."
    ;;
  bash)
    COMP_DIR="${HOME}/.local/share/bash-completion/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion bash > "$COMP_DIR/ssi-debugger"
    echo "Installed bash completions to $COMP_DIR/ssi-debugger"
    echo "Run 'source $COMP_DIR/ssi-debugger' or restart your shell."
    ;;
  fish)
    COMP_DIR="${HOME}/.config/fish/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion fish > "$COMP_DIR/ssi-debugger.fish"
    echo "Installed fish completions to $COMP_DIR/ssi-debugger.fish"
    ;;
  *)
    echo "Unknown shell '$CURRENT_SHELL', skipping completion installation."
    ;;
esac
