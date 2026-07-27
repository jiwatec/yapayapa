#!/usr/bin/env bash
# YapaYapa installer: downloads the right prebuilt client binary from the
# latest GitHub Release and drops it in ~/.local/bin. No Rust needed.
#
#   curl -fsSL https://raw.githubusercontent.com/jiwatec/yapayapa/main/install.sh | bash
#
set -euo pipefail

REPO="jiwatec/yapayapa"
BIN="yapayapa"
INSTALL_DIR="${YAPAYAPA_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) asset="yapayapa-linux-x86_64" ;;
      *) echo "No prebuilt Linux binary for '$arch'. Build from source instead."; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      arm64 | aarch64) asset="yapayapa-macos-aarch64" ;;
      x86_64) asset="yapayapa-macos-x86_64" ;;
      *) echo "No prebuilt macOS binary for '$arch'."; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $os."
    echo "On Windows, download yapayapa-windows-x86_64.exe from:"
    echo "  https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

url="https://github.com/$REPO/releases/latest/download/$asset"
tmp="$(mktemp)"

echo "Downloading $asset ..."
if command -v curl >/dev/null 2>&1; then
  curl -fSL "$url" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$tmp" "$url"
else
  echo "Need curl or wget installed."; exit 1
fi

mkdir -p "$INSTALL_DIR"
mv "$tmp" "$INSTALL_DIR/$BIN"
chmod +x "$INSTALL_DIR/$BIN"

echo "Installed yapayapa -> $INSTALL_DIR/$BIN"

# Make sure it's runnable as a bare command.
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    echo
    echo "Done! Get started with:"
    echo "  yapayapa register"
    ;;
  *)
    echo
    echo "NOTE: $INSTALL_DIR is not on your PATH yet. Add it:"
    echo "  bash/zsh:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.profile && source ~/.profile"
    echo "  fish:      fish_add_path ~/.local/bin"
    echo
    echo "Then run:  yapayapa register"
    echo "(or run it directly right now: $INSTALL_DIR/$BIN register)"
    ;;
esac
