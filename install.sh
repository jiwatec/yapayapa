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
      x86_64) echo "Intel Macs have no prebuilt binary — build from source (see the README)."; exit 1 ;;
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
    echo "$INSTALL_DIR is not on your PATH yet — adding it for you."
    line="export PATH=\"$INSTALL_DIR:\$PATH\""
    updated=""
    case "$(basename "${SHELL:-bash}")" in
      fish)
        # Universal path persists across sessions without editing config.
        if command -v fish >/dev/null 2>&1 && fish -c "fish_add_path -U $INSTALL_DIR" 2>/dev/null; then
          updated="fish (universal path)"
        else
          rc="$HOME/.config/fish/config.fish"
          mkdir -p "$(dirname "$rc")"
          grep -qsF "$INSTALL_DIR" "$rc" || printf '\nfish_add_path %s\n' "$INSTALL_DIR" >> "$rc"
          updated="$rc"
        fi
        ;;
      zsh)
        rc="$HOME/.zshrc"
        grep -qsF "$INSTALL_DIR" "$rc" || printf '\n%s\n' "$line" >> "$rc"
        updated="$rc"
        ;;
      *)
        rc="$HOME/.bashrc"; [ -f "$rc" ] || rc="$HOME/.profile"
        grep -qsF "$INSTALL_DIR" "$rc" || printf '\n%s\n' "$line" >> "$rc"
        updated="$rc"
        ;;
    esac
    echo "Updated $updated."
    echo
    echo "Open a new terminal (or run 'source $updated'), then:  yapayapa register"
    echo "Or run it right now without restarting:  $INSTALL_DIR/$BIN register"
    ;;
esac
