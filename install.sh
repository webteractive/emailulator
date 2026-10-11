#!/bin/sh
# emailulator installer.
#
# Default — download a prebuilt binary. No Rust toolchain required:
#   curl -fsSL https://raw.githubusercontent.com/webteractive/emailulator/main/install.sh | sh
#
# From a local checkout, build from source instead (requires cargo):
#   ./install.sh --source
#
# Environment:
#   EMAILULATOR_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   EMAILULATOR_VERSION      install this release instead of the latest, e.g. 0.1.0
#   EMAILULATOR_BASE_URL     fetch the release files from here instead of GitHub
set -eu

REPO="webteractive/emailulator"
BIN="emailulator"
INSTALL_DIR="${EMAILULATOR_INSTALL_DIR:-$HOME/.local/bin}"
MODE="release"

err() { printf '%s-install: %s\n' "$BIN" "$1" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --source) MODE="source" ;;
    --release) MODE="release" ;;
    -h | --help)
      printf 'Usage: install.sh [--source|--release]\n\n'
      printf '  --release  download a prebuilt binary (default; no Rust required)\n'
      printf '  --source   build from the local checkout (requires cargo)\n'
      exit 0
      ;;
    *) err "unknown option '$arg' — see --help" ;;
  esac
done

# Put a file in place with a rename, so a running copy is replaced whole rather
# than overwritten underneath itself.
place() {
  mkdir -p "$INSTALL_DIR"
  cp "$1" "$INSTALL_DIR/.$2.new.$$"
  chmod 755 "$INSTALL_DIR/.$2.new.$$"
  mv -f "$INSTALL_DIR/.$2.new.$$" "$INSTALL_DIR/$2"
}

finish() {
  printf 'Installed %s to %s/%s\n' "$("$INSTALL_DIR/$BIN" --version)" "$INSTALL_DIR" "$BIN"
  printf '\n  %s run    start the SMTP and HTTP servers\n' "$BIN"
  # The macOS build has the desktop app compiled in; the Linux build is the
  # server alone.
  if [ "$os" = "darwin" ]; then
    printf '  %s app    open the desktop app\n' "$BIN"
  fi
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) printf '\nNote: %s is not on your PATH. Add it to your shell profile:\n  export PATH="%s:$PATH"\n' \
         "$INSTALL_DIR" "$INSTALL_DIR" ;;
  esac
}

os=$(uname -s | tr '[:upper:]' '[:lower:]')

# --- source build -----------------------------------------------------------
# Only useful from inside a clone; the release path is what a fresh machine uses.
if [ "$MODE" = "source" ]; then
  command -v cargo >/dev/null 2>&1 || err "cargo is required for --source; omit the flag to download a prebuilt binary"
  if [ ! -f Cargo.toml ] || [ ! -d src/desktop ]; then
    err "--source must be run from the root of an emailulator checkout"
  fi

  # The desktop app needs a windowing stack to build; macOS has one built in.
  if [ "$os" = "darwin" ]; then
    cargo build --release --locked --features desktop
  else
    cargo build --release --locked
  fi
  place "target/release/$BIN" "$BIN"
  finish
  exit 0
fi

# --- prebuilt release -------------------------------------------------------
command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"

case "$os" in
  darwin | linux) ;;
  *) err "unsupported OS '$os' — prebuilt binaries exist for darwin and linux only" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) err "unsupported architecture '$arch'" ;;
esac
if [ "$os" = "darwin" ] && [ "$arch" = "amd64" ]; then
  err "there is no prebuilt binary for Intel Macs — build one from a checkout with ./install.sh --source"
fi

if [ -n "${EMAILULATOR_VERSION:-}" ]; then
  tag="v${EMAILULATOR_VERSION#v}"
else
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$tag" ] || err "could not determine the latest release tag — has a version been tagged yet?"
fi
ver="${tag#v}"

file="${BIN}_${ver}_${os}_${arch}.tar.gz"
base="${EMAILULATOR_BASE_URL:-https://github.com/$REPO/releases/download/$tag}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'Downloading %s %s (%s/%s)...\n' "$BIN" "$tag" "$os" "$arch"
curl -fsSL "$base/$file" -o "$tmp/$file" || err "download failed: $base/$file"

# The checksum is not optional: this is a program that will hold credentials
# and captured mail, and it is about to be put on PATH.
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || err "download failed: $base/checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then sha='sha256sum'
elif command -v shasum >/dev/null 2>&1; then sha='shasum -a 256'
else err "sha256sum or shasum is required to verify the download"; fi
want=$(grep " ${file}\$" "$tmp/checksums.txt" | awk '{print $1}')
got=$($sha "$tmp/$file" | awk '{print $1}')
[ -n "$want" ] || err "checksums.txt has no entry for $file"
[ "$want" = "$got" ] || err "checksum mismatch for $file"
printf 'Checksum OK.\n'

mkdir "$tmp/unpacked"
tar -xzf "$tmp/$file" -C "$tmp/unpacked" || err "failed to unpack $file"
[ -f "$tmp/unpacked/$BIN" ] || err "$file does not contain $BIN"

place "$tmp/unpacked/$BIN" "$BIN"
finish
