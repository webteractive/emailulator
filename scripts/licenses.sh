#!/bin/sh
# Writes THIRD_PARTY_LICENSES.md, the notices every release archive carries:
# the licenses of the crates compiled into the binary (from cargo-about, with
# about.toml and about.hbs) and of the bundled caniemail.com data.
#
#   scripts/licenses.sh          regenerate it; run after any Cargo.lock change
#   scripts/licenses.sh --check  fail if it no longer matches (CI does this)
#
# Generated offline (--frozen), from the license files each crate packages, so
# the same Cargo.lock always gives the same file. Needs cargo-about:
# `brew install cargo-about` or `cargo install --locked cargo-about --features cli`.
set -eu
cd "$(dirname "$0")/.."

OUT=THIRD_PARTY_LICENSES.md

die() { printf '%s\n' "error: $*" >&2; exit 1; }

command -v cargo-about >/dev/null 2>&1 \
  || die "cargo-about is required: brew install cargo-about, or cargo install --locked cargo-about --features cli"

generate() {
  cargo about generate --frozen --all-features --fail about.hbs
  printf '## caniemail.com data\n\nThe client-support data in data/caniemail.json, from https://www.caniemail.com.\n\n```\n'
  cat data/caniemail.LICENSE
  printf '```\n'
}

# --frozen reads only crates already downloaded.
cargo fetch --locked >/dev/null 2>&1 || die "cargo fetch failed"

case "${1:-}" in
  --check)
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    generate > "$tmp"
    cmp -s "$tmp" "$OUT" \
      || die "$OUT does not match Cargo.lock — run scripts/licenses.sh and commit the result"
    echo "$OUT is up to date"
    ;;
  "")
    generate > "$OUT"
    echo "wrote $OUT"
    ;;
  *) die "usage: scripts/licenses.sh [--check]" ;;
esac
