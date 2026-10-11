#!/bin/sh
# Packages the macOS build of emailulator into
# dist/emailulator_<version>_darwin_arm64.tar.gz: an optimized build with the
# desktop app compiled in, Developer ID signed with the hardened runtime and
# notarized, so it runs with no Gatekeeper override and keeps one identity
# across updates.
#
# This runs on a Mac rather than in CI because the signing certificate lives in
# a keychain. Signing reads nothing from this repo, secret or personal: the
# identity is the one "Developer ID Application" certificate in the keychain,
# found at run time, and notarytool authenticates through a keychain profile
# (created once with `xcrun notarytool store-credentials <profile>`). Override
# either with EMAILULATOR_SIGN_IDENTITY (a name or SHA-1 hash) /
# EMAILULATOR_NOTARY_PROFILE.
#
# Usage:
#   scripts/package.sh              build, sign, self-test, notarize, verify the ticket
#   scripts/package.sh --preflight  only check the identity and notary profile
#   scripts/package.sh --adhoc      ad-hoc signed and NOT notarized: for a
#                                   machine without the certificate; never ship it
set -eu
cd "$(dirname "$0")/.."

SIGN_IDENTITY=${EMAILULATOR_SIGN_IDENTITY:-}
NOTARY_PROFILE=${EMAILULATOR_NOTARY_PROFILE:-notary}
# Stable across releases, so macOS treats every version as the same program.
IDENTIFIER=com.webteractive.emailulator

MODE=release
case "${1:-}" in
  "") ;;
  --preflight) MODE=preflight ;;
  --adhoc) MODE=adhoc ;;
  -h|--help) sed -n '2,/^set -eu/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
  *) echo "usage: scripts/package.sh [--preflight | --adhoc]" >&2; exit 2 ;;
esac

die() { printf '%s\n' "error: $*" >&2; exit 1; }

# Checked before anything builds: release.sh runs this ahead of its version
# bump, so a missing certificate or profile stops it before it changes anything.
preflight() {
  if [ -n "$SIGN_IDENTITY" ]; then
    security find-identity -v -p codesigning | grep -qF "$SIGN_IDENTITY" \
      || die "EMAILULATOR_SIGN_IDENTITY is not a valid signing identity in the keychain"
  else
    # Signed by SHA-1 hash, not name: a renewed certificate keeps its name, and
    # codesign refuses a name two valid certificates share.
    found=$(security find-identity -v -p codesigning | grep '"Developer ID Application: ' || true)
    case $(printf '%s' "$found" | grep -c . || true) in
      0) die "no valid \"Developer ID Application\" certificate in the keychain" ;;
      1) SIGN_IDENTITY=$(printf '%s' "$found" | awk '{print $2}') ;;
      *) die "several Developer ID Application certificates — pick one with EMAILULATOR_SIGN_IDENTITY=<hash>" ;;
    esac
  fi
  xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 \
    || die "notary keychain profile '$NOTARY_PROFILE' is missing or rejected — run: xcrun notarytool store-credentials $NOTARY_PROFILE"
}

# Submits one file and waits, leaving the submission id in NOTARY_ID.
# notarytool exits 0 for an Invalid verdict too, so the status is read from its
# JSON, and a rejection prints Apple's log.
notarize() {
  out=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" \
    --wait --output-format json) || die "notarytool submit failed for $1"
  NOTARY_ID=$(printf '%s' "$out" | plutil -extract id raw -o - -)
  status=$(printf '%s' "$out" | plutil -extract status raw -o - -)
  if [ "$status" != "Accepted" ]; then
    xcrun notarytool log "$NOTARY_ID" --keychain-profile "$NOTARY_PROFILE" >&2 || true
    die "notarization ended '$status' (submission $NOTARY_ID)"
  fi
  echo "notarized ($NOTARY_ID)"
}

if [ "$MODE" = preflight ]; then
  preflight
  echo "signing ready: identity $SIGN_IDENTITY, notary profile '$NOTARY_PROFILE'"
  exit 0
fi

[ "$(uname -s)" = Darwin ] || die "this packages the macOS build; the Linux archives come from the release workflow"
# arm64 only: nobody is known to run this on an Intel Mac. Building universal
# would mean a second target here and a second archive in install.sh.
[ "$(uname -m)" = arm64 ] || die "the macOS release is arm64; run this on Apple silicon"
if [ "$MODE" = release ]; then preflight; fi

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"

cargo build --release --locked --features desktop

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
BIN="$STAGE/emailulator"
cp target/release/emailulator "$BIN"

# Checked on the built file, not the build flags.
archs=$(lipo -archs "$BIN")
[ "$archs" = arm64 ] || die "built for '$archs', expected arm64"
case "$("$BIN" --version)" in
  "emailulator $VERSION"*) ;;
  *) die "the build reports '$("$BIN" --version)', expected version $VERSION" ;;
esac

if [ "$MODE" = release ]; then
  codesign --force --timestamp --options runtime --identifier "$IDENTIFIER" \
    --sign "$SIGN_IDENTITY" "$BIN"
else
  codesign --force --identifier "$IDENTIFIER" --sign - "$BIN"
fi
codesign --verify --strict --verbose=2 "$BIN"

# The hardened runtime restricts what a process may load, and the desktop app
# brings up Metal and the system webview. Prove the signed binary still opens a
# message before asking Apple to notarize it. Ephemeral ports, scratch store.
echo "==> self-testing the signed binary"
EMAILULATOR_APP_SELFTEST=1 "$BIN" app --foreground \
  --smtp-addr 127.0.0.1:0 --http-addr 127.0.0.1:0 --data-dir "$STAGE/data" \
  || die "the signed binary failed its self-test"

if [ "$MODE" = release ]; then
  # A bare executable cannot be stapled. It is notarized inside a zip, and
  # Gatekeeper fetches the ticket online the first time it needs it.
  echo "==> notarizing"
  ditto -c -k "$BIN" "$STAGE/emailulator.zip"
  notarize "$STAGE/emailulator.zip"

  # With nothing stapled, `spctl` and `codesign -R notarized` both report an
  # unnotarized binary however the submission went: they read a stapled ticket
  # and there is none to read. What can be checked is that the ticket Apple
  # issued names this exact binary, by its code directory hash.
  ticket=$(xcrun notarytool log "$NOTARY_ID" --keychain-profile "$NOTARY_PROFILE" \
    | plutil -extract ticketContents.0.cdhash raw -o - -) \
    || die "could not read the notarization ticket for submission $NOTARY_ID"
  cdhash=$(codesign -dvvv "$BIN" 2>&1 | sed -n 's/^CDHash=//p')
  [ -n "$cdhash" ] && [ "$ticket" = "$cdhash" ] \
    || die "Apple's ticket is for $ticket, but the signed binary is $cdhash"
  echo "ticket matches the signed binary ($cdhash)"
fi

# The archive is written last, from the exact file that was signed and checked.
mkdir -p dist
ARCHIVE="dist/emailulator_${VERSION}_darwin_arm64.tar.gz"
tar -czf "$ARCHIVE" -C "$STAGE" emailulator

if [ "$MODE" = adhoc ]; then
  echo "Packaged $ARCHIVE ($("$BIN" --version)) — AD-HOC, not notarized: do not ship"
else
  echo "Packaged $ARCHIVE ($("$BIN" --version)) — Developer ID signed, notarized"
fi
