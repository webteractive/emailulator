# Developing emailulator

## Build and test

```sh
cargo test                           # the server
cargo test --features desktop        # plus the desktop app's own tests
cargo clippy --all-targets -- -D warnings
cargo deny check                     # licenses, sources, advisories, banned crates
cargo run -- run                     # the server from source
cargo run --features desktop -- app  # the desktop app from source
```

`./install.sh --source` builds a release binary with cargo and installs it in
place of a downloaded one. The desktop app is behind the `desktop` feature:
`cargo build --release --features desktop`. The Linux release leaves it out,
because a binary that links the windowing system cannot start on a headless host.

## Toolchain

`rust-toolchain.toml` pins the Rust version for every build: this machine, CI,
the release workflow's Linux archives and the macOS archive `scripts/package.sh`
signs. rustup fetches it on first use. To upgrade, change it and the
Dockerfile's base image together, and let CI check it.

The release workflow's runner images are pinned for the same reason. CI runs on
`ubuntu-latest`, so a new image shows up there before a release is built on it.

## Web UI

`ui/` is plain HTML, CSS and one ES module: no build step. In a debug build it
is read from disk on every request, so an edit needs only a reload; a release
build embeds it.

## Desktop app

The app is the web UI in a tao window, shown by wry, with a muda menu bar. It
runs the SMTP and HTTP servers in process and its webview may load only that
server.

It can test itself against a real window: set `EMAILULATOR_APP_SELFTEST=1` and
run `emailulator app --foreground` with a scratch `--data-dir`. It delivers a
message through its own API, waits for the window to show it, and exits non-zero
if it does not within 30 seconds. `scripts/package.sh` runs this against the
signed binary.

## Client-check data

The client check uses [caniemail.com](https://www.caniemail.com)'s data (MIT
licensed), bundled into the binary from `data/caniemail.json`. To refresh it:

```sh
curl -o data/caniemail.json https://www.caniemail.com/api/data.json
```

## Third-party licenses

Every release archive carries `LICENSE` and `THIRD_PARTY_LICENSES.md`, the
notices of the crates compiled into the binary and of the caniemail data. After
any change to `Cargo.lock`, regenerate it and commit the result:

```sh
scripts/licenses.sh           # needs cargo-about: brew install cargo-about
```

It is generated offline from `Cargo.lock` with `about.toml` and `about.hbs`, so
it is reproducible. CI fails when it is out of date, and so does
`scripts/package.sh` before it builds anything.

## Releasing

```sh
scripts/release.sh patch      # or minor, major, X.Y.Z, or `current` for no bump
```

A release is assembled from two places, and the script drives both:

- **macOS** is built on a Mac by `scripts/package.sh`: Developer ID signed with
  the hardened runtime, self-tested, and notarized. It needs the "Developer ID
  Application" certificate in the keychain and a notarytool keychain profile
  named `notary`; `scripts/package.sh --preflight` checks both, and the release
  script runs that before it changes anything.
- **Linux** is built by the release workflow when the tag is pushed, and left on
  a draft release.

The script then adds the macOS archive and a `checksums.txt` covering all three
archives, and publishes. Until then the release is a draft, which `install.sh`
cannot see, so a half-assembled release is never installable.

Afterwards, install what was published and check it:

```sh
./install.sh && emailulator --version
rm -rf dist target/release
```
