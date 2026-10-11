//! `emailulator self-update`: replace this binary with the latest release.
//!
//! A release is trusted because its checksums.txt carries a minisign
//! signature from the release key, whose public half is built in below, and
//! because that signature names the release's own tag. The checksums file
//! comes from the same GitHub release as the archives, so without the
//! signature anyone able to publish a release could choose what every server
//! running this installs next.
//!
//! Downloading and unpacking use `curl` and `tar`, as install.sh does, rather
//! than an HTTP client and archive crates compiled into the server.

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use minisign_verify::{PublicKey, Signature};

/// The public half of the key that signs every release's checksums.txt. The
/// secret half stays on the machine that cuts releases; see DEVELOPMENT.md.
const RELEASE_KEY: &str = include_str!("../minisign.pub");

const REPO: &str = "webteractive/emailulator";
const BIN: &str = "emailulator";

/// Where releases are found.
pub struct Source {
    /// Answers like GitHub's "latest release" API: JSON with a `tag_name`.
    latest: String,
    /// `<downloads>/<tag>/<file>` is one of that release's files.
    downloads: String,
    https_only: bool,
}

impl Source {
    pub fn github() -> Self {
        Self {
            latest: format!("https://api.github.com/repos/{REPO}/releases/latest"),
            downloads: format!("https://github.com/{REPO}/releases/download"),
            https_only: true,
        }
    }

    /// A copy of the releases laid out as `<base>/latest` and
    /// `<base>/download/<tag>/<file>`, for testing an update end to end. The
    /// signature is checked against the same built-in key either way.
    pub fn at(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            latest: format!("{base}/latest"),
            downloads: format!("{base}/download"),
            https_only: false,
        }
    }
}

/// A release version: `major.minor.patch`, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let numbers: Vec<u64> = text
            .strip_prefix('v')
            .unwrap_or(text)
            .split('.')
            .map(|part| {
                part.parse()
                    .map_err(|_| anyhow!("`{text}` is not a release version"))
            })
            .collect::<Result<_>>()?;
        match numbers[..] {
            [major, minor, patch] => Ok(Self(major, minor, patch)),
            _ => bail!("`{text}` is not a release version"),
        }
    }

    fn tag(self) -> String {
        format!("v{self}")
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The archive a release ships for this platform, named as release.sh and the
/// release workflow name them.
pub fn archive_name(version: Version, os: &str, arch: &str) -> Result<String> {
    let platform = match (os, arch) {
        ("macos", "aarch64") => "darwin_arm64",
        ("linux", "x86_64") => "linux_amd64",
        ("linux", "aarch64") => "linux_arm64",
        _ => bail!("there is no release build for {os}/{arch}"),
    };
    Ok(format!("{BIN}_{version}_{platform}.tar.gz"))
}

/// Check checksums.txt against its signature: made by the release key, and
/// for this release. The trusted comment is signed with the file, and
/// release.sh sets it to the tag, so a genuine checksums file from an older
/// release cannot be passed off as a newer one.
pub fn verify_checksums(checksums: &[u8], signature: &str, version: Version) -> Result<()> {
    verify_signed(RELEASE_KEY, checksums, signature, version)
}

fn verify_signed(key: &str, checksums: &[u8], signature: &str, version: Version) -> Result<()> {
    let key = PublicKey::decode(key).context("reading the release key")?;
    let signature = Signature::decode(signature).context("reading checksums.txt.minisig")?;
    key.verify(checksums, &signature, false)
        .map_err(|e| anyhow!("checksums.txt is not signed by the release key: {e}"))?;
    let expected = format!("{BIN} {}", version.tag());
    if signature.trusted_comment() != expected {
        bail!(
            "checksums.txt is signed for `{}`, not `{expected}`",
            signature.trusted_comment()
        );
    }
    Ok(())
}

/// The checksum listed for `file`, from lines of `<sha256>  <file>`.
pub fn listed_checksum<'a>(checksums: &'a str, file: &str) -> Option<&'a str> {
    checksums.lines().find_map(|line| {
        let (sum, name) = line.split_once(char::is_whitespace)?;
        (name.trim_start_matches([' ', '*']) == file).then_some(sum)
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A directory of its own for the download, removed however the update ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "{BIN}-update-{}-{}",
            std::process::id(),
            crate::security::generate_token()
                .get(..8)
                .unwrap_or_default()
        ));
        fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn curl(source: &Source, url: &str, out: &Path) -> Result<()> {
    let mut command = Command::new("curl");
    command.args(["-fsSL", "--retry", "2", "--max-time", "300"]);
    if source.https_only {
        command.args(["--proto", "=https", "--tlsv1.2"]);
    }
    let status = command
        .arg("-o")
        .arg(out)
        .arg(url)
        .status()
        .context("running curl, which self-update needs")?;
    if !status.success() {
        bail!("downloading {url} failed");
    }
    Ok(())
}

fn latest(source: &Source, scratch: &Scratch) -> Result<Version> {
    let path = scratch.0.join("latest.json");
    curl(source, &source.latest, &path)?;
    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(&path)?).context("reading the latest release")?;
    let tag = json["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow!("the latest release has no tag"))?;
    Version::parse(tag)
}

/// What a run of self-update did, for its caller to report.
pub enum Outcome {
    Current(Version),
    Available {
        current: Version,
        latest: Version,
    },
    Updated {
        from: Version,
        to: Version,
        path: PathBuf,
    },
}

/// Find the latest release, and unless `check_only`, install it in place of
/// the running binary when it is newer. Never moves to an older version.
pub fn update(source: &Source, current: Version, check_only: bool) -> Result<Outcome> {
    let scratch = Scratch::new()?;
    let latest = latest(source, &scratch)?;
    if latest.cmp(&current) != Ordering::Greater {
        return Ok(Outcome::Current(current));
    }
    if check_only {
        return Ok(Outcome::Available { current, latest });
    }

    let archive = archive_name(latest, std::env::consts::OS, std::env::consts::ARCH)?;
    let base = format!("{}/{}", source.downloads, latest.tag());
    let fetch = |file: &str| -> Result<Vec<u8>> {
        let path = scratch.0.join(file);
        curl(source, &format!("{base}/{file}"), &path)?;
        fs::read(&path).with_context(|| format!("reading the downloaded {file}"))
    };

    let checksums = fetch("checksums.txt")?;
    let signature = String::from_utf8(fetch("checksums.txt.minisig")?)
        .context("checksums.txt.minisig is not text")?;
    verify_checksums(&checksums, &signature, latest)?;
    let checksums = String::from_utf8(checksums).context("checksums.txt is not text")?;
    let expected = listed_checksum(&checksums, &archive)
        .ok_or_else(|| anyhow!("checksums.txt has no entry for {archive}"))?;
    let bytes = fetch(&archive)?;
    if sha256_hex(&bytes) != expected {
        bail!("{archive} does not match its signed checksum");
    }

    let unpacked = scratch.0.join("unpacked");
    fs::create_dir(&unpacked)?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(scratch.0.join(&archive))
        .arg("-C")
        .arg(&unpacked)
        .arg(BIN)
        .status()
        .context("running tar, which self-update needs")?;
    if !status.success() {
        bail!("unpacking {archive} failed");
    }
    let new = unpacked.join(BIN);

    // The archive is signed, but make sure it holds the release it says it is
    // before it replaces anything.
    let output = Command::new(&new)
        .arg("--version")
        .output()
        .context("running the downloaded binary")?;
    let reported = String::from_utf8_lossy(&output.stdout);
    let wanted = format!("{BIN} {latest}");
    if !output.status.success()
        || !(reported.trim() == wanted || reported.starts_with(&format!("{wanted} ")))
    {
        bail!(
            "the downloaded binary reports `{}`, not {wanted}",
            reported.trim()
        );
    }

    let target = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .context("finding this binary")?;
    install(&new, &target)?;
    Ok(Outcome::Updated {
        from: current,
        to: latest,
        path: target,
    })
}

/// Put `new` where `target` is, in one rename: a running server keeps the
/// file it started from, and nothing ever sees half a binary.
fn install(new: &Path, target: &Path) -> Result<()> {
    let dir = target
        .parent()
        .ok_or_else(|| anyhow!("{} has no directory", target.display()))?;
    let staged = dir.join(format!(".{BIN}.update.{}", std::process::id()));
    let result = (|| {
        fs::copy(new, &staged)
            .with_context(|| format!("writing to {}; is it writable?", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        }
        fs::rename(&staged, target).with_context(|| format!("replacing {}", target.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

/// Ask this user's running `emailulator run` servers to stop, so whatever
/// supervises them (a Forge daemon, systemd) starts them on the new binary.
/// Returns whether any was running.
pub fn restart_servers() -> Result<bool> {
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .context("running id")?;
    let uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
    let status = Command::new("pkill")
        .args(["-TERM", "-u", &uid, "-f", &format!("(^|/){BIN} run( |$)")])
        .status()
        .context("running pkill")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("pkill could not signal the running server"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_order() {
        assert_eq!(Version::parse("v0.1.2").unwrap(), Version(0, 1, 2));
        assert_eq!(Version::parse("1.10.0").unwrap(), Version(1, 10, 0));
        assert!(Version::parse("v1.10.0").unwrap() > Version::parse("v1.9.9").unwrap());
        for bad in ["", "v1", "1.2", "1.2.3.4", "1.2.x", "1.2.3-beta.1"] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Version(0, 1, 2).tag(), "v0.1.2");
    }

    #[test]
    fn archives_are_named_as_releases_name_them() {
        let v = Version(0, 2, 0);
        assert_eq!(
            archive_name(v, "macos", "aarch64").unwrap(),
            "emailulator_0.2.0_darwin_arm64.tar.gz"
        );
        assert_eq!(
            archive_name(v, "linux", "x86_64").unwrap(),
            "emailulator_0.2.0_linux_amd64.tar.gz"
        );
        assert_eq!(
            archive_name(v, "linux", "aarch64").unwrap(),
            "emailulator_0.2.0_linux_arm64.tar.gz"
        );
        assert!(archive_name(v, "macos", "x86_64").is_err());
        assert!(archive_name(v, "windows", "x86_64").is_err());
    }

    #[test]
    fn checksums_are_found_by_file_name() {
        let listing = "aaa  emailulator_0.2.0_darwin_arm64.tar.gz\n\
                       bbb  emailulator_0.2.0_linux_amd64.tar.gz\n\
                       ccc *emailulator_0.2.0_linux_arm64.tar.gz\n";
        assert_eq!(
            listed_checksum(listing, "emailulator_0.2.0_linux_amd64.tar.gz"),
            Some("bbb")
        );
        assert_eq!(
            listed_checksum(listing, "emailulator_0.2.0_linux_arm64.tar.gz"),
            Some("ccc")
        );
        assert_eq!(listed_checksum(listing, "emailulator_0.2.0_linux"), None);
    }

    #[test]
    fn the_release_key_is_readable() {
        PublicKey::decode(RELEASE_KEY).unwrap();
    }

    // A throwaway key pair, made with `minisign -G -W` for these tests only,
    // and checksums.txt as release.sh would sign it for v0.2.0.
    const TEST_KEY: &str = "untrusted comment: minisign public key 2F33BCEBDA3A4EFC\n\
        RWT8Tjra67wzLzKimI1TqoeggECMs/FWYElrsggLg/Y0A9u1uVT+l5KR\n";
    const TEST_CHECKSUMS: &[u8] = b"abc123  emailulator_0.2.0_linux_amd64.tar.gz\n";
    const TEST_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\n\
        RUT8Tjra67wzL+YGGvd8EjTdXQRKJAuX9QybRXKBb3xzncROTwbgPaajolmC3DBKL/kzHY+bp4bvcfaWXn6491s1xwPQanYY9wM=\n\
        trusted comment: emailulator v0.2.0\n\
        IgiXE7vUvYyO+oLKwtZo+zJhAo/momVlurVJUKFeG6jP5e28+saorU6yM1DN7I7Vbyebrq3PMkeDaHbKQztUDQ==\n";

    #[test]
    fn signed_checksums_for_their_own_release_pass() {
        verify_signed(TEST_KEY, TEST_CHECKSUMS, TEST_SIGNATURE, Version(0, 2, 0)).unwrap();
    }

    #[test]
    fn a_signature_for_another_release_is_refused() {
        // Genuine, but for v0.2.0: it cannot vouch for a release called v0.3.0.
        let error =
            verify_signed(TEST_KEY, TEST_CHECKSUMS, TEST_SIGNATURE, Version(0, 3, 0)).unwrap_err();
        assert!(error.to_string().contains("signed for"), "{error:#}");
    }

    #[test]
    fn altered_checksums_are_refused() {
        let altered = b"evil00  emailulator_0.2.0_linux_amd64.tar.gz\n";
        assert!(verify_signed(TEST_KEY, altered, TEST_SIGNATURE, Version(0, 2, 0)).is_err());
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        // The test key's signature, checked against the real release key.
        let error = verify_checksums(TEST_CHECKSUMS, TEST_SIGNATURE, Version(0, 2, 0)).unwrap_err();
        assert!(error.to_string().contains("release key"), "{error:#}");
    }
}
