//! Stamps the binary with the commit it was built from, so `--version` can tell
//! a release from a local build of the same version number.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (output.status.success() && !text.is_empty()).then(|| text.to_string())
}

fn main() {
    // A container build has no .git; it passes these in instead.
    println!("cargo:rerun-if-env-changed=EMAILULATOR_GIT_SHA");
    println!("cargo:rerun-if-env-changed=EMAILULATOR_GIT_DATE");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let from_env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let sha = from_env("EMAILULATOR_GIT_SHA").or_else(|| git(&["rev-parse", "--short", "HEAD"]));
    let date = from_env("EMAILULATOR_GIT_DATE").or_else(|| git(&["log", "-1", "--format=%cs"]));

    let version = env!("CARGO_PKG_VERSION");
    let stamped = match (sha, date) {
        (Some(sha), Some(date)) => format!("{version} ({sha}, {date})"),
        (Some(sha), None) => format!("{version} ({sha})"),
        _ => version.to_string(),
    };
    println!("cargo:rustc-env=EMAILULATOR_VERSION={stamped}");
}
