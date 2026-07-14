//! Binary-level regression coverage for absolute Cargo install paths (#219).

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set test permissions");
}

#[test]
#[cfg(unix)]
fn cargo_bin_absolute_hook_registration_is_accepted() {
    let temp = TempDir::new().expect("create isolated home");
    set_mode(temp.path(), 0o700);

    let cargo_bin = temp.path().join(".cargo").join("bin");
    fs::create_dir_all(&cargo_bin).expect("create cargo bin");
    set_mode(&cargo_bin, 0o700);
    let installed = cargo_bin.join("contextcrawler");
    fs::copy(binary_path(), &installed).expect("copy cargo-installed binary fixture");
    set_mode(&installed, 0o700);

    let claude_dir = temp.path().join(".claude");
    fs::create_dir(&claude_dir).expect("create Claude config directory");
    set_mode(&claude_dir, 0o700);
    let settings = claude_dir.join("settings.json");
    let root = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook claude", installed.display())
                }]
            }]
        }
    });
    fs::write(
        &settings,
        serde_json::to_vec_pretty(&root).expect("serialize settings fixture"),
    )
    .expect("write settings fixture");
    set_mode(&settings, 0o600);

    // The registration identity hashes only the OWNED (matcher, command)
    // tuples for `type == "command"` hooks, sorted and serialised as JSON
    // (#234 round-2) — not the whole PreToolUse surface. Mirror that here.
    let command = format!("{} hook claude", installed.display());
    let bindings: Vec<(&str, &str)> = vec![("Bash", command.as_str())];
    let surface = serde_json::to_vec(&bindings).expect("serialize registration identity material");
    let hash = format!("{:x}", Sha256::digest(surface));
    let identity_dir = temp.path().join("data").join("ctxcrl");
    fs::create_dir_all(&identity_dir).expect("create identity directory");
    set_mode(temp.path().join("data").as_path(), 0o700);
    set_mode(&identity_dir, 0o700);
    let identity = identity_dir.join("claude-hook-registration.sha256");
    fs::write(&identity, format!("{hash}  settings.json:PreToolUse\n"))
        .expect("write registration identity");
    set_mode(&identity, 0o600);

    let output = Command::new(binary_path())
        .arg("verify")
        .env("HOME", temp.path())
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("RTK_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run contextcrawler verify");

    assert!(
        output.status.success(),
        "Cargo-bin registration should verify: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("PASS  native binary hook registration verified"));
}
