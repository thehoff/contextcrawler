//! Security regression tests for the legacy shell hook `hooks/claude/rtk-rewrite.sh`.
//!
//! These drive the actual bash script with crafted PreToolUse payloads and
//! assert the fail-closed / passthrough behaviour the council flagged across
//! three review rounds (#2493). They mirror the Rust `hook claude` path's
//! `resolve_claude_command` unit tests in `src/hooks/hook_cmd.rs` — the two
//! entry paths must agree.
//!
//! Dependencies: the thin hook delegates to the Rust binary, so the tests need
//! `bash` + `contextcrawler` on `PATH`. The script's first action is a
//! `command -v contextcrawler` guard that exits 0 if the binary is absent, so
//! without it the fail-closed paths would never be reached. If a dependency is
//! missing the tests SKIP (return) rather than fail, so a bare CI checkout
//! without an installed binary stays green. Unix-gated (the hook is bash).
#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

fn tool_on_path(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// True when every dependency the script needs is available. The thin hook
/// delegates to the Rust binary, so it needs `bash` + `contextcrawler` (no jq).
fn deps_present() -> bool {
    tool_on_path("bash") && tool_on_path("contextcrawler")
}

/// Run the shell hook with `payload` on stdin; return (stdout, exit_code).
fn run_hook(payload: &str) -> (String, i32) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/hooks/claude/rtk-rewrite.sh");
    let mut child = Command::new("bash")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn bash hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

fn is_deny(stdout: &str) -> bool {
    stdout.contains("\"permissionDecision\":\"deny\"")
}

/// Assert `payload` fails closed (deny), skipping if deps are missing.
fn assert_denies(payload: &str) {
    if !deps_present() {
        eprintln!("skipping: bash/jq/contextcrawler not all on PATH");
        return;
    }
    let (out, code) = run_hook(payload);
    assert_eq!(code, 0, "hook must exit 0 (verdict via JSON, not exit code)");
    assert!(is_deny(&out), "payload must deny, got: {out}");
}

/// Assert `payload` passes through silently (no verdict), skipping if deps missing.
fn assert_passes_through(payload: &str) {
    if !deps_present() {
        eprintln!("skipping: bash/jq/contextcrawler not all on PATH");
        return;
    }
    let (out, code) = run_hook(payload);
    assert_eq!(code, 0);
    assert!(out.trim().is_empty(), "must be silent passthrough, got: {out}");
}

#[test]
fn malformed_json_fails_closed() {
    assert_denies("not json at all {{{");
}

#[test]
fn non_object_root_passes_through() {
    // A non-object JSON root (scalar/array) cannot carry a tool command, so
    // there is nothing to gate and no bypass is possible — the Rust handler
    // safely Ignores it (passthrough). This is the delegated single-source-of-
    // truth behaviour; the bypass risk lives only in object payloads that carry
    // a command, which are covered by the deny tests above.
    assert_passes_through("42");
    assert_passes_through(r#""just a string""#);
    assert_passes_through("[1,2,3]");
}

#[test]
fn non_string_command_fails_closed() {
    assert_denies(r#"{"tool_name":"Bash","tool_input":{"command":12345}}"#);
}

#[test]
fn inactive_schema_non_string_command_fails_closed() {
    // Active (legacy Bash) command is a valid string, but the inactive schema
    // hides a non-string — must still deny.
    assert_denies(
        r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"input":{"command":123}}"#,
    );
}

#[test]
fn mismatched_dual_schema_fails_closed() {
    // The first exploit: a dangerous input.command plus a stale benign
    // tool_input.command must not gate/allow the benign one.
    assert_denies(
        r#"{"tool":"Bash","tool_input":{"command":"echo safe"},"input":{"command":"rm -rf /x"}}"#,
    );
}

#[test]
fn conflicting_discriminators_fail_closed() {
    // Council round 3: legacy tool_name=Read (non-Bash) hiding a live Bash
    // command on the new schema must fail closed, not passthrough.
    assert_denies(r#"{"tool_name":"Read","tool":"Bash","input":{"command":"rm -rf /"}}"#);
}

#[test]
fn unmodeled_command_container_fails_closed() {
    // Command hidden in a non-Claude-Code container must not slip through.
    assert_denies(r#"{"tool":"Bash","parameters":{"command":"rm -rf /"}}"#);
    assert_denies(r#"{"tool_name":"Bash","arguments":{"command":"rm -rf /"}}"#);
}

#[test]
fn non_bash_tool_with_command_fails_closed() {
    // Non-Bash discriminator carrying a command on the other schema is anomalous.
    assert_denies(r#"{"tool_name":"Read","input":{"command":"rm -rf /"}}"#);
}

#[test]
fn partial_new_schema_missing_command_fails_closed() {
    // Active schema (new `tool`) missing its command while legacy carries one.
    assert_denies(r#"{"tool":"Bash","tool_input":{"command":"git status"}}"#);
}

#[test]
fn empty_stdin_passes_through() {
    assert_passes_through("");
}

#[test]
fn clean_non_bash_tool_passes_through() {
    // A legitimate non-shell tool with NO command field must not be denied.
    assert_passes_through(r#"{"tool_name":"Read","tool_input":{"file_path":"y"}}"#);
}

#[test]
fn bare_bash_no_command_passes_through() {
    assert_passes_through(r#"{"tool_name":"Bash"}"#);
}
