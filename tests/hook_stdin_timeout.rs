//! Regression tests for hook stdin that stays open without sending a payload
//! or EOF (#200).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn spawn_hook(name: &str) -> Child {
    Command::new(binary_path())
        .arg("hook")
        .arg(name)
        .env("CONTEXTCRAWLER_TEST_MODE", "1")
        .env("RTK_TELEMETRY_DISABLED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn contextcrawler hook {name}: {e}"))
}

fn wait_quickly(mut child: Child, hook: &str) -> std::process::Output {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child
            .try_wait()
            .unwrap_or_else(|e| panic!("{hook}: try_wait failed: {e}"))
            .is_some()
        {
            return child
                .wait_with_output()
                .unwrap_or_else(|e| panic!("{hook}: wait_with_output failed: {e}"));
        }
        thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    panic!("{hook}: hook did not exit before timeout with stdin held open");
}

fn run_open_stdin_without_payload(hook: &str) -> std::process::Output {
    let mut child = spawn_hook(hook);
    let _held_open = child.stdin.take().expect("child stdin pipe");
    wait_quickly(child, hook)
}

fn run_empty_eof(hook: &str) -> std::process::Output {
    let mut child = spawn_hook(hook);
    drop(child.stdin.take());
    wait_quickly(child, hook)
}

#[test]
fn claude_open_stdin_without_payload_fails_closed_without_hanging() {
    let output = run_open_stdin_without_payload("claude");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("Claude timeout must emit JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn gemini_open_stdin_without_payload_fails_closed_without_hanging() {
    let output = run_open_stdin_without_payload("gemini");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("Gemini timeout must emit JSON");
    assert_eq!(v["decision"], "deny");
}

#[test]
fn copilot_open_stdin_without_payload_fails_open_without_hanging() {
    let output = run_open_stdin_without_payload("copilot");
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "Copilot timeout should pass through silently, got stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn empty_eof_remains_clean_noop_for_pass_through_hooks() {
    for hook in ["claude", "copilot"] {
        let output = run_empty_eof(hook);
        assert!(
            output.status.success(),
            "{hook}: status {:?}",
            output.status
        );
        assert!(
            output.stdout.is_empty(),
            "{hook}: empty EOF should not emit stdout, got {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
