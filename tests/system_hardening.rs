//! Integration tests for the system-command wrapper hardening
//! (issue #100, group G5).
//!
//! Covers the `ls` / `tree` path-as-flag boundary: user path operands that
//! begin with `-` must not be reinterpreted as command options. The wrappers
//! now insert a `--` separator before path operands, so a directory whose
//! name starts with `-` is listed as a path rather than parsed as a flag.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

fn unique_dir(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ctxc-g5-{}-{}-{}", tag, pid, ts))
}

fn contextcrawler_cmd() -> Command {
    let mut cmd = Command::new(binary_path());
    cmd.env("CONTEXTCRAWLER_TEST_MODE", "1");
    cmd.env_remove("CONTEXTCRAWLER_ALLOW_SENSITIVE_ENV_READ");
    cmd
}

/// `ls` of a directory that contains an entry named `-la` must succeed and
/// show the dash-prefixed entry — the `--` boundary keeps `ls` from parsing
/// any operand as an option.
#[test]
fn ls_lists_dash_prefixed_entry() {
    let root = unique_dir("ls");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("-la")).expect("create -la subdir");
    fs::write(root.join("normal.txt"), "hi").expect("write normal.txt");

    let out = contextcrawler_cmd()
        .arg("ls")
        .arg(&root)
        .output()
        .expect("spawn contextcrawler ls");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "ls of a dir with a dash-prefixed entry should succeed; got:\n{}",
        combined,
    );
    assert!(
        combined.contains("-la"),
        "dash-prefixed entry should be listed, got:\n{}",
        combined,
    );
    assert!(
        combined.contains("normal.txt"),
        "normal entry should still be listed, got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// `tree` of a directory whose only child is named `-la` must succeed: the
/// `--` boundary stops `tree` parsing the path operand as an option.
#[test]
fn tree_handles_dash_prefixed_path() {
    if Command::new("tree").arg("--version").output().is_err() {
        eprintln!("[skip] tree not on PATH");
        return;
    }

    let root = unique_dir("tree");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("-la")).expect("create -la subdir");

    let out = contextcrawler_cmd()
        .arg("tree")
        .arg(&root)
        .output()
        .expect("spawn contextcrawler tree");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "tree of a dir with a dash-prefixed child should succeed; got:\n{}",
        combined,
    );
    assert!(
        combined.contains("-la"),
        "dash-prefixed child should appear in tree output, got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// A grep pattern shaped like `--pre=<cmd>` must NOT be parsed by rg as the
/// `--pre` preprocessor flag (confirmed RCE, #32 / #111 G5). With the `--`
/// boundary in front of the pattern, rg treats it as a literal pattern, so
/// the marker file the "preprocessor" would create is never written.
#[test]
fn grep_pattern_shaped_like_pre_flag_is_not_executed() {
    let root = unique_dir("grep-pre");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create grep-pre dir");
    fs::write(root.join("haystack.txt"), "nothing interesting here\n").expect("write haystack.txt");

    // If `--pre` were honoured, rg would exec this script per file.
    let marker = root.join("pwned.marker");
    let script = root.join("evil.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\ncat \"$1\"\n", marker.display()),
    )
    .expect("write evil.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let out = contextcrawler_cmd()
        .arg("grep")
        .arg(format!("--pre={}", script.display()))
        .arg(&root)
        .output()
        .expect("spawn contextcrawler grep");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert!(
        !marker.exists(),
        "preprocessor script must NOT have run — `--`-shaped pattern reached rg as a flag; got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// A grep `path` operand that begins with `-` must be treated as a path, not
/// parsed as an rg/grep option — the `--` boundary precedes the path.
#[test]
fn grep_path_starting_with_dash_is_treated_as_path() {
    let root = unique_dir("grep-dashpath");
    let _ = fs::remove_dir_all(&root);
    let dash_dir = root.join("-dashdir");
    fs::create_dir_all(&dash_dir).expect("create -dashdir");
    fs::write(dash_dir.join("file.txt"), "findme_token\n").expect("write file.txt");

    let out = contextcrawler_cmd()
        .arg("grep")
        .arg("findme_token")
        .arg(&dash_dir)
        .output()
        .expect("spawn contextcrawler grep");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert!(
        combined.contains("findme_token"),
        "grep should search a dash-prefixed path and find the match, got:\n{}",
        combined,
    );

    let _ = fs::remove_dir_all(&root);
}

/// `read --tail-lines N` with NO positional files and piped stdin must read
/// stdin (like `cat`/`tail`) and exit 0 — not hard-error on a missing
/// argument. Regression guard for the clap `required = true` removal.
#[test]
fn read_no_files_reads_piped_stdin() {
    use std::io::Write;
    use std::process::Stdio;

    let input: String = (1..=100).map(|i| format!("{}\n", i)).collect();

    let mut child = contextcrawler_cmd()
        .args(["read", "--tail-lines", "20"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn contextcrawler read");

    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");

    let out = child.wait_with_output().expect("wait for read");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(
        out.status.code(),
        Some(0),
        "read with no files + piped stdin should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        stdout.contains("100"),
        "should show last lines, got:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("a value is required"),
        "must not emit the clap missing-arg error, got:\n{}",
        stdout,
    );
}

#[test]
fn read_refuses_dotenv_secret_without_echoing_value() {
    let root = unique_dir("dotenv-read");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dotenv-read dir");
    fs::write(root.join(".env"), "PASSWORD=demo-only\n").expect("write .env");

    let out = contextcrawler_cmd()
        .arg("read")
        .arg(".env")
        .current_dir(&root)
        .output()
        .expect("spawn contextcrawler read");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_ne!(out.status.code(), Some(0), "read .env must fail");
    assert!(
        combined.contains("refusing to read sensitive env file"),
        "expected clear refusal, got:\n{}",
        combined
    );
    assert!(
        !combined.contains("demo-only"),
        "refusal must not echo secret values, got:\n{}",
        combined
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn grep_refuses_dotenv_secret_without_echoing_value() {
    let root = unique_dir("dotenv-grep");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dotenv-grep dir");
    fs::write(root.join(".env"), "PASSWORD=demo-only\n").expect("write .env");

    let out = contextcrawler_cmd()
        .args(["grep", "PASSWORD", ".env"])
        .current_dir(&root)
        .output()
        .expect("spawn contextcrawler grep");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_ne!(out.status.code(), Some(0), "grep .env must fail");
    assert!(
        combined.contains("refusing to read sensitive env file"),
        "expected clear refusal, got:\n{}",
        combined
    );
    assert!(
        !combined.contains("demo-only"),
        "refusal must not echo secret values, got:\n{}",
        combined
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn proxy_grep_refuses_dotenv_secret_without_echoing_value() {
    let root = unique_dir("dotenv-proxy-grep");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dotenv-proxy-grep dir");
    fs::write(root.join(".env"), "PASSWORD=demo-only\n").expect("write .env");

    let out = contextcrawler_cmd()
        .args(["proxy", "grep", "PASSWORD", ".env"])
        .current_dir(&root)
        .output()
        .expect("spawn contextcrawler proxy grep");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert_eq!(out.status.code(), Some(126), "proxy refusal exit code");
    assert!(
        combined.contains("refusing to proxy sensitive env file read"),
        "expected clear proxy refusal, got:\n{}",
        combined
    );
    assert!(
        !combined.contains("demo-only"),
        "refusal must not echo secret values, got:\n{}",
        combined
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn documented_dotenv_templates_are_allowed() {
    let root = unique_dir("dotenv-templates");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dotenv-templates dir");

    for name in [".env.example", ".env.sample", ".env.template"] {
        fs::write(root.join(name), "PASSWORD=demo-only\n").expect("write template");

        let read = contextcrawler_cmd()
            .arg("read")
            .arg(name)
            .current_dir(&root)
            .output()
            .expect("spawn contextcrawler read template");
        assert_eq!(
            read.status.code(),
            Some(0),
            "read {name} should be allowed; stderr:\n{}",
            String::from_utf8_lossy(&read.stderr)
        );
        assert!(
            String::from_utf8_lossy(&read.stdout).contains("demo-only"),
            "read {name} should show template content"
        );

        let grep = contextcrawler_cmd()
            .args(["grep", "PASSWORD", name])
            .current_dir(&root)
            .output()
            .expect("spawn contextcrawler grep template");
        assert_eq!(
            grep.status.code(),
            Some(0),
            "grep {name} should be allowed; stderr:\n{}",
            String::from_utf8_lossy(&grep.stderr)
        );
        assert!(
            String::from_utf8_lossy(&grep.stdout).contains("demo-only"),
            "grep {name} should show template content"
        );
    }

    let _ = fs::remove_dir_all(&root);
}
