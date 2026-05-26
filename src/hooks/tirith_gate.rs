// SPDX-License-Identifier: MIT
// Part of the ContextCrawler downstream of rtk-ai/rtk.
// Copyright (c) 2026 ContextCrawler contributors.
//
//! Tirith pre-execution gate.
//!
//! Subprocess-calls `tirith check --format json` and parses the verdict.
//! Used by both the `contextcrawler rewrite` path (`hooks::rewrite_cmd`) and
//! the `contextcrawler hook claude` path (`hooks::hook_cmd`) so the gate is
//! consistent regardless of which integration the user runs.
//!
//! Subprocess-only invocation; no statically-linked AGPL code.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

/// Hard cap on how long we wait for `tirith check` before treating it as
/// unavailable. A hung tirith would otherwise block the agent's PreToolUse
/// hook indefinitely (until the host agent itself times out — multi-second
/// freeze of the agent UI).
const TIRITH_TIMEOUT: Duration = Duration::from_secs(8);

/// Hard cap on tirith stdout size. A trusted tirith returns a small JSON
/// verdict; a compromised one could emit gigabytes and OOM us.
const TIRITH_STDOUT_MAX: u64 = 4 * 1024 * 1024;

pub enum Verdict {
    Allow,
    Block { tirith_json: String },
    /// Tirith missing, errored, or returned an unrecognized verdict.
    /// Caller decides fail-open (proceed) vs fail-closed (downgrade).
    Unavailable,
}

pub fn check(cmd: &str) -> Verdict {
    // Soft opt-out for debugging.
    if std::env::var("CONTEXTCRAWLER_TIRITH_DISABLED").as_deref() == Ok("1") {
        return Verdict::Unavailable;
    }

    // Try `tirith` from $PATH; fall back to ~/.cargo/bin/tirith.
    let bin = if which::which("tirith").is_ok() {
        "tirith".to_string()
    } else {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return Verdict::Unavailable,
        };
        let cargo_bin = home.join(".cargo/bin/tirith");
        if !cargo_bin.exists() {
            return Verdict::Unavailable;
        }
        cargo_bin.to_string_lossy().to_string()
    };

    // Tirith puts the verdict in stdout JSON; exit code is 0 even on block.
    // Spawn explicitly (not output()) so we can apply a wall-clock timeout
    // and a stdout size cap. F-01 / F-02 from the 2026-05-15 module audit.
    let mut child = match Command::new(&bin)
        .args([
            "check",
            "--format",
            "json",
            "--non-interactive",
            "--no-daemon",
            "--",
        ])
        .arg(cmd)
        // Don't inherit stdin from the host agent's hook pipe (F-05).
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // stderr to /dev/null, not piped. A noisy tirith would otherwise
        // fill the ~64 KiB kernel pipe buffer and block on write until
        // our 8s wait_timeout fires — turning a successful check into an
        // 8-second stall. We don't surface tirith stderr anywhere, so
        // discarding directly is safe. (Codex review follow-up.)
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Verdict::Unavailable,
    };

    let exit_status = match child.wait_timeout(TIRITH_TIMEOUT) {
        Ok(Some(s)) => s,
        Ok(None) => {
            // Timed out. Kill the child so it doesn't linger; fall through
            // to Unavailable (caller decides fail-open vs fail-closed).
            let _ = child.kill();
            let _ = child.wait();
            return Verdict::Unavailable;
        }
        Err(_) => return Verdict::Unavailable,
    };

    let _ = exit_status; // tirith returns 0 on both allow and block; rely on JSON content.

    // Read piped stdout with a hard size cap.
    let mut stdout_buf = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s
            .by_ref()
            .take(TIRITH_STDOUT_MAX)
            .read_to_end(&mut stdout_buf);
    }
    let stdout = String::from_utf8_lossy(&stdout_buf).to_string();

    // Parse structurally — substring matching on JSON is fragile (pretty-
    // printed output, descriptions containing the word "block", etc.).
    let parsed: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(_) => return Verdict::Unavailable,
    };
    match parsed.get("action").and_then(|x| x.as_str()) {
        Some("block") => Verdict::Block { tirith_json: stdout },
        Some("allow") => Verdict::Allow,
        _ => Verdict::Unavailable,
    }
}

pub fn require_tirith() -> bool {
    std::env::var("CONTEXTCRAWLER_TIRITH_REQUIRED").as_deref() == Ok("1")
}

/// Decide whether an upstream `Allow` verdict should be downgraded.
/// Returns Some((reason, optional_tirith_json)) to downgrade; None to proceed.
pub fn should_downgrade(verdict: &Verdict) -> Option<(&'static str, Option<&str>)> {
    match verdict {
        Verdict::Block { tirith_json } => Some(("tirith_block", Some(tirith_json.as_str()))),
        Verdict::Unavailable if require_tirith() => Some(("tirith_required_unavailable", None)),
        _ => None,
    }
}

/// Append a downgrade event to the ContextCrawler local log.
/// Path: $XDG_DATA_HOME/contextcrawler/downgrades.jsonl
/// (or platform equivalent via dirs::data_local_dir).
/// Best-effort: any I/O error is silently dropped.
pub fn log_downgrade(cmd: &str, reason: &'static str, tirith_json: Option<&str>) {
    let dir = match dirs::data_local_dir() {
        Some(d) => d.join("contextcrawler"),
        None => return,
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("downgrades.jsonl");

    // Scrub credentials before the cmd lands on disk. See issue #180.
    let safe_cmd = crate::core::secret_redact::redact(cmd);
    // The tirith blob frequently echoes the command (and any inline
    // credentials) back in its findings, so scrub it too. The redactor is
    // structure-preserving — it only touches matched substrings — so the
    // surrounding JSON shape remains valid.
    let safe_tirith = tirith_json.map(|j| crate::core::secret_redact::redact(j));

    let timestamp = chrono::Utc::now().to_rfc3339();
    let record = match safe_tirith.as_deref() {
        Some(json) => format!(
            r#"{{"ts":"{}","reason":"{}","cmd":{},"tirith":{}}}"#,
            timestamp,
            reason,
            json_escape(&safe_cmd),
            json.trim(),
        ),
        None => format!(
            r#"{{"ts":"{}","reason":"{}","cmd":{}}}"#,
            timestamp,
            reason,
            json_escape(&safe_cmd),
        ),
    };

    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", record);
    }
}

/// Resolve the Tirith binary path the gate would actually use. Returns
/// `None` if neither `which tirith` nor `~/.cargo/bin/tirith` finds it.
/// Used by the `security` dashboard so the user can see exactly which
/// binary is in play.
pub fn tirith_binary_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = which::which("tirith") {
        return Some(p);
    }
    let home = dirs::home_dir()?;
    let cargo_bin = home.join(".cargo/bin/tirith");
    if cargo_bin.exists() {
        Some(cargo_bin)
    } else {
        None
    }
}

/// Returns the path where downgrade events are appended (whether or not
/// the file exists yet). Mirrors the resolution in `log_downgrade`.
pub fn downgrades_log_path() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|d| d.join("contextcrawler/downgrades.jsonl"))
}

/// Maximum number of bytes read from the tail of `downgrades.jsonl`.
///
/// The log lives in a user-writable data dir, so an attacker (or a runaway
/// writer) could grow it without bound. We only ever need the last `limit`
/// records — each record is one short line — so 256 KB of tail is plentiful.
/// Capping the read keeps `read_recent_downgrades` O(tail), not O(filesize).
const DOWNGRADES_TAIL_BYTES: u64 = 256 * 1024;

/// Read the tail of the downgrades log, returning up to `limit` most
/// recent records. Each returned `String` is one VALID JSON record
/// (re-serialised compactly via `serde_json` to ensure parseability).
///
/// SEC-I4 hardening:
///
/// - The read is capped to the last [`DOWNGRADES_TAIL_BYTES`] of the file
///   instead of slurping the whole file with `read_to_string`. An attacker
///   who grows the log can no longer force an unbounded allocation.
/// - Records are parsed line-by-line (`log_downgrade` always writes
///   single-line JSON), replacing the previous multi-line balanced-brace
///   scanner that was O(n²) on a large/adversarial file.
///
/// Behaviour is identical for well-formed single-line logs.
pub fn read_recent_downgrades(limit: usize) -> Vec<String> {
    let path = match downgrades_log_path() {
        Some(p) if p.exists() => p,
        _ => return Vec::new(),
    };

    let content = match read_file_tail(&path, DOWNGRADES_TAIL_BYTES) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Parse line-by-line. A capped read may have sliced the first line in
    // half — skip any line that does not round-trip through serde_json.
    // Re-serialised form is canonical (compact, single-line) so JSON
    // consumers can rely on one record == one line.
    let records: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let v: serde_json::Value = serde_json::from_str(trimmed).ok()?;
            serde_json::to_string(&v).ok()
        })
        .collect();

    let start = records.len().saturating_sub(limit);
    records[start..].to_vec()
}

/// Read at most the last `max_bytes` of `path` as a UTF-8 string.
///
/// Seeks to `len - max_bytes` for large files so the read cost is bounded by
/// `max_bytes` rather than the file size. A lossy UTF-8 conversion is used so
/// a tail that begins mid-multibyte-sequence does not abort the read.
fn read_file_tail(path: &std::path::Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > max_bytes {
        f.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut buf = Vec::with_capacity(max_bytes.min(len) as usize);
    f.take(max_bytes).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// `contextcrawler security` dashboard. Renders the current Tirith gate
/// configuration + recent downgrade events. Two modes:
/// - default (human-readable): bullet list + tail of the log
/// - `--json`: machine-readable, suitable for piping into jq
///
/// Implements what the CONTEXTCRAWLER.md template has long advertised
/// ("Tirith defense-in-depth gate dashboard") but which previously had
/// no actual subcommand backing it — `contextcrawler security` fell
/// through to macOS's `/usr/bin/security` (keychain tool). See issue #32
/// for the discovery context.
pub fn run_security_dashboard(all: bool, json: bool) -> anyhow::Result<i32> {
    let bin = tirith_binary_path();
    let disabled =
        std::env::var("CONTEXTCRAWLER_TIRITH_DISABLED").as_deref() == Ok("1");
    let required =
        std::env::var("CONTEXTCRAWLER_TIRITH_REQUIRED").as_deref() == Ok("1");
    let log_path = downgrades_log_path();
    let log_exists = log_path.as_ref().is_some_and(|p| p.exists());
    let limit = if all { usize::MAX } else { 10 };
    let recent = read_recent_downgrades(limit);

    if json {
        // Use serde_json for the whole envelope — the previous draft
        // hand-rolled escaping only covered `\` and `"`, which leaves
        // control chars (tab, newline) producing invalid JSON when a
        // path contains them. Codex P3 catch.
        // Each recent record is ALREADY canonical-form JSON (see
        // read_recent_downgrades), so we splice it in as a raw value.
        let parsed_recent: Vec<serde_json::Value> = recent
            .iter()
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect();
        let envelope = serde_json::json!({
            "tirith_binary": bin.as_ref().map(|p| p.to_string_lossy()),
            "installed": bin.is_some(),
            "gate_disabled": disabled,
            "gate_required": required,
            "log_path": log_path.as_ref().map(|p| p.to_string_lossy()),
            "log_exists": log_exists,
            "recent_downgrades": parsed_recent,
        });
        let rendered = serde_json::to_string_pretty(&envelope)
            .unwrap_or_else(|_| "{}".to_string());
        println!("{}", rendered);
        return Ok(0);
    }

    println!("ContextCrawler Tirith Gate — Status");
    println!("════════════════════════════════════════════════════════════");
    println!();
    println!("Installation:");
    match &bin {
        Some(p) => println!("  [ok] tirith binary: {}", p.display()),
        None => {
            println!("  [--] tirith binary: not found (PATH lookup + ~/.cargo/bin/tirith both empty)");
            println!("       install with: cargo install tirith");
        }
    }
    println!();
    println!("Gate state:");
    if disabled {
        println!("  [!!] DISABLED via CONTEXTCRAWLER_TIRITH_DISABLED=1");
        println!("       (every command bypasses tirith inspection)");
    } else if bin.is_none() {
        println!("  [!!] EFFECTIVELY DISABLED (tirith binary missing)");
    } else {
        println!("  [ok] enabled — every hook-routed command is inspected before exec");
    }
    if required {
        println!("  [ok] CONTEXTCRAWLER_TIRITH_REQUIRED=1 (strict mode: tirith failure ≠ allow)");
    } else {
        println!("  [--] not required — tirith unavailability falls open (default)");
    }
    println!();
    println!("Downgrade log:");
    match &log_path {
        Some(p) => {
            println!("  path: {}", p.display());
            println!("  exists: {}", if log_exists { "yes" } else { "no" });
        }
        None => println!("  path: unresolvable (no data_local_dir)"),
    }
    println!();
    if recent.is_empty() {
        println!("Recent downgrade events: (none)");
    } else {
        let shown = recent.len();
        let label = if all {
            format!("Downgrade events (all {} shown)", shown)
        } else {
            format!("Recent downgrade events (last {} of newest)", shown)
        };
        println!("{}:", label);
        for line in &recent {
            println!("  {}", line);
        }
    }
    println!();
    println!("Scope note: tirith inspects COMMAND STRINGS only — env-var-driven attacks");
    println!("(e.g. RIPGREP_CONFIG_PATH hijack, see issue #32) are blocked separately");
    println!("inside the spawning code path via env_remove + arg deny-list.");
    Ok(0)
}

/// Minimal JSON string escape for our log lines.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_file_tail_returns_whole_small_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("small.txt");
        std::fs::write(&path, "line one\nline two\n").unwrap();
        let out = read_file_tail(&path, DOWNGRADES_TAIL_BYTES).unwrap();
        assert_eq!(out, "line one\nline two\n");
    }

    #[test]
    fn read_file_tail_caps_oversized_file() {
        // Write a file larger than the cap; the tail read must return at
        // most `max_bytes` and never allocate the whole file.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("big.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        // 1 MB of filler, then a recognisable trailer.
        let filler = vec![b'x'; 1024 * 1024];
        f.write_all(&filler).unwrap();
        f.write_all(b"\nTAIL-MARKER\n").unwrap();
        drop(f);

        let cap = 4 * 1024;
        let out = read_file_tail(&path, cap).unwrap();
        assert!(
            out.len() as u64 <= cap,
            "tail read must not exceed cap: got {} bytes",
            out.len()
        );
        // Guard against a degenerate zero-byte read passing the `<= cap`
        // check: the file is far larger than the cap, so the tail must be
        // approximately `cap`-sized, not near-empty.
        assert!(
            out.len() as u64 >= cap - 1024,
            "tail read must be approximately cap-sized: got {} bytes (cap {})",
            out.len(),
            cap
        );
        assert!(
            out.ends_with("TAIL-MARKER\n"),
            "tail read must include the end of the file"
        );
    }

    #[test]
    fn read_file_tail_oversized_jsonl_parses_last_records() {
        // Simulate an attacker-grown downgrades.jsonl: many lines, far past
        // the cap. The line-by-line parse must still recover well-formed
        // trailing records and silently drop any half-line at the cap edge.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("downgrades.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for i in 0..50_000 {
            writeln!(
                f,
                r#"{{"ts":"2026-01-01T00:00:00Z","reason":"r","cmd":"c{}"}}"#,
                i
            )
            .unwrap();
        }
        drop(f);

        let content = read_file_tail(&path, DOWNGRADES_TAIL_BYTES).unwrap();
        assert!(
            content.len() as u64 <= DOWNGRADES_TAIL_BYTES,
            "tail must be capped"
        );
        // Parse line-by-line exactly as read_recent_downgrades does.
        let records: Vec<String> = content
            .lines()
            .filter_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l.trim()).ok()?;
                serde_json::to_string(&v).ok()
            })
            .collect();
        assert!(!records.is_empty(), "must recover trailing records");
        // The very last line of the file is record 49999.
        assert!(
            records.last().unwrap().contains("c49999"),
            "last record must be the most recent line"
        );
    }
}
