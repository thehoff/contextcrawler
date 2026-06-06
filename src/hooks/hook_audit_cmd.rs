//! Audits hook activity logs to show what commands were rewritten and when.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Hard cap on how much of the audit log we will read (#100 G2 IMPORTANT 8).
/// The log is append-only and small in normal use; a multi-GB file (whether
/// accidental or a crafted symlink target) must not be slurped whole.
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
/// Cap on number of lines parsed, independent of byte size.
const MAX_LOG_LINES: usize = 200_000;

/// The directory the audit log is expected to live under.
fn audit_dir() -> PathBuf {
    if let Some(dir) = crate::core::env_compat::env_var("CTXCRL_AUDIT_DIR") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join(".local/share")
            .join(crate::core::constants::RTK_DATA_DIR)
    }
}

/// Default log file location (aligned with hook's $HOME/.local/share/rtk/).
fn default_log_path() -> PathBuf {
    audit_dir().join("hook-audit.log")
}

/// Validate that `log_path` resolves to a regular file inside `expected_dir`
/// after canonicalisation (#100 G2 IMPORTANT 8).
///
/// This rejects a symlink whose target escapes the audit directory — a
/// crafted `hook-audit.log` symlink pointing at `/etc/shadow` (or any
/// arbitrary file) must not be read back and rendered.
fn validate_log_path(log_path: &Path, expected_dir: &Path) -> Result<()> {
    let canon_log = std::fs::canonicalize(log_path)
        .with_context(|| format!("Failed to resolve {}", log_path.display()))?;
    // The directory may legitimately be a symlink itself; canonicalise it
    // too so the containment check compares like-for-like.
    let canon_dir = std::fs::canonicalize(expected_dir)
        .unwrap_or_else(|_| expected_dir.to_path_buf());
    if !canon_log.starts_with(&canon_dir) {
        anyhow::bail!(
            "audit log {} resolves outside the audit directory {} — \
             refusing to read (possible symlink escape)",
            log_path.display(),
            canon_dir.display()
        );
    }
    let meta = std::fs::symlink_metadata(&canon_log)
        .with_context(|| format!("Failed to stat {}", canon_log.display()))?;
    if !meta.is_file() {
        anyhow::bail!("audit log {} is not a regular file", canon_log.display());
    }
    Ok(())
}

/// A single parsed audit log entry.
struct AuditEntry {
    timestamp: String,
    action: String,
    original_cmd: String,
    _rewritten_cmd: String,
}

/// Parse a single log line: "timestamp | action | original_cmd | rewritten_cmd"
fn parse_line(line: &str) -> Option<AuditEntry> {
    let parts: Vec<&str> = line.splitn(4, " | ").collect();
    if parts.len() < 3 {
        return None;
    }
    Some(AuditEntry {
        timestamp: parts[0].to_string(),
        action: parts[1].to_string(),
        original_cmd: parts[2].to_string(),
        _rewritten_cmd: parts.get(3).unwrap_or(&"-").to_string(),
    })
}

/// Extract the base command (first 1-2 words) for grouping.
fn base_command(cmd: &str) -> String {
    // Strip env var prefixes (FOO=bar ...)
    let stripped = cmd
        .split_whitespace()
        .skip_while(|w| w.contains('='))
        .collect::<Vec<_>>();

    match stripped.len() {
        0 => cmd.to_string(),
        1 => stripped[0].to_string(),
        _ => format!("{} {}", stripped[0], stripped[1]),
    }
}

/// Filter entries to those within the last N days.
fn filter_since_days(entries: &[AuditEntry], days: u64) -> Vec<&AuditEntry> {
    if days == 0 {
        return entries.iter().collect();
    }

    let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
    let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    entries
        .iter()
        .filter(|e| e.timestamp >= cutoff_str)
        .collect()
}

pub fn run(since_days: u64, verbose: u8) -> Result<()> {
    let log_path = default_log_path();

    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        println!("Enable audit mode: export RTK_HOOK_AUDIT=1 in your shell, then use Claude Code.");
        return Ok(());
    }

    // SECURITY (#100 G2 IMPORTANT 8): canonicalise + confirm the log lives
    // inside the audit directory (rejects symlink escapes) before reading.
    validate_log_path(&log_path, &audit_dir())?;

    let file = std::fs::File::open(&log_path)
        .with_context(|| format!("Failed to open {}", log_path.display()))?;

    // Stream the file with a byte cap and line cap rather than slurping an
    // arbitrarily large file into memory with `read_to_string`.
    let mut reader = BufReader::new(file);
    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut bytes_read: u64 = 0;
    let mut line = String::new();
    loop {
        if entries.len() >= MAX_LOG_LINES {
            eprintln!(
                "[contextcrawler] audit log line cap ({}) reached — output truncated",
                MAX_LOG_LINES
            );
            break;
        }
        line.clear();
        let n = reader
            .read_line(&mut line)
            .with_context(|| format!("Failed to read {}", log_path.display()))?;
        if n == 0 {
            break;
        }
        bytes_read += n as u64;
        if bytes_read > MAX_LOG_BYTES {
            eprintln!(
                "[contextcrawler] audit log byte cap ({} MiB) reached — output truncated",
                MAX_LOG_BYTES / (1024 * 1024)
            );
            break;
        }
        if let Some(entry) = parse_line(line.trim_end_matches(['\n', '\r'])) {
            entries.push(entry);
        }
    }

    if entries.is_empty() {
        println!("Audit log is empty.");
        return Ok(());
    }

    let filtered = filter_since_days(&entries, since_days);

    if filtered.is_empty() {
        println!("No entries in the last {} days.", since_days);
        return Ok(());
    }

    // Count by action
    let mut action_counts: HashMap<&str, usize> = HashMap::new();
    let mut cmd_counts: HashMap<String, usize> = HashMap::new();

    for entry in &filtered {
        *action_counts.entry(&entry.action).or_insert(0) += 1;
        if entry.action == "rewrite" {
            *cmd_counts
                .entry(base_command(&entry.original_cmd))
                .or_insert(0) += 1;
        }
    }

    let total = filtered.len();
    let rewrites = action_counts.get("rewrite").copied().unwrap_or(0);
    let skips = total - rewrites;
    let rewrite_pct = if total > 0 {
        rewrites as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    let skip_pct = if total > 0 {
        skips as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    // Period label
    let period = if since_days == 0 {
        "all time".to_string()
    } else {
        format!("last {} days", since_days)
    };

    println!("Hook Audit ({})", period);
    println!("{}", "─".repeat(30));
    println!("Total invocations: {}", total);
    println!("Rewrites:          {} ({:.1}%)", rewrites, rewrite_pct);
    println!("Skips:             {} ({:.1}%)", skips, skip_pct);

    // Skip breakdown
    let skip_actions: Vec<(&str, usize)> = action_counts
        .iter()
        .filter(|(k, _)| k.starts_with("skip:"))
        .map(|(k, v)| (*k, *v))
        .collect();

    if !skip_actions.is_empty() {
        let mut sorted_skips = skip_actions;
        sorted_skips.sort_by_key(|b| std::cmp::Reverse(b.1));
        for (action, count) in &sorted_skips {
            let reason = action.strip_prefix("skip:").unwrap_or(action);
            println!(
                "  {}:{}{}",
                reason,
                " ".repeat(14 - reason.len().min(13)),
                count
            );
        }
    }

    // Top commands (rewrites only)
    if !cmd_counts.is_empty() {
        let mut sorted_cmds: Vec<_> = cmd_counts.iter().collect();
        sorted_cmds.sort_by(|a, b| b.1.cmp(a.1));
        let top: Vec<String> = sorted_cmds
            .iter()
            .take(5)
            .map(|(cmd, count)| format!("{} ({})", cmd, count))
            .collect();
        println!("Top commands: {}", top.join(", "));
    }

    if verbose > 0 {
        println!("\nLog: {}", log_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_rewrite() {
        let line = "2026-02-16T14:30:01Z | rewrite | git status | rtk git status";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.action, "rewrite");
        assert_eq!(entry.original_cmd, "git status");
        assert_eq!(entry._rewritten_cmd, "rtk git status");
    }

    #[test]
    fn test_parse_line_skip() {
        let line = "2026-02-16T14:30:02Z | skip:no_match | echo hello | -";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.action, "skip:no_match");
        assert_eq!(entry.original_cmd, "echo hello");
    }

    #[test]
    fn test_parse_line_invalid() {
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn test_base_command_simple() {
        assert_eq!(base_command("git status"), "git status");
        assert_eq!(base_command("cargo test --nocapture"), "cargo test");
    }

    #[test]
    fn test_base_command_with_env() {
        assert_eq!(base_command("GIT_PAGER=cat git status"), "git status");
        assert_eq!(base_command("NODE_ENV=test CI=1 npx vitest"), "npx vitest");
    }

    #[test]
    fn test_base_command_single_word() {
        assert_eq!(base_command("ls"), "ls");
        assert_eq!(base_command("pytest"), "pytest");
    }

    fn make_entry(action: &str, cmd: &str) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-02-16T14:30:00Z".to_string(),
            action: action.to_string(),
            original_cmd: cmd.to_string(),
            _rewritten_cmd: "-".to_string(),
        }
    }

    #[test]
    fn test_filter_since_days_zero_returns_all() {
        let entries = vec![
            make_entry("rewrite", "git status"),
            make_entry("skip:no_match", "echo hi"),
        ];
        let result = filter_since_days(&entries, 0);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_token_savings() {
        // Simulate what rtk hook-audit would output vs raw log dump
        let raw_log = r#"2026-02-16T14:30:01Z | rewrite | git status | rtk git status
2026-02-16T14:30:02Z | skip:no_match | echo hello | -
2026-02-16T14:30:03Z | rewrite | cargo test | rtk cargo test
2026-02-16T14:30:04Z | skip:already_rtk | rtk git log | -
2026-02-16T14:30:05Z | rewrite | git log --oneline -10 | rtk git log --oneline -10
2026-02-16T14:30:06Z | rewrite | gh pr view 42 | rtk gh pr view 42
2026-02-16T14:30:07Z | skip:no_match | mkdir -p foo | -
2026-02-16T14:30:08Z | rewrite | cargo clippy --all-targets | rtk cargo clippy --all-targets"#;

        let entries: Vec<AuditEntry> = raw_log.lines().filter_map(parse_line).collect();
        assert_eq!(entries.len(), 8);

        let rewrites = entries.iter().filter(|e| e.action == "rewrite").count();
        assert_eq!(rewrites, 5);

        let skips = entries
            .iter()
            .filter(|e| e.action.starts_with("skip:"))
            .count();
        assert_eq!(skips, 3);

        // Compact output would be ~10 lines vs 8 raw lines — savings test:
        // The purpose of hook-audit is metrics, not filtering, so savings are moderate
        let input_tokens: usize = raw_log.split_whitespace().count();
        // Simulated compact output
        let compact = format!(
            "Hook Audit (all time)\nTotal: {}\nRewrites: {} ({:.1}%)\nSkips: {} ({:.1}%)\nTop: git status (1), cargo test (1)",
            entries.len(),
            rewrites,
            rewrites as f64 / entries.len() as f64 * 100.0,
            skips,
            skips as f64 / entries.len() as f64 * 100.0,
        );
        let output_tokens: usize = compact.split_whitespace().count();
        let savings = 100.0 - (output_tokens as f64 / input_tokens as f64 * 100.0);
        assert!(
            savings >= 30.0,
            "Expected >=30% savings for audit summary, got {:.1}%",
            savings
        );
    }
}
