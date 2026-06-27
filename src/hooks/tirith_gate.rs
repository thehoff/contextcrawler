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

/// Run the `contextcrawler security --scrub-logs` action: scan both the
/// tirith downgrade log and the supply-chain event log, deep-redact every
/// string field via `core::secret_redact::redact`, and rewrite atomically.
/// A timestamped backup is written alongside each rewritten file. With
/// `dry_run`, no file is touched — only counts are reported.
///
/// Returns the process exit code (0 on success).
pub fn run_scrub_logs(dry_run: bool) -> anyhow::Result<i32> {
    let data_dir = dirs::data_local_dir().ok_or_else(|| {
        anyhow::anyhow!("could not resolve data_local_dir (XDG_DATA_HOME or platform equivalent)")
    })?;
    let log_dir = data_dir.join("contextcrawler");
    let report = scrub_logs_in(&log_dir, dry_run)?;
    println!(
        "ContextCrawler audit log scrub — {}",
        if dry_run { "DRY RUN" } else { "live" }
    );
    println!("════════════════════════════════════════════════════════════");
    println!("log dir: {}", log_dir.display());
    println!();
    for f in &report.files {
        if f.skipped {
            println!("  {}: not present, skipping", f.name);
            continue;
        }
        println!(
            "  {}: lines={} changed={} unparseable={}",
            f.name, f.total, f.changed, f.unparseable
        );
        if let Some(bak) = &f.backup_path {
            println!("    backup: {}", bak.display());
        }
    }
    println!();
    println!(
        "Summary: {} lines processed, {} changed{}",
        report.grand_total,
        report.grand_changed,
        if dry_run { " (no files written)" } else { "" }
    );
    Ok(0)
}

/// Per-file outcome from a scrub pass.
#[derive(Debug, Default)]
pub struct ScrubFileReport {
    pub name: String,
    pub skipped: bool,
    pub total: usize,
    pub changed: usize,
    pub unparseable: usize,
    pub backup_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Default)]
pub struct ScrubReport {
    pub files: Vec<ScrubFileReport>,
    pub grand_total: usize,
    pub grand_changed: usize,
}

/// Core of `run_scrub_logs`, lifted out so tests can drive it against a
/// tempdir instead of the real `~/Library/Application Support/contextcrawler`.
pub fn scrub_logs_in(
    log_dir: &std::path::Path,
    dry_run: bool,
) -> anyhow::Result<ScrubReport> {
    use crate::core::secret_redact::redact;
    use chrono::Utc;
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Write};

    fn deep_redact(v: &mut Value) {
        match v {
            Value::String(s) => {
                let r = redact(s);
                if let std::borrow::Cow::Owned(new) = r {
                    *s = new;
                }
            }
            Value::Array(a) => a.iter_mut().for_each(deep_redact),
            Value::Object(m) => m.values_mut().for_each(deep_redact),
            _ => {}
        }
    }

    let targets = ["downgrades.jsonl", "supply_chain.jsonl"];
    let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let mut report = ScrubReport::default();

    for name in &targets {
        let mut entry = ScrubFileReport {
            name: (*name).to_string(),
            ..Default::default()
        };
        let path = log_dir.join(name);
        if !path.exists() {
            entry.skipped = true;
            report.files.push(entry);
            continue;
        }
        let src = std::fs::File::open(&path)?;
        let reader = BufReader::new(src);
        let tmp_path = path.with_extension("jsonl.scrub-tmp");
        let mut out_buf: Vec<u8> = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                out_buf.extend_from_slice(b"\n");
                continue;
            }
            entry.total += 1;
            match serde_json::from_str::<Value>(&line) {
                Ok(mut v) => {
                    let before = v.clone();
                    deep_redact(&mut v);
                    if v != before {
                        entry.changed += 1;
                    }
                    let serialised =
                        serde_json::to_string(&v).unwrap_or_else(|_| line.clone());
                    out_buf.extend_from_slice(serialised.as_bytes());
                    out_buf.push(b'\n');
                }
                Err(_) => {
                    entry.unparseable += 1;
                    let r = redact(&line);
                    if r.as_ref() != line {
                        entry.changed += 1;
                    }
                    out_buf.extend_from_slice(r.as_bytes());
                    out_buf.push(b'\n');
                }
            }
        }
        report.grand_total += entry.total;
        report.grand_changed += entry.changed;
        if !dry_run {
            {
                let mut tmp = std::fs::File::create(&tmp_path)?;
                tmp.write_all(&out_buf)?;
                tmp.sync_all()?;
            }
            let bak = path.with_file_name(format!("{}.bak-{}", name, stamp));
            std::fs::copy(&path, &bak)?;
            std::fs::rename(&tmp_path, &path)?;
            entry.backup_path = Some(bak);
        }
        report.files.push(entry);
    }
    Ok(report)
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

/// Extract a bare host from a URL or host-ish token, dropping scheme,
/// userinfo, port, path and query.
///
/// SECURITY-critical: this is what gets shown to the user in the permission
/// prompt and what we hand to `tirith trust add`. It must NEVER return the
/// path, query, or userinfo — a URL like `https://user:tok@host/p?key=secret`
/// can carry credentials, and only `host` may surface. Returns `None` if no
/// plausible host remains.
fn extract_host(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Drop scheme (`https://`, `http://`, …).
    let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    // The authority ends at the first '/', '?' or '#'. This drops path+query
    // (and any credentials hidden in them) before anything else.
    let authority = s.split(['/', '?', '#']).next().unwrap_or("");
    // Drop userinfo (`user:pass@host`).
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // Drop a trailing `:port` (only when the suffix is all digits, so an
    // IPv6-ish or odd token isn't truncated mid-host).
    let host = host_port
        .rsplit_once(':')
        .filter(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(host_port);
    // Strip IPv6 brackets: `[fe80::1]` -> `fe80::1`.
    let host = host
        .strip_prefix('[')
        .map_or(host, |inner| inner.strip_suffix(']').unwrap_or(inner));
    // Strip an IPv6 zone id (`%eth0`): an interface name is network-topology
    // metadata, not a host, and the "host only" contract forbids it surfacing
    // (council/mmax #197). `split('%').next()` keeps everything before the
    // first '%' and is a no-op for the common no-'%' hostname.
    let host = host.split('%').next().unwrap_or(host);
    let host = host.trim();
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return None;
    }
    Some(host.to_string())
}

/// Build a copy-paste Tirith trust suggestion from a block verdict JSON, to be
/// surfaced in the Ask permission reason so the user can act on the flag
/// without digging through logs (#197).
///
/// Returns `None` when the JSON has no actionable findings or cannot be parsed
/// — the caller then falls back to the generic Ask reason.
///
/// SECURITY: only host names reach the output (see [`extract_host`]); the full
/// command and any credentials in a URL are never echoed here.
///
/// SCRUB-SAFETY: this runs on the *pre-scrub* verdict JSON (the redaction in
/// [`log_downgrade`] happens on its own copy). That is safe by construction,
/// not by ordering: the only fields read are `rule_id` (an identifier) and
/// `url`-type `evidence.raw` (passed through [`extract_host`], which yields a
/// host or nothing). No other evidence field is ever copied into the output,
/// so a credential cannot flow through even if new evidence shapes appear.
pub fn suggest_trust(tirith_json: &str) -> Option<String> {
    // Cap on hosts listed so a pathological verdict can't produce a wall of
    // trust lines in the prompt.
    const MAX_HOSTS: usize = 5;

    let parsed: serde_json::Value = serde_json::from_str(tirith_json.trim()).ok()?;
    let findings = parsed.get("findings")?.as_array()?;

    let mut rules: Vec<String> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut any_pattern_only = false;

    for f in findings {
        let rule = f.get("rule_id").and_then(|r| r.as_str()).unwrap_or("");
        // Accept only identifier-shaped rule ids. A crafted rule_id with
        // newlines/control chars would otherwise inject extra lines into the
        // user-visible hint (council/Codex #197). Real Tirith ids look like
        // `pipe_to_interpreter` / `schemeless_to_sink`.
        let rule_ok = !rule.is_empty()
            && rule
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if rule_ok && !rules.iter().any(|r| r == rule) {
            rules.push(rule.to_string());
        }
        let mut finding_has_host = false;
        if let Some(ev) = f.get("evidence").and_then(|e| e.as_array()) {
            for e in ev {
                if e.get("type").and_then(|t| t.as_str()) != Some("url") {
                    continue;
                }
                if let Some(host) = e
                    .get("raw")
                    .and_then(|r| r.as_str())
                    .and_then(extract_host)
                {
                    finding_has_host = true;
                    if !hosts.iter().any(|h| h == &host) {
                        hosts.push(host);
                    }
                }
            }
        }
        if !finding_has_host {
            any_pattern_only = true;
        }
    }

    if rules.is_empty() {
        return None;
    }

    let mut out = String::from("contextcrawler: Tirith flagged this command before it ran.\n");
    out.push_str(&format!("  rules: {}\n", rules.join(", ")));

    for host in hosts.iter().take(MAX_HOSTS) {
        out.push_str(&format!("  host:  {host}\n"));
        out.push_str(&format!(
            "  trust (this repo):  tirith trust add {host} --scope repo\n"
        ));
        out.push_str(&format!(
            "  trust (everywhere): tirith trust add {host} --scope user\n"
        ));
    }
    if hosts.len() > MAX_HOSTS {
        out.push_str(&format!("  (+{} more host(s))\n", hosts.len() - MAX_HOSTS));
    }

    if hosts.is_empty() {
        // Pattern-only findings (e.g. pipe_to_interpreter) have no host to
        // trust — and are the shape most prone to false positives. Point at
        // inspection rather than fabricating a trust target.
        out.push_str("  no host to trust (pattern rule) — inspect with tirith why.\n");
    } else {
        if any_pattern_only {
            out.push_str("  (some findings are pattern rules with no host — see tirith why)\n");
        }
    }
    out.push_str("  review / why:       tirith trust last   ·   tirith why\n");
    Some(out)
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
    fn extract_host_strips_scheme_port_path_query_userinfo() {
        // SECURITY: path/query/userinfo must never survive — they can carry creds.
        assert_eq!(
            extract_host("https://user:tok@gitea.example.com:3000/p?key=secret"),
            Some("gitea.example.com".to_string())
        );
        assert_eq!(
            extract_host("http://192.0.2.10:3000/api/v1/repos/x"),
            Some("192.0.2.10".to_string())
        );
        assert_eq!(extract_host("192.0.2.10"), Some("192.0.2.10".to_string()));
        assert_eq!(extract_host("json.tool"), Some("json.tool".to_string()));
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("has space"), None);
    }

    #[test]
    fn extract_host_never_returns_userinfo() {
        // Targeted: credentials in userinfo must never survive, on their own.
        let h = extract_host("https://admin:s3cr3t-token@internal.host/p").unwrap();
        assert_eq!(h, "internal.host");
        assert!(!h.contains("admin"));
        assert!(!h.contains("s3cr3t"));
    }

    #[test]
    fn extract_host_strips_ipv6_brackets_and_zone_id() {
        // #197 (mmax): an IPv6 zone id is an interface name (topology), not a
        // host — it must not surface. Brackets are stripped too.
        assert_eq!(
            extract_host("https://[fe80::1%eth0]:8080/p"),
            Some("fe80::1".to_string())
        );
        assert_eq!(extract_host("[::1]"), Some("::1".to_string()));
    }

    #[test]
    fn suggest_trust_never_echoes_credentials_from_url() {
        let json = r#"{"action":"block","findings":[
            {"rule_id":"plain_http_to_sink","evidence":[{"type":"url","raw":"https://admin:tok3n@vault.example.com/secret?k=v"}]}
        ]}"#;
        let out = suggest_trust(json).expect("should suggest");
        assert!(out.contains("vault.example.com"));
        assert!(!out.contains("admin"), "userinfo must not leak: {out}");
        assert!(!out.contains("tok3n"), "credential must not leak: {out}");
        assert!(!out.contains("secret"), "path must not leak: {out}");
    }

    #[test]
    fn suggest_trust_builds_host_lines_repo_then_user() {
        let json = r#"{"action":"block","findings":[
            {"rule_id":"plain_http_to_sink","evidence":[{"type":"url","raw":"http://gitea.example.com:3000/x.git"}]},
            {"rule_id":"private_network_access","evidence":[{"type":"url","raw":"http://gitea.example.com:3000/x.git"}]}
        ]}"#;
        let out = suggest_trust(json).expect("should suggest");
        // Both rules surfaced, host de-duped to one block, repo before user.
        assert!(out.contains("plain_http_to_sink"));
        assert!(out.contains("private_network_access"));
        let repo_at = out.find("--scope repo").unwrap();
        let user_at = out.find("--scope user").unwrap();
        assert!(repo_at < user_at, "repo scope must be suggested before user scope");
        assert_eq!(
            out.matches("tirith trust add gitea.example.com --scope repo").count(),
            1,
            "host must be de-duplicated across findings"
        );
        // Never leak the path.
        assert!(!out.contains("x.git"), "path must not leak into the suggestion");
    }

    #[test]
    fn suggest_trust_pattern_only_points_at_why_no_fake_host() {
        let json = r#"{"action":"block","findings":[
            {"rule_id":"pipe_to_interpreter","evidence":[{"type":"command_pattern","matched":"curl x | sh"}]}
        ]}"#;
        let out = suggest_trust(json).expect("should suggest");
        assert!(out.contains("pipe_to_interpreter"));
        assert!(out.contains("tirith why"));
        assert!(out.contains("tirith trust last"));
        assert!(!out.contains("trust add"), "no host → no fabricated trust target");
    }

    #[test]
    fn suggest_trust_rejects_injected_rule_id() {
        // #197 (Codex): a rule_id with a newline must not inject extra lines.
        // A valid finding rides alongside so a suggestion is still produced —
        // proving the injected id is dropped while legitimate content survives.
        let json = r#"{"action":"block","findings":[
            {"rule_id":"evil\n  malicious: line","evidence":[{"type":"url","raw":"http://h.example.com/"}]},
            {"rule_id":"plain_http_to_sink","evidence":[{"type":"url","raw":"http://h.example.com/"}]}
        ]}"#;
        let out = suggest_trust(json).expect("the valid finding yields a suggestion");
        assert!(!out.contains("malicious"), "injected rule_id must be dropped: {out}");
        assert!(out.contains("plain_http_to_sink"), "valid rule still surfaces");
        assert!(out.contains("h.example.com"), "valid host still surfaces");
    }

    #[test]
    fn suggest_trust_none_on_garbage_or_empty() {
        assert!(suggest_trust("not json").is_none());
        assert!(suggest_trust(r#"{"action":"block"}"#).is_none());
        assert!(suggest_trust(r#"{"action":"block","findings":[]}"#).is_none());
    }

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

    #[test]
    fn scrub_logs_in_strips_credentials_and_backs_up() {
        let dir = tempfile::TempDir::new().unwrap();
        let down = dir.path().join("downgrades.jsonl");
        let supply = dir.path().join("supply_chain.jsonl");
        std::fs::write(
            &down,
            concat!(
                r#"{"ts":"2026-05-26T00:00:00Z","reason":"tirith_block","cmd":"TEA_TOKEN=147dd871c9edab5848377af412b6575bca133169 curl -H \"Authorization: token 147dd871c9edab5848377af412b6575bca133169\" https://x","tirith":{"action":"block","evidence":[{"raw":"Authorization: token 147dd871c9edab5848377af412b6575bca133169"}]}}"#,
                "\n",
            ),
        )
        .unwrap();
        std::fs::write(
            &supply,
            concat!(
                r#"{"ts":"2026-05-26T00:00:00Z","verdict":"skip","cmd":"echo MY_API_KEY=abc123 && curl -H 'Authorization: Bearer eyJ.tok.en' https://x","findings":[]}"#,
                "\n",
            ),
        )
        .unwrap();

        let report = scrub_logs_in(dir.path(), false).unwrap();
        assert_eq!(report.grand_total, 2);
        assert_eq!(report.grand_changed, 2, "both lines must be scrubbed");
        assert!(report.files.iter().all(|f| f.backup_path.is_some()));

        let down_new = std::fs::read_to_string(&down).unwrap();
        let supply_new = std::fs::read_to_string(&supply).unwrap();
        assert!(!down_new.contains("147dd871"), "leaked: {}", down_new);
        assert!(!down_new.contains("Authorization: token 147"));
        assert!(!supply_new.contains("abc123"));
        assert!(!supply_new.contains("eyJ.tok.en"));
        assert!(supply_new.contains("MY_API_KEY=<REDACTED>"));
        // Surrounding JSON shape preserved.
        assert!(down_new.contains(r#""reason""#));
        assert!(supply_new.contains(r#""verdict""#));
    }

    #[test]
    fn scrub_logs_in_dry_run_does_not_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let down = dir.path().join("downgrades.jsonl");
        let leaky = concat!(
            r#"{"ts":"x","reason":"r","cmd":"TEA_TOKEN=abc curl https://x"}"#,
            "\n",
        );
        std::fs::write(&down, leaky).unwrap();
        let before = std::fs::read_to_string(&down).unwrap();
        let report = scrub_logs_in(dir.path(), true).unwrap();
        let after = std::fs::read_to_string(&down).unwrap();
        assert_eq!(before, after, "dry-run must not mutate the file");
        assert_eq!(report.grand_changed, 1, "dry-run still reports counts");
        assert!(report.files.iter().all(|f| f.backup_path.is_none()));
    }

    #[test]
    fn scrub_logs_in_skips_missing_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let report = scrub_logs_in(dir.path(), false).unwrap();
        assert!(report.files.iter().all(|f| f.skipped));
        assert_eq!(report.grand_total, 0);
        assert_eq!(report.grand_changed, 0);
    }
}
