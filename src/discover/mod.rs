//! Scans AI coding sessions to find commands that could benefit from CTXCRL filtering.

pub mod codex;
pub mod lexer;
pub mod provider;
pub mod reconcile;
pub mod registry;
mod report;
pub mod rules;

use anyhow::Result;
use std::collections::HashMap;

use provider::{ClaudeProvider, ExtractedCommand, SessionProvider};
use reconcile::{is_runtime_tracked, load_tracked, TrackedCommand, DEFAULT_MATCH_WINDOW_SECS};
use registry::{
    category_avg_tokens, classify_command, cmd_has_ctxcrl_disabled_prefix, split_command_chain,
    strip_disabled_prefix, Classification,
};
use report::{DiscoverReport, SupportedEntry, UnsupportedEntry};

/// Aggregation bucket for supported commands.
struct SupportedBucket {
    ctxcrl_equivalent: &'static str,
    category: &'static str,
    count: usize,
    /// Total estimated tokens *saved* (post-filter). Used for the "Est. Savings" column.
    total_output_tokens: usize,
    /// Total estimated tokens *before* filtering (raw output). Accumulated alongside
    /// `total_output_tokens` so the bucket's effective savings rate can be derived as
    /// `total_output_tokens / total_raw_output_tokens` — a weighted average across
    /// all sub-commands, regardless of which sub-command was seen first.
    total_raw_output_tokens: usize,
    // For display: the most common raw command
    command_counts: HashMap<String, usize>,
}

/// Aggregation bucket for unsupported commands.
struct UnsupportedBucket {
    count: usize,
    example: String,
}

pub fn run(
    project: Option<&str>,
    all: bool,
    since_days: u64,
    limit: usize,
    format: &str,
    verbose: u8,
) -> Result<()> {
    let provider = ClaudeProvider;

    // Determine project filter
    let project_filter = if all {
        None
    } else if let Some(p) = project {
        Some(p.to_string())
    } else {
        // Default: current working directory
        let cwd = std::env::current_dir()?;
        let cwd_str = cwd.to_string_lossy().to_string();
        let encoded = ClaudeProvider::encode_project_path(&cwd_str);
        Some(encoded)
    };

    let sessions = provider.discover_sessions(project_filter.as_deref(), Some(since_days))?;

    if verbose > 0 {
        eprintln!("Scanning {} session files...", sessions.len());
        for s in &sessions {
            eprintln!("  {}", s.display());
        }
    }

    let mut total_commands: usize = 0;
    let mut already_ctxcrl: usize = 0;
    let mut ctxcrl_via_runtime: usize = 0;
    let mut parse_errors: usize = 0;
    let mut ctxcrl_disabled_count: usize = 0;
    let mut ctxcrl_disabled_cmds: HashMap<String, usize> = HashMap::new();
    let mut supported_map: HashMap<&'static str, SupportedBucket> = HashMap::new();
    let mut unsupported_map: HashMap<String, UnsupportedBucket> = HashMap::new();

    // Pre-pass: extract every command across every session and collect them
    // alongside their session path, so we can:
    //   1. compute the [earliest, latest] timestamp window for the tracking DB
    //      query, and
    //   2. cross-reference each tool_use against the tracking DB before
    //      classifying it (so hook-rewritten successes don't fall into the
    //      MISSED SAVINGS bucket).
    let mut all_extracted: Vec<ExtractedCommand> = Vec::new();
    for session_path in &sessions {
        let extracted = match provider.extract_commands(session_path) {
            Ok(cmds) => cmds,
            Err(e) => {
                if verbose > 0 {
                    eprintln!("Warning: skipping {}: {}", session_path.display(), e);
                }
                parse_errors += 1;
                continue;
            }
        };
        all_extracted.extend(extracted);
    }

    // Codex IMPORTANT #3 (F2): count tool_uses with no timestamp so we can
    // surface a verbose note about skipped reconciliation.
    let none_ts_count = all_extracted.iter().filter(|c| c.timestamp.is_none()).count();
    if verbose > 0 && none_ts_count > 0 {
        eprintln!(
            "[contextcrawler] {} tool_uses had no timestamp; skipping reconciliation for these",
            none_ts_count
        );
    }

    let (earliest_ts, latest_ts) = all_extracted
        .iter()
        .filter_map(|c| c.timestamp)
        .fold((None, None), |(min, max), ts| {
            let new_min = match min {
                None => Some(ts),
                Some(m) if ts < m => Some(ts),
                m => m,
            };
            let new_max = match max {
                None => Some(ts),
                Some(m) if ts > m => Some(ts),
                m => m,
            };
            (new_min, new_max)
        });

    let reconcile_ctx = load_tracked(earliest_ts, latest_ts);
    let reconcile_warning = reconcile_ctx.warning.clone();
    let tracked = reconcile_ctx.tracked;

    if verbose > 0 {
        eprintln!(
            "Reconcile: loaded {} tracked commands from {}",
            tracked.len(),
            reconcile_ctx.db_path.display()
        );
    }

    // Optional hook-health warning: only fire when we have enough signal to
    // distinguish "fresh install" from "the hook isn't reaching us".
    // See `should_emit_hook_health_warning` for the gating rationale.
    if should_emit_hook_health_warning(sessions.len(), all_extracted.len(), tracked.len())
        && reconcile_warning.is_none()
        && matches!(
            crate::hooks::hook_check::status(),
            crate::hooks::hook_check::HookStatus::Ok
        )
    {
        eprintln!(
            "[contextcrawler] hook reports healthy but {} of {} sessions show tracked-command activity (<1%) -- another agent (Codex, subagent) may be producing tool_uses without reaching the hook",
            tracked.len(),
            sessions.len()
        );
    }

    count_extracted_commands(
        &all_extracted,
        &tracked,
        DEFAULT_MATCH_WINDOW_SECS,
        &mut total_commands,
        &mut already_ctxcrl,
        &mut ctxcrl_via_runtime,
        &mut ctxcrl_disabled_count,
        &mut ctxcrl_disabled_cmds,
        &mut supported_map,
        &mut unsupported_map,
    );

    // Build report
    let mut supported: Vec<SupportedEntry> = supported_map
        .into_values()
        .map(|bucket| {
            // Pick the most common command as the display name
            let (command_with_status, status) = bucket
                .command_counts
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(name, _)| {
                    // Extract status from "command:Status" format
                    if let Some(colon_pos) = name.rfind(':') {
                        let cmd = name[..colon_pos].to_string();
                        let status_str = &name[colon_pos + 1..];
                        let status = match status_str {
                            "Passthrough" => report::CtxcrlStatus::Passthrough,
                            "NotSupported" => report::CtxcrlStatus::NotSupported,
                            _ => report::CtxcrlStatus::Existing,
                        };
                        (cmd, status)
                    } else {
                        (name, report::CtxcrlStatus::Existing)
                    }
                })
                .unwrap_or_else(|| (String::new(), report::CtxcrlStatus::Existing));

            // Derive the effective savings rate from accumulated totals rather than
            // using the first-seen sub-command's rate. This gives a weighted average
            // across all sub-commands that fell in this bucket.
            let effective_savings_pct = if bucket.total_raw_output_tokens > 0 {
                bucket.total_output_tokens as f64 * 100.0 / bucket.total_raw_output_tokens as f64
            } else {
                0.0
            };

            SupportedEntry {
                command: command_with_status,
                count: bucket.count,
                ctxcrl_equivalent: bucket.ctxcrl_equivalent,
                category: bucket.category,
                estimated_savings_tokens: bucket.total_output_tokens,
                estimated_savings_pct: effective_savings_pct,
                ctxcrl_status: status,
            }
        })
        .collect();

    // Sort by estimated savings descending
    supported.sort_by(|a, b| b.estimated_savings_tokens.cmp(&a.estimated_savings_tokens));

    let mut unsupported: Vec<UnsupportedEntry> = unsupported_map
        .into_iter()
        .map(|(base, bucket)| UnsupportedEntry {
            base_command: base,
            count: bucket.count,
            example: bucket.example,
        })
        .collect();

    // Sort by count descending
    unsupported.sort_by(|a, b| b.count.cmp(&a.count));

    // Build RTK_DISABLED examples sorted by frequency (top 5)
    let ctxcrl_disabled_examples: Vec<String> = {
        let mut sorted: Vec<_> = ctxcrl_disabled_cmds.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        sorted
            .into_iter()
            .take(5)
            .map(|(cmd, count)| format!("{} ({}x)", cmd, count))
            .collect()
    };

    let report = DiscoverReport {
        sessions_scanned: sessions.len(),
        total_commands,
        already_ctxcrl,
        ctxcrl_via_runtime,
        reconcile_warning,
        since_days,
        supported,
        unsupported,
        parse_errors,
        ctxcrl_disabled_count,
        ctxcrl_disabled_examples,
        agent_status: report::AgentIntegrationStatus::detect(),
    };

    match format {
        "json" => println!("{}", report::format_json(&report)),
        _ => print!("{}", report::format_text(&report, limit, verbose > 0)),
    }

    Ok(())
}

/// Scan codex job logs and print a compliance report.
///
/// Reports `wrapped / total` commands and the top raw-command patterns
/// that should be added to the AGENTS.md template. Mirrors the Claude
/// `discover` flow but for codex job logs instead of session jsonl.
pub fn run_codex(since_days: u64, format: &str) -> Result<()> {
    let report = codex::scan(None, Some(since_days))?;
    match format {
        "json" => println!("{}", codex::format_json(&report)),
        _ => print!("{}", codex::format_text(&report)),
    }
    Ok(())
}

/// Extract the subcommand from a command string (second word).
fn extract_subcmd(cmd: &str) -> &str {
    let parts: Vec<&str> = cmd.trim().splitn(3, char::is_whitespace).collect();
    if parts.len() >= 2 {
        parts[1]
    } else {
        ""
    }
}

/// Truncate a command for display (keep first meaningful portion).
fn truncate_command(cmd: &str) -> String {
    let trimmed = cmd.trim();
    // Keep first two words for display
    let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
    match parts.len() {
        0 => String::new(),
        1 => parts[0].to_string(),
        _ => format!("{} {}", parts[0], parts[1]),
    }
}

/// Returns true if a tool_use command is already wrapped by CTXCRL/contextcrawler.
///
/// Used by `count_extracted_commands` at the `Classification::Ignored` arm and
/// by the classifier unit tests. Keep this as the single source of truth — do
/// not duplicate the prefix check inline. (A2 Codex CRITICAL.)
fn is_already_ctxcrl_prefix(s: &str) -> bool {
    let t = s.trim();
    // branding-lint: allow legacy
    t.starts_with("rtk ") || t.starts_with("contextcrawler ")
}

/// Per-session counting loop, extracted from `run()` so it can be driven by
/// tests against a synthetic `Vec<ExtractedCommand>` fixture without spinning
/// up disk I/O or the full provider stack.
///
/// Combines A2's testable extraction with F's runtime-tracked short-circuit —
/// `tracked` carries the rows loaded from the tracking DB (see
/// [`reconcile::load_tracked`]) and `window_secs` is the timestamp tolerance
/// for matching JSONL tool_uses to executed contextcrawler invocations. Tests
/// pass an empty `tracked` slice to exercise the non-runtime path.
///
/// This is the *production* counting decision — `run()` calls this directly,
/// so any test against this function exercises the same code path that ships.
#[allow(clippy::too_many_arguments)]
fn count_extracted_commands(
    extracted: &[ExtractedCommand],
    tracked: &[TrackedCommand],
    window_secs: i64,
    total_commands: &mut usize,
    already_ctxcrl: &mut usize,
    ctxcrl_via_runtime: &mut usize,
    ctxcrl_disabled_count: &mut usize,
    ctxcrl_disabled_cmds: &mut HashMap<String, usize>,
    supported_map: &mut HashMap<&'static str, SupportedBucket>,
    unsupported_map: &mut HashMap<String, UnsupportedBucket>,
) {
    for ext_cmd in extracted {
        // Reconcile the *original* JSONL command (pre-split) against the
        // tracking DB. The hook records the full pipeline string, so chained
        // commands like `git status && git diff` are tracked as one row and
        // we want a single match to credit both halves.
        let runtime_tracked = is_runtime_tracked(
            &ext_cmd.command,
            ext_cmd.timestamp,
            ext_cmd.session_project_slug.as_deref(),
            tracked,
            window_secs,
        );

        let parts = split_command_chain(&ext_cmd.command);
        for part in parts {
            *total_commands += 1;

            if runtime_tracked {
                // Credit this command to runtime-tracked (the hook handled
                // it) and skip MISSED SAVINGS accounting entirely.
                *already_ctxcrl += 1;
                *ctxcrl_via_runtime += 1;
                continue;
            }

            // Detect RTK_DISABLED= bypass before classification
            if cmd_has_ctxcrl_disabled_prefix(part) {
                let (_prefix, actual_cmd) = strip_disabled_prefix(part);
                // Only count if the underlying command is one CTXCRL supports
                match classify_command(actual_cmd) {
                    Classification::Supported { .. } => {
                        *ctxcrl_disabled_count += 1;
                        let display = truncate_command(actual_cmd);
                        *ctxcrl_disabled_cmds.entry(display).or_insert(0) += 1;
                    }
                    _ => {
                        // RTK_DISABLED on unsupported/ignored command — not interesting
                    }
                }
                continue;
            }

            match classify_command(part) {
                Classification::Supported {
                    ctxcrl_equivalent,
                    category,
                    estimated_savings_pct,
                    status,
                } => {
                    let bucket = supported_map.entry(ctxcrl_equivalent).or_insert_with(|| {
                        SupportedBucket {
                            ctxcrl_equivalent,
                            category,
                            count: 0,
                            total_output_tokens: 0,
                            total_raw_output_tokens: 0,
                            command_counts: HashMap::new(),
                        }
                    });

                    bucket.count += 1;

                    let output_tokens = if let Some(len) = ext_cmd.output_len {
                        len / 4
                    } else {
                        let subcmd = extract_subcmd(part);
                        category_avg_tokens(category, subcmd)
                    };

                    let savings =
                        (output_tokens as f64 * estimated_savings_pct / 100.0) as usize;
                    bucket.total_output_tokens += savings;
                    bucket.total_raw_output_tokens += output_tokens;

                    let display_name = truncate_command(part);
                    let entry = bucket
                        .command_counts
                        .entry(format!("{}:{:?}", display_name, status))
                        .or_insert(0);
                    *entry += 1;
                }
                Classification::Unsupported { base_command } => {
                    let bucket = unsupported_map.entry(base_command).or_insert_with(|| {
                        UnsupportedBucket {
                            count: 0,
                            example: part.to_string(),
                        }
                    });
                    bucket.count += 1;
                }
                Classification::Ignored => {
                    if is_already_ctxcrl_prefix(part) {
                        *already_ctxcrl += 1;
                    }
                }
            }
        }
    }
}

/// Decide whether the optional hook-health warning should fire.
///
/// Codex IMPORTANT #2 (F2): the previous gate (`tracked.is_empty()` + sessions
/// non-empty + hook OK) false-positives on fresh installs that haven't
/// accumulated tracking rows yet. Tighten to:
///   - require ≥ `HOOK_HEALTH_MIN_SESSIONS` sessions (fresh-install
///     suppression),
///   - require a match rate < `HOOK_HEALTH_MIN_MATCH_RATE` (1%) — if the
///     hook is producing any meaningful volume of tracked rows we don't
///     want to nag.
///
/// Thresholds are conservative; revisit once we have field data on the
/// distribution of (sessions, matches) for healthy installs.
fn should_emit_hook_health_warning(
    sessions_count: usize,
    extracted_count: usize,
    tracked_count: usize,
) -> bool {
    const HOOK_HEALTH_MIN_SESSIONS: usize = 20;
    const HOOK_HEALTH_MIN_MATCH_RATE: f64 = 0.01;

    if sessions_count < HOOK_HEALTH_MIN_SESSIONS {
        return false;
    }
    if extracted_count == 0 {
        return false;
    }
    let match_rate = tracked_count as f64 / extracted_count as f64;
    match_rate < HOOK_HEALTH_MIN_MATCH_RATE
}

#[cfg(test)]
mod tests {
    use super::registry::{classify_command, Classification};
    use super::*;

    fn mk_cmd(command: &str) -> ExtractedCommand {
        ExtractedCommand {
            command: command.to_string(),
            output_len: None,
            session_id: "test-session".to_string(),
            output_content: None,
            is_error: false,
            sequence_index: 0,
            timestamp: None,
            session_project_slug: None,
        }
    }

    #[test]
    fn test_is_already_ctxcrl_prefix_predicate() {
        assert!(is_already_ctxcrl_prefix("contextcrawler git status"));
        assert!(is_already_ctxcrl_prefix("  contextcrawler git diff  "));
        assert!(is_already_ctxcrl_prefix("rtk git status"));
        assert!(!is_already_ctxcrl_prefix("git status"));
        assert!(!is_already_ctxcrl_prefix("contextcrawlerish"));

        // Classifier must route these down the Ignored arm so the counter
        // in count_extracted_commands actually fires.
        assert_eq!(
            classify_command("contextcrawler git status"),
            Classification::Ignored
        );
        assert_eq!(
            classify_command("rtk git status"),
            Classification::Ignored
        );
    }

    #[test]
    fn test_run_loop_counts_already_ctxcrl_via_synthetic_fixture() {
        // A2 #81: drive the actual production counting loop with a synthetic
        // session fixture and assert the `already_ctxcrl` counter increments
        // for both prefixes — covering the run() path itself, not just
        // the helper predicate. Empty `tracked` slice exercises the
        // non-runtime path (F's runtime_tracked short-circuit returns false).
        let extracted = vec![
            mk_cmd("git status"),                  // Supported
            mk_cmd("contextcrawler git status"),   // Ignored + already_ctxcrl
            mk_cmd("rtk git log"),                 // Ignored + already_ctxcrl
            mk_cmd("frobnicate --all"),            // Unsupported
        ];

        let mut total_commands: usize = 0;
        let mut already_ctxcrl: usize = 0;
        let mut ctxcrl_via_runtime: usize = 0;
        let mut ctxcrl_disabled_count: usize = 0;
        let mut ctxcrl_disabled_cmds: HashMap<String, usize> = HashMap::new();
        let mut supported_map: HashMap<&'static str, SupportedBucket> = HashMap::new();
        let mut unsupported_map: HashMap<String, UnsupportedBucket> = HashMap::new();

        count_extracted_commands(
            &extracted,
            &[],
            DEFAULT_MATCH_WINDOW_SECS,
            &mut total_commands,
            &mut already_ctxcrl,
            &mut ctxcrl_via_runtime,
            &mut ctxcrl_disabled_count,
            &mut ctxcrl_disabled_cmds,
            &mut supported_map,
            &mut unsupported_map,
        );

        assert_eq!(total_commands, 4, "every part should be counted once");
        assert_eq!(
            already_ctxcrl, 2,
            "both rtk-prefixed forms must increment the counter" // branding-lint: allow legacy
        );
        assert_eq!(ctxcrl_via_runtime, 0, "no tracked rows → no runtime credit");
        assert_eq!(ctxcrl_disabled_count, 0);
        assert!(
            unsupported_map.contains_key("frobnicate"),
            "frobnicate should land in the unsupported bucket (got keys: {:?})",
            unsupported_map.keys().collect::<Vec<_>>()
        );
        assert_eq!(unsupported_map["frobnicate"].count, 1);
    }

    #[test]
    fn test_hook_health_warning_suppressed_low_sample() {
        assert!(
            !should_emit_hook_health_warning(10, 50, 0),
            "fresh install (<20 sessions) must not trigger warning"
        );
    }

    #[test]
    fn test_hook_health_warning_suppressed_when_matches_present() {
        assert!(
            !should_emit_hook_health_warning(100, 500, 50),
            "high match rate must suppress the warning"
        );
    }

    #[test]
    fn test_hook_health_warning_fires_on_large_sample_zero_match() {
        assert!(
            should_emit_hook_health_warning(50, 500, 0),
            "≥20 sessions + zero tracked rows should fire the warning"
        );
    }

    #[test]
    fn test_hook_health_warning_fires_at_threshold() {
        assert!(
            should_emit_hook_health_warning(20, 500, 4),
            "boundary case: sessions == 20, match rate < 1% should fire"
        );
    }

    #[test]
    fn test_hook_health_warning_suppressed_no_extracted() {
        assert!(
            !should_emit_hook_health_warning(30, 0, 0),
            "zero extracted commands should suppress (no signal to gate on)"
        );
    }
}
