//! Compares CTXCRL-routed vs raw commands in a coding session.

use crate::core::utils::format_tokens;
use crate::discover::provider::{ClaudeProvider, ExtractedCommand, SessionProvider};
use crate::discover::registry::{classify_command, split_command_chain, Classification};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

/// A summarized session for display.
struct SessionSummary {
    id: String,
    date: String,
    total_cmds: usize,
    ctxcrl_cmds: usize,
    output_tokens: usize,
}

impl SessionSummary {
    fn adoption_pct(&self) -> f64 {
        if self.total_cmds == 0 {
            return 0.0;
        }
        self.ctxcrl_cmds as f64 / self.total_cmds as f64 * 100.0
    }
}

/// Count CTXCRL-covered commands from extracted commands.
/// A command is "covered" if it either:
/// - starts with "rtk " or "contextcrawler " (explicit invocation), or
/// - would be rewritten by the hook (classify_command returns Supported)
///
/// Chained commands (e.g. "cd ./path && contextcrawler ls") are split so each
/// part is classified independently — matching the discover module's behavior.
///
/// G7/#111: the live hook emits `contextcrawler <cmd>`; matching only the
/// legacy `rtk ` prefix counted those as NOT adopted and understated the
/// Adoption %. Reuses the same predicate logic as
/// `discover::is_already_ctxcrl_prefix`.
fn count_ctxcrl_commands(cmds: &[ExtractedCommand]) -> (usize, usize, usize) {
    let mut total: usize = 0;
    let mut ctxcrl: usize = 0;
    for c in cmds {
        let parts = split_command_chain(&c.command);
        for part in &parts {
            total += 1;
            let trimmed = part.trim_start();
            // branding-lint: allow legacy
            if trimmed.starts_with("rtk ")
                || trimmed.starts_with("contextcrawler ")
                || matches!(classify_command(part), Classification::Supported { .. })
            {
                ctxcrl += 1;
            }
        }
    }
    let output: usize = cmds.iter().filter_map(|c| c.output_len).sum();
    (total, ctxcrl, output)
}

fn progress_bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    format!("{}{}", "@".repeat(filled), ".".repeat(empty))
}

pub fn run(_verbose: u8) -> Result<()> {
    let provider = ClaudeProvider;
    let sessions = provider
        .discover_sessions(None, Some(30))
        .context("Failed to discover Claude Code sessions")?;

    if sessions.is_empty() {
        println!("No Claude Code sessions found in the last 30 days.");
        println!("Make sure Claude Code has been used at least once.");
        return Ok(());
    }

    // Group JSONL files by parent session (ignore subagent files)
    let mut session_files: Vec<PathBuf> = sessions
        .into_iter()
        .filter(|p| {
            // Skip subagent files — only top-level session JSONL
            !p.to_string_lossy().contains("subagents")
        })
        .collect();

    // Sort by mtime desc
    session_files.sort_by(|a, b| {
        let ma = fs::metadata(a)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let mb = fs::metadata(b)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        mb.cmp(&ma)
    });

    // Take top 10
    session_files.truncate(10);

    let mut summaries: Vec<SessionSummary> = Vec::new();

    for path in &session_files {
        let cmds = match provider.extract_commands(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if cmds.is_empty() {
            continue;
        }

        let (total_cmds, ctxcrl_cmds, output_tokens) = count_ctxcrl_commands(&cmds);

        // Extract session ID from filename
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        // G7/#100: char-safe truncation — byte slicing panics if the
        // filename stem contains a multibyte char split at the boundary.
        let short_id: String = id.chars().take(8).collect();

        // Extract date from mtime
        let date = fs::metadata(path)
            .and_then(|m| m.modified())
            .map(|t| {
                let elapsed = std::time::SystemTime::now()
                    .duration_since(t)
                    .unwrap_or_default();
                let days = elapsed.as_secs() / 86400;
                if days == 0 {
                    "Today".to_string()
                } else if days == 1 {
                    "Yesterday".to_string()
                } else {
                    format!("{}d ago", days)
                }
            })
            .unwrap_or_else(|_| "?".to_string());

        summaries.push(SessionSummary {
            id: short_id.to_string(),
            date,
            total_cmds,
            ctxcrl_cmds,
            output_tokens,
        });
    }

    if summaries.is_empty() {
        println!("No sessions with Bash commands found.");
        return Ok(());
    }

    // Display table
    let header = "ContextCrawler Session Overview (last 10)";
    println!("{}", header);
    println!("{}", "-".repeat(70));
    println!(
        "{:<12} {:<12} {:>5} {:>5} {:>9} {:<7} {:>8}",
        "Session", "Date", "Cmds", "Ctxc", "Adoption", "", "Output"
    );
    println!("{}", "-".repeat(70));

    let mut total_cmds = 0;
    let mut total_ctxcrl = 0;

    for s in &summaries {
        let pct = s.adoption_pct();
        let bar = progress_bar(pct, 5);
        total_cmds += s.total_cmds;
        total_ctxcrl += s.ctxcrl_cmds;

        println!(
            "{:<12} {:<12} {:>5} {:>5} {:>8.0}% {:<7} {:>8}",
            s.id,
            s.date,
            s.total_cmds,
            s.ctxcrl_cmds,
            pct,
            bar,
            format_tokens(s.output_tokens),
        );
    }

    println!("{}", "-".repeat(70));

    let avg_adoption = if total_cmds > 0 {
        total_ctxcrl as f64 / total_cmds as f64 * 100.0
    } else {
        0.0
    };
    println!("Average adoption: {:.0}%", avg_adoption);
    println!("Tip: Run `contextcrawler discover` to find missed ContextCrawler opportunities");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::provider::ExtractedCommand;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_cmd(command: &str, output_len: Option<usize>) -> ExtractedCommand {
        ExtractedCommand {
            command: command.to_string(),
            output_len,
            session_id: "test".to_string(),
            output_content: None,
            is_error: false,
            sequence_index: 0,
            timestamp: None,
            session_project_slug: None,
        }
    }

    // --- Progress bar ---

    #[test]
    fn test_progress_bar_boundaries() {
        assert_eq!(progress_bar(0.0, 5), ".....");
        assert_eq!(progress_bar(100.0, 5), "@@@@@");
        assert_eq!(progress_bar(50.0, 5), "@@@..");
    }

    // --- count_ctxcrl_commands: core counting logic ---

    #[test]
    fn test_count_all_ctxcrl() {
        let cmds = vec![
            make_cmd("rtk git status", Some(200)),
            make_cmd("rtk cargo test", Some(5000)),
            make_cmd("rtk git log -10", Some(800)),
        ];
        let (total, ctxcrl, output) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 3);
        assert_eq!(ctxcrl, 3);
        assert_eq!(output, 6000);
    }

    #[test]
    fn test_count_hook_rewritten_commands() {
        // Hook rewrites "git status" → "rtk git status" but JSONL logs the original.
        // count_ctxcrl_commands should detect these via classify_command.
        let cmds = vec![
            make_cmd("git status", Some(500)),
            make_cmd("cargo test", Some(3000)),
            make_cmd("echo hello", Some(100)),
        ];
        let (total, ctxcrl, output) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 3);
        // git status + cargo test are supported by CTXCRL, echo is not
        assert_eq!(ctxcrl, 2);
        assert_eq!(output, 3600);
    }

    #[test]
    fn test_count_mixed_explicit_and_hook() {
        let cmds = vec![
            make_cmd("rtk git status", Some(200)),  // explicit rtk
            make_cmd("git log -5", Some(1000)),     // hook-rewritten (logged as raw)
            make_cmd("rtk cargo test", Some(5000)), // explicit rtk
            make_cmd("echo hello", None),           // not supported
        ];
        let (total, ctxcrl, output) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 4);
        assert_eq!(ctxcrl, 3); // rtk git status + git log + rtk cargo test
        assert_eq!(output, 6200);
    }

    #[test]
    fn test_count_contextcrawler_prefixed_commands() {
        // G7/#111: the live hook emits "contextcrawler <cmd>". Even commands
        // the classifier does NOT support (e.g. an explicit contextcrawler
        // meta invocation) must count as adopted via the prefix match.
        let cmds = vec![
            make_cmd("contextcrawler git status", Some(200)),
            make_cmd("contextcrawler gain --history", Some(400)),
            make_cmd("  contextcrawler discover  ", Some(100)),
            make_cmd("echo hello", Some(50)),
        ];
        let (total, ctxcrl, output) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 4);
        // All three contextcrawler-prefixed commands count as adopted;
        // echo does not.
        assert_eq!(ctxcrl, 3, "contextcrawler-prefixed commands must count as adopted");
        assert_eq!(output, 750);
    }

    #[test]
    fn test_count_mixed_ctxcrl_and_contextcrawler_prefixes() {
        // Legacy "rtk " and current "contextcrawler " prefixes both adopted.
        let cmds = vec![
            make_cmd("rtk git status", Some(100)),
            make_cmd("contextcrawler cargo test", Some(100)),
        ];
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 2);
        assert_eq!(ctxcrl, 2, "both legacy and current prefixes are adopted");
    }

    #[test]
    fn test_count_unsupported_commands_not_counted() {
        let cmds = vec![
            make_cmd("echo hello", Some(100)),
            make_cmd("mkdir -p /tmp/foo", Some(10)),
            make_cmd("cd /tmp", Some(5)),
        ];
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 3);
        assert_eq!(ctxcrl, 0);
    }

    #[test]
    fn test_count_empty_commands() {
        let cmds: Vec<ExtractedCommand> = vec![];
        let (total, ctxcrl, output) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 0);
        assert_eq!(ctxcrl, 0);
        assert_eq!(output, 0);
    }

    // --- chained commands ---

    #[test]
    fn test_count_chained_commands_split() {
        // "cd ./path && rtk ls" is one ExtractedCommand but two logical commands.
        // cd is ignored/unsupported, ls is supported → 1 out of 2 covered.
        let cmds = vec![make_cmd("cd ./your/app/path && rtk ls", Some(200))];
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 2, "chain should split into 2 commands");
        assert_eq!(ctxcrl, 1, "only 'rtk ls' is CTXCRL-covered");
    }

    #[test]
    fn test_count_chained_all_supported() {
        // Both parts are CTXCRL-supported
        let cmds = vec![make_cmd("git status && git log -5", Some(500))];
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 2, "chain should split into 2 commands");
        assert_eq!(ctxcrl, 2, "both git commands are CTXCRL-covered");
    }

    #[test]
    fn test_count_chained_with_semicolon() {
        let cmds = vec![make_cmd("cd /tmp; git status; echo done", Some(100))];
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 3, "semicolon chain splits into 3 commands");
        assert_eq!(ctxcrl, 1, "only git status is CTXCRL-covered");
    }

    #[test]
    fn test_count_chained_no_false_inflation() {
        // Single command should still count as 1
        let cmds = vec![make_cmd("git status", Some(100))];
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 1);
        assert_eq!(ctxcrl, 1);
    }

    // --- adoption_pct ---

    #[test]
    fn test_adoption_pct_zero_division() {
        let s = SessionSummary {
            id: "x".to_string(),
            date: "Today".to_string(),
            total_cmds: 0,
            ctxcrl_cmds: 0,
            output_tokens: 0,
        };
        assert_eq!(s.adoption_pct(), 0.0);
    }

    #[test]
    fn test_adoption_pct_75_percent() {
        let s = SessionSummary {
            id: "x".to_string(),
            date: "Today".to_string(),
            total_cmds: 20,
            ctxcrl_cmds: 15,
            output_tokens: 0,
        };
        assert_eq!(s.adoption_pct(), 75.0);
    }

    // --- End-to-end: parse real JSONL and count ---

    #[test]
    fn test_parse_jsonl_session_and_count() {
        // Simulate a session with 3 Bash commands: 2 rtk, 1 raw
        let jsonl = [
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"rtk git status"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"On branch main"}]}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"git log -5"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","content":"commit abc123\ncommit def456"}]}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"rtk cargo test"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t3","content":"test result: ok. 5 passed"}]}}"#,
        ];

        let mut tmp = NamedTempFile::new().expect("create tempfile");
        for line in &jsonl {
            writeln!(tmp, "{}", line).expect("write line");
        }

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(tmp.path()).expect("parse JSONL");

        let (total, ctxcrl, _output) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 3, "should find 3 Bash commands");
        // All 3 are CTXCRL-covered: 2 explicit "rtk ..." + 1 hook-rewritten "git log"
        assert_eq!(ctxcrl, 3, "all 3 commands should be CTXCRL-covered");
    }

    #[test]
    fn test_parse_jsonl_ignores_non_bash_tools() {
        // Read/Grep/Edit tools should NOT be counted
        let jsonl = [
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/tmp/foo"}}]}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Grep","input":{"pattern":"TODO"}}]}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"rtk git status"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t3","content":"clean"}]}}"#,
        ];

        let mut tmp = NamedTempFile::new().expect("create tempfile");
        for line in &jsonl {
            writeln!(tmp, "{}", line).expect("write line");
        }

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(tmp.path()).expect("parse JSONL");

        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 1, "only Bash tool should be counted");
        assert_eq!(ctxcrl, 1, "the one Bash command is rtk");
    }

    #[test]
    fn test_parse_empty_session() {
        // Session with no Bash commands at all
        let jsonl = [
            r#"{"type":"user","message":{"role":"user","content":"Hello"}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":"Hi there!"}}"#,
        ];

        let mut tmp = NamedTempFile::new().expect("create tempfile");
        for line in &jsonl {
            writeln!(tmp, "{}", line).expect("write line");
        }

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(tmp.path()).expect("parse JSONL");

        assert!(cmds.is_empty(), "no Bash commands = empty");
    }

    #[test]
    fn test_parse_jsonl_chained_command() {
        // Claude often runs "cd ./path && git status" as a single Bash call.
        // The adoption metric should split the chain and count each part.
        let jsonl = [
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cd ./your/app/path && rtk ls"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"file1.rs\nfile2.rs"}]}}"#,
        ];

        let mut tmp = NamedTempFile::new().expect("create tempfile");
        for line in &jsonl {
            writeln!(tmp, "{}", line).expect("write line");
        }

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(tmp.path()).expect("parse JSONL");

        assert_eq!(cmds.len(), 1, "one Bash tool call");
        let (total, ctxcrl, _) = count_ctxcrl_commands(&cmds);
        assert_eq!(total, 2, "chain splits into cd + rtk ls");
        assert_eq!(ctxcrl, 1, "rtk ls is covered, cd is not");
    }

    #[test]
    fn test_extract_commands_populates_timestamp() {
        // Codex NICE-TO-HAVE #2: JSONL with a top-level ISO-8601 timestamp
        // must surface as `Some(...)` on the ExtractedCommand. The
        // reconcile path depends on this and was previously untested.
        let jsonl = [
            r#"{"type":"assistant","timestamp":"2026-05-19T10:00:00.000Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"git status"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"clean"}]}}"#,
        ];

        let mut tmp = NamedTempFile::new().expect("create tempfile");
        for line in &jsonl {
            writeln!(tmp, "{}", line).expect("write line");
        }

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(tmp.path()).expect("parse JSONL");

        assert_eq!(cmds.len(), 1);
        let ts = cmds[0]
            .timestamp
            .expect("timestamp should be Some when JSONL provides it");
        assert_eq!(ts.to_rfc3339(), "2026-05-19T10:00:00+00:00");
    }
}
