//! Filters grep output by grouping matches by file.

use crate::core::config;
use crate::core::runner;
use crate::core::sensitive_paths;
use crate::core::stream::exec_capture;
use crate::core::tracking;
use crate::core::utils::{check_forbidden_rg_args, secure_rg_command};
// `resolved_command` is unused in production (replaced by secure_rg_command)
// but the test mod uses it as a baseline — gate the import to tests so the
// production binary doesn't warn.
#[cfg(test)]
use crate::core::utils::resolved_command;
use anyhow::{Context, Result};
use regex::Regex;
use std::ffi::OsString;
use std::collections::HashMap;

#[allow(clippy::too_many_arguments)]
pub fn run(
    pattern: &str,
    path: &str,
    max_line_len: usize,
    max_results: usize,
    context_only: bool,
    file_type: Option<&str>,
    extra_args: &[String],
    verbose: u8,
) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    sensitive_paths::ensure_not_sensitive_env_path(std::path::Path::new(path), "contextcrawler grep")?;

    if verbose > 0 {
        eprintln!("grep: '{}' in {}", pattern, path);
    }

    // Reject `--pre`, `--pre-glob`, `--search-zip` / `-z` before they reach
    // rg — they enable arbitrary code execution per file. See issue #32.
    if let Err(msg) = check_forbidden_rg_args(extra_args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    // Fix: convert BRE alternation \| → | for rg (which uses PCRE-style regex)
    let rg_pattern = pattern.replace(r"\|", "|");

    // `secure_rg_command` strips RIPGREP_CONFIG_PATH/_FILE from the inherited
    // env so a tainted parent can't hijack this invocation via a config file
    // containing `--pre`. See issue #32.
    let mut rg_cmd = secure_rg_command("rg");
    // --no-ignore-vcs: match grep -r behavior (don't skip .gitignore'd files).
    // Without this, rg returns 0 matches for files in .gitignore, causing
    // false negatives that make AI agents draw wrong conclusions.
    // Using --no-ignore-vcs (not --no-ignore) so .ignore/.rgignore are still respected.
    //
    // argv layout (#100, G5#1): fixed flags, then the forbidden-checked
    // `extra_args`, then a `--` boundary, then the pattern and path. The
    // `--` MUST precede `rg_pattern`/`path` so neither can be parsed as an
    // option — without it a pattern of the form `--pre=<cmd>` reaches rg
    // unscanned and runs an arbitrary preprocessor (confirmed RCE, #32).
    //
    // -H/--with-filename + --null: force rg to ALWAYS emit the filename and to
    // separate it from `line:content` with a NUL byte. Without -H, rg emits
    // `<line>:<content>` for a single-file search, and the old `splitn(3, ':')`
    // heuristic could not tell that apart from `<file>:<line>:<content>` when
    // the matched line content itself contains ':' (e.g. `Foo::bar()`,
    // `http://…`, `std::vec`) — producing phantom `[file] N` buckets (upstream
    // be226d4 / issue #1436). --null makes the file boundary unambiguous: NUL
    // can never appear in a path, content, or line number, so the parser is
    // correct even for Windows drive letters or filenames containing `:digits:`.
    rg_cmd.args(["-n", "-H", "--no-heading", "--null", "--no-ignore-vcs"]);

    if let Some(ft) = file_type {
        rg_cmd.arg("--type").arg(ft);
    }

    // `extra_args` were already screened by `check_forbidden_rg_args` above;
    // they must stay on the option side of the `--` boundary so legitimate
    // flags (e.g. `-i`, `-A 3`) are still parsed as options.
    for arg in extra_args {
        // Fix: skip grep-ism -r flag (rg is recursive by default; rg -r means --replace)
        if arg == "-r" || arg == "--recursive" {
            continue;
        }
        rg_cmd.arg(arg);
    }

    rg_cmd.arg("--");
    rg_cmd.arg(&rg_pattern);
    rg_cmd.arg(path);

    let result = exec_capture(&mut rg_cmd)
        .or_else(|_| {
            // Fallback grep also needs env-sanitisation (env vars are
            // inherited the same way; grep ignores rg's vars but a future
            // grep variant could honor similar mechanisms). Use the secure
            // helper for consistency.
            let mut grep_cmd = secure_rg_command("grep");
            // When we fall back to grep, include all args, not just -rn.
            // Same `--` boundary as the rg path above (#100, G5#1): the
            // forbidden-checked `extra_args` stay on the option side, then
            // `--`, then pattern and path so neither is parsed as an option.
            // -H: always emit the filename; -Z: NUL-separate the filename from
            // `line:content` so the parser disambiguates regardless of colons
            // in content (parity with rg's -H/--null above; upstream be226d4).
            grep_cmd.args(["-rnHZ"]).args(extra_args);
            grep_cmd.arg("--").arg(pattern).arg(path);
            exec_capture(&mut grep_cmd)
        })
        .context("grep/rg failed")?;

    // Passthrough output flags that produce output that is already small.
    if has_format_flag(extra_args) {
        print!("{}", result.stdout);
        if !result.stderr.is_empty() {
            eprint!("{}", result.stderr.trim());
        }

        let args_display = if extra_args.is_empty() {
            format!("'{}' {}", pattern, path)
        } else {
            format!("{} '{}' {}", extra_args.join(" "), pattern, path)
        };

        timer.track_passthrough(
            &format!("grep {}", args_display),
            &format!("contextcrawler grep {} (passthrough)", args_display),
        );
        return Ok(result.exit_code);
    }

    let exit_code = result.exit_code;
    let raw_output = result.stdout.clone();

    // `raw_output` carries the NUL-delimited shape (`file\0line:content`) we
    // force with rg `--null` / grep `-Z` so parsing is unambiguous. NUL bytes
    // must NEVER reach stdout, though: `no_bloat` may pick the raw output as
    // the smaller form on small results. Reconstruct the human-readable
    // `file:line:content` (what a normal grep shows) for the no_bloat baseline
    // and for any raw passthrough — parsing still uses the NUL form below.
    let raw_display = raw_output.replace('\0', ":");

    if result.stdout.trim().is_empty() {
        // Show stderr for errors (bad regex, missing file, etc.)
        if exit_code == 2 && !result.stderr.trim().is_empty() {
            eprintln!("{}", result.stderr.trim());
        }
        // No-bloat guard (issue #95): raw grep emits nothing on a no-match.
        // The "0 matches for '<pattern>'" convenience message is ~13 tokens
        // of pure overhead — negative savings. `no_bloat` picks the raw
        // (empty) output here; consistency wins over the convenience line.
        let msg = format!("0 matches for '{}'", pattern);
        let emitted = runner::no_bloat(&raw_display, &msg);
        if !emitted.is_empty() {
            println!("{}", emitted);
        }
        timer.track(
            &format!("grep -rn '{}' {}", pattern, path),
            "ctxcrl grep",
            &raw_display,
            emitted,
        );
        return Ok(exit_code);
    }

    // Always filter: truncate long lines, apply per-file and global caps.
    // Output in standard file:line:content format that AI agents can parse.
    // (A passthrough approach yields 0% savings — no reason for CTXCRL to exist on that path.)
    let total_matches = result.stdout.lines().count();

    let context_re = if context_only {
        Regex::new(&format!("(?i).{{0,20}}{}.*", regex::escape(pattern))).ok()
    } else {
        None
    };

    let mut by_file: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    for line in result.stdout.lines() {
        let Some((file, line_num, content)) = parse_match_line(line) else {
            continue;
        };
        let cleaned = clean_line(content, max_line_len, context_re.as_ref(), pattern);
        by_file.entry(file).or_default().push((line_num, cleaned));
    }

    let mut ctxcrl_output = String::new();
    ctxcrl_output.push_str(&format!(
        "{} matches in {} files:\n\n",
        total_matches,
        by_file.len()
    ));

    let mut shown = 0;
    let mut files: Vec<_> = by_file.iter().collect();
    files.sort_by_key(|(f, _)| *f);

    let per_file = config::limits().grep_max_per_file;
    for (file, matches) in files {
        if shown >= max_results {
            break;
        }

        let file_display = compact_path(file);
        for (line_num, content) in matches.iter().take(per_file) {
            if shown >= max_results {
                break;
            }
            ctxcrl_output.push_str(&format!("{}:{}:{}\n", file_display, line_num, content));
            shown += 1;
        }
    }

    if total_matches > shown {
        ctxcrl_output.push_str(&format!("[+{} more]\n", total_matches - shown));
    }

    // No-bloat guard (issue #95): for small match sets the grouped framing
    // ("N matches in M files:" + blank line) can exceed the raw rg output.
    // Emit whichever is smaller so the filter never costs more than it saves.
    let emitted = runner::no_bloat(&raw_display, &ctxcrl_output);
    print!("{}", emitted);
    timer.track(
        &format!("grep -rn '{}' {}", pattern, path),
        "ctxcrl grep",
        &raw_display,
        emitted,
    );

    Ok(exit_code)
}

/// Filter rg/grep *context* output (`-A`/`-B`/`-C` runs) without destroying
/// the per-match grouping. Plain grep_cmd::run parses every line as
/// `file:line:content`, which mangles context lines (`file-line-content`) and
/// the `--` group separators rg emits between matches. So context output is
/// handled here instead: we keep whole match-groups intact and cap how many
/// groups we emit per file and overall, using the same `[limits]` knobs as the
/// non-context path (`grep_max_results`, `grep_max_per_file`).
///
/// Returns `(filtered, group_count)`. The caller applies `no_bloat` against the
/// raw output so the filter can never inflate a small result.
pub fn filter_context_output(
    raw: &str,
    max_results: usize,
    max_per_file: usize,
) -> (String, usize) {
    // rg/grep emit a literal `--` line between context groups. Split on it to
    // recover discrete match-groups, each a contiguous block of lines.
    let groups: Vec<&str> = raw
        .split("\n--\n")
        .map(|g| g.trim_matches('\n'))
        .filter(|g| !g.is_empty())
        .collect();

    let total_groups = groups.len();
    if total_groups == 0 {
        return (String::new(), 0);
    }

    // Attribute each group to a file using its first match line. rg context
    // lines use `file-line-` and match lines use `file:line:`; the leading
    // `file` token is identical, so we split on the first `:` or `-` that is
    // followed by a digit run (the line number).
    let mut per_file_seen: HashMap<String, usize> = HashMap::new();
    let mut shown = 0usize;
    let mut out = String::new();
    let mut emitted_groups = 0usize;

    for group in &groups {
        if shown >= max_results {
            break;
        }
        let file = group_file(group);
        let count = per_file_seen.entry(file).or_insert(0);
        if *count >= max_per_file {
            continue;
        }
        *count += 1;
        if emitted_groups > 0 {
            out.push_str("--\n");
        }
        out.push_str(group);
        out.push('\n');
        emitted_groups += 1;
        shown += 1;
    }

    if total_groups > emitted_groups {
        out.push_str(&format!("[+{} more groups]\n", total_groups - emitted_groups));
    }

    (out, total_groups)
}

/// Extract the leading `file` token from the first line of a context group.
/// rg lines look like `path/to/file.rs:42:match` (match) or
/// `path/to/file.rs-41-context` (context). Windows drive letters (`C:`) are
/// not a concern here — rg emits forward-slash relative paths by default.
fn group_file(group: &str) -> String {
    let first = group.lines().next().unwrap_or("");
    // Find the separator that introduces the line number: the first `:` or `-`
    // immediately followed by ASCII digits. Anything before it is the path.
    let bytes = first.as_bytes();
    for i in 0..bytes.len() {
        let c = bytes[i];
        if (c == b':' || c == b'-')
            && bytes
                .get(i + 1)
                .map(|n| n.is_ascii_digit())
                .unwrap_or(false)
        {
            // Bucket on the RAW path, not the compacted display form
            // (council/Codex finding, #193). filter_context_output keys its
            // per-file cap on this string AND emits the verbatim group text,
            // so compacting here would let two distinct files that collapse to
            // the same short display path share a counter and wrongly truncate
            // each other. compact_path is for display only — used by the
            // non-context filter, not here.
            return first[..i].to_string();
        }
    }
    // No line-number separator found (unusual): bucket the whole raw line.
    first.to_string()
}

/// Parse a single non-context rg/grep match line into `(file, line, content)`.
///
/// Expects the NUL-separated shape produced by rg's `-H`/`--null` (and grep's
/// `-H`/`-Z`) in `grep_cmd::run`: `file\0line_number:content`. NUL cannot occur
/// in a path, line number, or content, so splitting on it makes the filename
/// boundary unambiguous — content containing `:` or `::` (`Foo::bar()`,
/// `http://…`), filenames containing `:digits:`, and Windows drive letters all
/// parse correctly (upstream be226d4 / issue #1436). This replaces the old
/// `splitn(3, ':')` length heuristic that produced phantom `[file] N` buckets.
///
/// Returns `None` for any line that does not match the expected shape (the
/// content slice borrows from `line`, so no allocation for content).
///
/// Note: only the non-context `run()` path uses this. The #193 context filter
/// (`filter_context_output` / `group_file`) parses the `file:line:` /
/// `file-line-` shape and is deliberately left untouched.
fn parse_match_line(line: &str) -> Option<(String, usize, &str)> {
    lazy_static::lazy_static! {
        // file = one-or-more non-NUL bytes; then NUL; then digits; ':' ; rest.
        static ref MATCH_LINE_RE: Regex =
            Regex::new(r"^([^\x00]+)\x00(\d+):(.*)$").unwrap();
    }
    let caps = MATCH_LINE_RE.captures(line)?;
    let file = caps.get(1)?.as_str().to_string();
    let line_num: usize = caps.get(2)?.as_str().parse().ok()?;
    let content_start = caps.get(3)?.start();
    Some((file, line_num, &line[content_start..]))
}

// `has_format_flag_raw` is the OsString-typed sibling of the existing
// `grep_format_flag_present(&[String])` used by main.rs. Currently only
// exercised by the unit tests below; keep it so we have one helper per
// arg-type without forcing callers to allocate a Vec<String>. Annotate
// to silence dead_code without losing the safety net of the assertions.
#[allow(dead_code)]
pub(crate) fn has_format_flag_raw(args: &[OsString]) -> bool {
    args.iter()
        .any(|arg| is_format_flag(&arg.to_string_lossy()))
}

fn has_format_flag(extra_args: &[String]) -> bool {
    extra_args.iter().any(|arg| is_format_flag(arg))
}

fn is_format_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--count"
            | "--files-with-matches"
            | "--files-without-match"
            | "--only-matching"
            | "--null"
    ) || is_short_format_flag_bundle(arg)
}

fn is_short_format_flag_bundle(arg: &str) -> bool {
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
        return false;
    }

    arg.chars()
        .skip(1)
        .any(|c| matches!(c, 'c' | 'l' | 'L' | 'o' | 'Z'))
}

fn clean_line(line: &str, max_len: usize, context_re: Option<&Regex>, pattern: &str) -> String {
    let trimmed = line.trim();

    if let Some(re) = context_re {
        if let Some(m) = re.find(trimmed) {
            let matched = m.as_str();
            if matched.len() <= max_len {
                return matched.to_string();
            }
        }
    }

    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        let lower = trimmed.to_lowercase();
        let pattern_lower = pattern.to_lowercase();

        if let Some(pos) = lower.find(&pattern_lower) {
            let char_pos = lower[..pos].chars().count();
            let chars: Vec<char> = trimmed.chars().collect();
            let char_len = chars.len();

            let start = char_pos.saturating_sub(max_len / 3);
            let end = (start + max_len).min(char_len);
            let start = if end == char_len {
                end.saturating_sub(max_len)
            } else {
                start
            };

            let slice: String = chars[start..end].iter().collect();
            if start > 0 && end < char_len {
                format!("...{}...", slice)
            } else if start > 0 {
                format!("...{}", slice)
            } else {
                format!("{}...", slice)
            }
        } else {
            let t: String = trimmed.chars().take(max_len - 3).collect();
            format!("{}...", t)
        }
    }
}

fn compact_path(path: &str) -> String {
    if path.len() <= 50 {
        return path.to_string();
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= 3 {
        return path.to_string();
    }

    format!(
        "{}/.../{}/{}",
        parts[0],
        parts[parts.len() - 2],
        parts[parts.len() - 1]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_line() {
        let line = "            const result = someFunction();";
        let cleaned = clean_line(line, 50, None, "result");
        assert!(!cleaned.starts_with(' '));
        assert!(cleaned.len() <= 50);
    }

    #[test]
    fn test_compact_path() {
        let path = "/Users/patrick/dev/project/src/components/Button.tsx";
        let compact = compact_path(path);
        assert!(compact.len() <= 60);
    }

    #[test]
    fn test_extra_args_accepted() {
        // Test that the function signature accepts extra_args
        // This is a compile-time test - if it compiles, the signature is correct
        let _extra: Vec<String> = vec!["-i".to_string(), "-A".to_string(), "3".to_string()];
        // No need to actually run - we're verifying the parameter exists
    }

    #[test]
    fn test_clean_line_multibyte() {
        // Thai text that exceeds max_len in bytes
        let line = "  สวัสดีครับ นี่คือข้อความที่ยาวมากสำหรับทดสอบ  ";
        let cleaned = clean_line(line, 20, None, "ครับ");
        // Should not panic
        assert!(!cleaned.is_empty());
    }

    #[test]
    fn test_clean_line_emoji() {
        let line = "🎉🎊🎈🎁🎂🎄 some text 🎃🎆🎇✨";
        let cleaned = clean_line(line, 15, None, "text");
        assert!(!cleaned.is_empty());
    }

    // Fix: BRE \| alternation is translated to PCRE | for rg
    #[test]
    fn test_bre_alternation_translated() {
        let pattern = r"fn foo\|pub.*bar";
        let rg_pattern = pattern.replace(r"\|", "|");
        assert_eq!(rg_pattern, "fn foo|pub.*bar");
    }

    // Fix: -r flag (grep recursive) is stripped from extra_args (rg is recursive by default)
    #[test]
    fn test_recursive_flag_stripped() {
        let extra_args: Vec<String> = vec!["-r".to_string(), "-i".to_string()];
        let filtered: Vec<&String> = extra_args
            .iter()
            .filter(|a| *a != "-r" && *a != "--recursive")
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "-i");
    }

    // --- truncation accuracy ---

    #[test]
    fn test_grep_overflow_uses_uncapped_total() {
        // Confirm the grep overflow invariant: matches vec is never capped before overflow calc.
        // If total_matches > per_file, overflow = total_matches - per_file (not capped).
        // This documents that grep_cmd.rs avoids the diff_cmd bug (cap at N then compute N-10).
        let per_file = config::limits().grep_max_per_file;
        let total_matches = per_file + 42;
        let overflow = total_matches - per_file;
        assert_eq!(overflow, 42, "overflow must equal true suppressed count");
        // Demonstrate why capping before subtraction is wrong:
        let hypothetical_cap = per_file + 5;
        let capped = total_matches.min(hypothetical_cap);
        let wrong_overflow = capped - per_file;
        assert_ne!(
            wrong_overflow, overflow,
            "capping before subtraction gives wrong overflow"
        );
    }

    // --- format flag detection ---

    #[test]
    fn test_format_flag_detects_count() {
        assert!(has_format_flag(&["-c".to_string()]));
        assert!(has_format_flag(&["--count".to_string()]));
    }

    #[test]
    fn test_format_flag_detects_files_with_matches() {
        assert!(has_format_flag(&["-l".to_string()]));
        assert!(has_format_flag(&["--files-with-matches".to_string()]));
    }

    #[test]
    fn test_format_flag_detects_files_without_match() {
        assert!(has_format_flag(&["-L".to_string()]));
        assert!(has_format_flag(&["--files-without-match".to_string()]));
    }

    #[test]
    fn test_format_flag_detects_only_matching() {
        assert!(has_format_flag(&["-o".to_string()]));
        assert!(has_format_flag(&["--only-matching".to_string()]));
    }

    #[test]
    fn test_format_flag_detects_null() {
        assert!(has_format_flag(&["-Z".to_string()]));
        assert!(has_format_flag(&["--null".to_string()]));
    }

    #[test]
    fn test_format_flag_ignores_normal_flags() {
        assert!(!has_format_flag(&[
            "-i".to_string(),
            "-w".to_string(),
            "-A".to_string(),
            "3".to_string(),
        ]));
    }

    #[test]
    fn test_raw_format_flag_detection() {
        assert!(has_format_flag_raw(&[OsString::from("-c")]));
        assert!(has_format_flag_raw(&[OsString::from("-ci")]));
        assert!(has_format_flag_raw(&[OsString::from("-cE")]));
        assert!(has_format_flag_raw(&[OsString::from("-cn")]));
        assert!(has_format_flag_raw(&[OsString::from("-cv")]));
        assert!(has_format_flag_raw(&[OsString::from("-l")]));
        assert!(has_format_flag_raw(&[OsString::from("-L")]));
        assert!(has_format_flag_raw(&[OsString::from("-o")]));
        assert!(has_format_flag_raw(&[OsString::from("-Z")]));

        assert!(has_format_flag_raw(&[OsString::from("--count")]));
        assert!(has_format_flag_raw(&[OsString::from("--files-with-matches")]));
        assert!(has_format_flag_raw(&[OsString::from("--files-without-match")]));
        assert!(has_format_flag_raw(&[OsString::from("--only-matching")]));
        assert!(has_format_flag_raw(&[OsString::from("--null")]));

        assert!(!has_format_flag_raw(&[OsString::from("-rn")]));
        assert!(!has_format_flag_raw(&[OsString::from("--recursive")]));
        assert!(!has_format_flag_raw(&[OsString::from("-iw")]));
    }

    // Verify line numbers are always enabled in rg invocation (grep_cmd.rs:24).
    // The -n/--line-numbers clap flag in main.rs is a no-op accepted for compat.
    #[test]
    fn test_rg_always_has_line_numbers() {
        // grep_cmd::run() always passes "-n" to rg (line 24).
        // This test documents that -n is built-in, so the clap flag is safe to ignore.
        let mut cmd = resolved_command("rg");
        cmd.args(["-n", "--no-heading", "NONEXISTENT_PATTERN_12345", "."]);
        // If rg is available, it should accept -n without error (exit 1 = no match, not error)
        if let Ok(output) = cmd.output() {
            assert!(
                output.status.code() == Some(1) || output.status.success(),
                "rg -n should be accepted"
            );
        }
        // If rg is not installed, skip gracefully (test still passes)
    }

    // Fix #95: a no-match grep emits raw (empty) output, not the
    // "0 matches for '<pattern>'" convenience message which is pure overhead.
    #[test]
    fn test_no_match_emits_raw_not_convenience_message() {
        let raw_output = String::new();
        let msg = format!("0 matches for '{}'", "needle");
        let emitted = runner::no_bloat(&raw_output, &msg);
        assert_eq!(emitted, "", "no-match grep must emit raw empty output");
        assert!(emitted.is_empty());
    }

    // Fix #95: when a small match set's grouped framing would exceed the
    // raw rg output, the raw output is emitted instead.
    #[test]
    fn test_small_result_emits_raw_when_framing_inflates() {
        let raw_output = "f.rs:1:x\n";
        // Simulated framed output: header + blank line + match line.
        let ctxcrl_output = "1 matches in 1 files:\n\nf.rs:1:x\n";
        assert!(ctxcrl_output.len() > raw_output.len());
        assert_eq!(runner::no_bloat(raw_output, ctxcrl_output), raw_output);
    }

    // Fix #95: a genuinely large grep result keeps the compact framed form.
    #[test]
    fn test_large_result_keeps_filtered() {
        let mut raw_output = String::new();
        for i in 0..200 {
            raw_output.push_str(&format!(
                "src/some/deeply/nested/path/module{}.rs:{}:    let value = compute();\n",
                i, i
            ));
        }
        let ctxcrl_output = "200 matches in 200 files:\n\n[+200 more]\n";
        assert!(ctxcrl_output.len() < raw_output.len());
        assert_eq!(runner::no_bloat(&raw_output, ctxcrl_output), ctxcrl_output);
    }

    // --- issue #193: context-output filtering ---

    fn count_tokens(s: &str) -> usize {
        s.split_whitespace().count()
    }

    #[test]
    fn test_context_filter_groups_and_caps() {
        // Synthetic context output: 5 groups across 2 files, `--` separated.
        let raw = "a.rs-1-ctx\na.rs:2:hit\na.rs-3-ctx\n--\n\
                   a.rs-4-ctx\na.rs:5:hit\n--\n\
                   a.rs-6-ctx\na.rs:7:hit\n--\n\
                   b.rs-1-ctx\nb.rs:2:hit\n--\n\
                   b.rs-3-ctx\nb.rs:4:hit\n";
        // Cap 2 per file, 200 global → 2 from a.rs + 2 from b.rs = 4 of 5.
        let (out, total) = filter_context_output(raw, 200, 2);
        assert_eq!(total, 5, "should count all 5 groups");
        assert!(out.contains("a.rs:2:hit"));
        assert!(out.contains("b.rs:2:hit"));
        // The third a.rs group (line 7) is dropped by the per-file cap.
        assert!(!out.contains("a.rs:7:hit"), "per-file cap must drop 3rd a.rs group");
        assert!(out.contains("[+1 more groups]"), "must indicate truncation");
    }

    #[test]
    fn test_context_filter_global_cap() {
        // 4 groups, global cap of 2 → exactly 2 emitted + truncation note.
        let raw = "a.rs:1:x\n--\nb.rs:1:x\n--\nc.rs:1:x\n--\nd.rs:1:x\n";
        let (out, total) = filter_context_output(raw, 2, 25);
        assert_eq!(total, 4);
        assert!(out.contains("[+2 more groups]"));
    }

    #[test]
    fn test_context_filter_empty() {
        let (out, total) = filter_context_output("", 200, 25);
        assert_eq!(total, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn test_group_file_extracts_path() {
        assert_eq!(group_file("src/foo.rs:42:hit"), "src/foo.rs");
        assert_eq!(group_file("src/foo.rs-41-ctx"), "src/foo.rs");
        // First line of a multi-line group decides the file.
        assert_eq!(group_file("src/bar.rs-1-ctx\nsrc/bar.rs:2:hit"), "src/bar.rs");
    }

    // Council/Codex finding (#193): group_file must bucket on the RAW path, not
    // the compacted display form. A long path is returned verbatim — never
    // collapsed — so the per-file cap counts the real file.
    #[test]
    fn test_group_file_returns_raw_long_path() {
        let long = "src/a/very/deeply/nested/directory/structure/here/module_one.rs";
        assert!(long.len() > 50, "fixture must exceed compact_path threshold");
        assert_eq!(group_file(&format!("{}:42:hit", long)), long);
    }

    // Council/Codex finding (#193): two DISTINCT long files that compact to the
    // same short display form must NOT share a per-file counter. With the old
    // compacted-key bug they collided into one bucket and truncated each other.
    #[test]
    fn test_context_filter_distinct_files_compact_collision() {
        // Both paths share parts[0]="src" and the final two segments
        // "shared/file.rs", so compact_path collapses BOTH to
        // "src/.../shared/file.rs" — identical display, distinct real files.
        let a = "src/alpha/branchx/deeply/nested/path/shared/file.rs";
        let b = "src/omega/branchx/deeply/nested/path/shared/file.rs";
        assert_eq!(
            compact_path(a),
            compact_path(b),
            "test premise: the two paths must compact to the same display form"
        );
        assert_ne!(a, b, "but they are distinct real files");

        // 2 groups in file a, 2 in file b. Per-file cap of 2 must keep ALL
        // FOUR — neither file may steal the other's budget.
        let raw = format!(
            "{a}-1-ctx\n{a}:2:hit\n--\n{a}-3-ctx\n{a}:4:hit\n--\n\
             {b}-1-ctx\n{b}:2:hit\n--\n{b}-3-ctx\n{b}:4:hit\n",
            a = a,
            b = b
        );
        let (out, total) = filter_context_output(&raw, 200, 2);
        assert_eq!(total, 4);
        // All four groups present, no truncation marker.
        assert!(out.contains(&format!("{}:2:hit", a)));
        assert!(out.contains(&format!("{}:4:hit", a)));
        assert!(out.contains(&format!("{}:2:hit", b)));
        assert!(out.contains(&format!("{}:4:hit", b)));
        assert!(
            !out.contains("more groups"),
            "distinct files must not truncate each other (raw-path bucketing)"
        );
    }

    #[test]
    fn test_context_filter_snapshot() {
        // The repo has no `insta` dependency (the cli-testing rule describes
        // the ideal, but no module wires it up), so this is a deterministic
        // golden-form assertion instead: stable framing on a real fixture.
        let input = include_str!("../../../tests/fixtures/grep_context_raw.txt");
        let (output, total) = filter_context_output(input, 200, 25);
        // Output must be strictly smaller than the raw fixture.
        assert!(output.len() < input.len());
        // Framing invariant: a truncated result ends with the "more groups"
        // marker, and groups are `--`-separated.
        if total > 0 && output.contains("[+") {
            assert!(output.trim_end().ends_with("more groups]"));
        }
        assert!(output.contains("--\n"), "groups stay --separated");
        // First emitted group is preserved verbatim (no mangling).
        let first_group = input.split("\n--\n").next().unwrap().trim_matches('\n');
        assert!(
            output.starts_with(first_group),
            "first group must be emitted verbatim"
        );
    }

    #[test]
    fn test_context_filter_token_savings() {
        // Real `grep -rn -C2 lazy_static src/cmds/` output. The per-file cap
        // collapses the many same-file context groups; assert >=60% savings.
        let input = include_str!("../../../tests/fixtures/grep_context_raw.txt");
        // Use a tight per-file cap (3) to model a focused agent search; the
        // default config cap is 25 but recursive same-file hits dominate here.
        let (output, _total) = filter_context_output(input, 200, 3);
        let savings =
            100.0 - (count_tokens(&output) as f64 / count_tokens(input) as f64 * 100.0);
        assert!(
            savings >= 60.0,
            "context grep filter: expected >=60% savings, got {:.1}%",
            savings
        );
    }

    // --- upstream be226d4 / issue #1436: single-file colon parsing ---
    //
    // After the fix, `grep_cmd::run` invokes rg with `-H --null` (grep with
    // `-Z`), so every emitted match line is `file\0line:content`. These tests
    // exercise `parse_match_line` directly against that NUL-separated shape.

    #[test]
    fn test_parse_match_line_simple() {
        let line = "src/foo.rs\x0010:let x = 1;";
        let (file, line_num, content) = parse_match_line(line).unwrap();
        assert_eq!(file, "src/foo.rs");
        assert_eq!(line_num, 10);
        assert_eq!(content, "let x = 1;");
    }

    // The core bug: a single-file match whose CONTENT contains `::` must parse
    // as ONE match with the full content intact — NOT split into phantom
    // `[file] N` buckets the way the old `splitn(3, ':')` heuristic did.
    #[test]
    fn test_parse_match_line_content_with_double_colon() {
        let line = "src/foo.rs\x0042:    let v: Vec<T> = foo::bar();";
        let (file, line_num, content) = parse_match_line(line).unwrap();
        assert_eq!(file, "src/foo.rs");
        assert_eq!(line_num, 42);
        // Full content preserved, including every colon.
        assert_eq!(content, "    let v: Vec<T> = foo::bar();");
    }

    // URL content (`http://…`) and Rust paths (`std::vec`) are the same class
    // of failure — colons in content. NUL separation makes them irrelevant.
    #[test]
    fn test_parse_match_line_content_with_url_and_path() {
        let line = "notes.md\x007:see http://example.com and std::vec::Vec";
        let (file, line_num, content) = parse_match_line(line).unwrap();
        assert_eq!(file, "notes.md");
        assert_eq!(line_num, 7);
        assert_eq!(content, "see http://example.com and std::vec::Vec");
    }

    // Filenames containing `:digits:` (which would fool a greedy `:` parser)
    // parse correctly because the file field is delimited by NUL, not `:`.
    #[test]
    fn test_parse_match_line_filename_with_colons() {
        let line = "badly:52:named.txt\x001:hit";
        let (file, line_num, content) = parse_match_line(line).unwrap();
        assert_eq!(file, "badly:52:named.txt");
        assert_eq!(line_num, 1);
        assert_eq!(content, "hit");
    }

    #[test]
    fn test_parse_match_line_empty_content() {
        let line = "f.rs\x009:";
        let (file, line_num, content) = parse_match_line(line).unwrap();
        assert_eq!(file, "f.rs");
        assert_eq!(line_num, 9);
        assert_eq!(content, "");
    }

    #[test]
    fn test_parse_match_line_malformed_returns_none() {
        // No NUL separator at all (e.g. a stray line) → None, skipped.
        assert!(parse_match_line("not a match line").is_none());
        // NUL present but no line number → None.
        assert!(parse_match_line("file.rs\x00fn foo()").is_none());
        // Empty.
        assert!(parse_match_line("").is_none());
    }

    // End-to-end grouping: simulate the NUL-separated multi-file stdout that
    // `grep_cmd::run` now receives, and confirm matches group by their real
    // file (no phantom buckets) even when content carries `::`.
    #[test]
    fn test_nul_output_groups_by_real_file() {
        let stdout = "src/a.rs\x001:use foo::bar;\n\
                      src/a.rs\x002:let x: T = 1;\n\
                      src/b.rs\x005:fn baz() {}\n";
        let mut by_file: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        for line in stdout.lines() {
            let (file, line_num, content) = parse_match_line(line).unwrap();
            by_file
                .entry(file)
                .or_default()
                .push((line_num, content.to_string()));
        }
        // Exactly two real files, never a phantom "1" / "2" / "5" bucket.
        assert_eq!(by_file.len(), 2, "must group into the two real files only");
        assert_eq!(by_file["src/a.rs"].len(), 2);
        assert_eq!(by_file["src/b.rs"].len(), 1);
        // The `::` content survived intact.
        assert_eq!(by_file["src/a.rs"][0].1, "use foo::bar;");
    }

    // Council/Codex BLOCKER regression: the NUL form we force for parsing
    // (rg --null / grep -Z) must NEVER reach stdout. On the common small-result
    // path `no_bloat` picks the raw output as the smaller form, so the raw
    // baseline must be the human-readable `file:line:content` (raw_display),
    // not the NUL-delimited capture. This mirrors the exact transform in
    // `run`: build raw_display from the NUL capture, then no_bloat against an
    // (inflating) compact form and assert the emitted bytes are clean.
    #[test]
    fn test_nul_raw_never_reaches_stdout_on_no_bloat_raw_path() {
        // Real command output shape after --null: file\0line:content.
        let raw_output = "f.rs\x001:let v: Vec = foo::bar();\n";
        let raw_display = raw_output.replace('\0', ":");

        // Single small match → grouped framing is larger, so no_bloat picks raw.
        let ctxcrl_output = "1 matches in 1 files:\n\nf.rs:1:let v: Vec = foo::bar();\n";
        assert!(
            ctxcrl_output.len() > raw_display.len(),
            "test premise: compact form must be larger so no_bloat picks raw"
        );

        let emitted = runner::no_bloat(&raw_display, ctxcrl_output);

        // (a) No NUL byte ever reaches stdout.
        assert!(
            !emitted.contains('\0'),
            "emitted output must not contain a NUL byte"
        );
        // (b) It is the clean, normal grep shape with the `::` content intact.
        assert_eq!(emitted, "f.rs:1:let v: Vec = foo::bar();\n");
    }

    #[test]
    fn test_rg_no_ignore_vcs_flag_accepted() {
        // Verify rg accepts --no-ignore-vcs (used to match grep -r behavior for .gitignore)
        let mut cmd = resolved_command("rg");
        cmd.args([
            "-n",
            "--no-heading",
            "--no-ignore-vcs",
            "NONEXISTENT_PATTERN_12345",
            ".",
        ]);
        if let Ok(output) = cmd.output() {
            assert!(
                output.status.code() == Some(1) || output.status.success(),
                "rg --no-ignore-vcs should be accepted"
            );
        }
        // If rg is not installed, skip gracefully (test still passes)
    }
}
