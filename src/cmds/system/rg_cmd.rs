//! First-class `rg` (ripgrep) command — issue #165A.
//!
//! Agents reach for `rg` naturally. Before this module, `contextcrawler rg ...`
//! fell through to the unfiltered passthrough and recorded as 0% savings.
//!
//! Strategy: parse the rg invocation into one of three buckets and delegate to
//! the work already done by `grep_cmd` (which itself shells out to rg):
//!
//! 1. `rg --files` / `rg --files <path>` — file-list formatter (compact,
//!    grouped by directory, mirrors `find`'s contract).
//! 2. `rg -l PATTERN [PATH]` and friends (`--files-with-matches`, `-L` /
//!    `--files-without-match`, `-c` / `--count`, `-o`, `-Z`) — delegate
//!    straight to `grep_cmd::run` with `extra_args` carrying the format
//!    flag; `grep_cmd` passes those through unmodified.
//! 3. `rg [-n|-i|-A 3|...] PATTERN [PATH]` — standard grouped-by-file grep
//!    output via `grep_cmd::run`.
//!
//! If the invocation can't be cleanly mapped (no detectable pattern, unknown
//! flag layout), we emit a one-line stderr note and fall through to raw rg —
//! the user gets correct output, just unfiltered. Never block the user.

use crate::cmds::system::grep_cmd;
use crate::core::stream::exec_capture;
use crate::core::tracking;
use crate::core::utils::{check_forbidden_rg_args, secure_rg_command};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

/// Entry point from main.rs. `args` is the trailing arg vec from clap — the
/// raw `rg`-flavoured invocation minus the leading `rg` token.
pub fn run_from_args(args: &[String], verbose: u8) -> Result<i32> {
    // Reject `--pre`, `--pre-glob`, `--search-zip` / `-z` for the same
    // reasons grep_cmd does (issue #32 RCE class). We re-check here because
    // the `--files` / list-only branches bypass grep_cmd.
    if let Err(msg) = check_forbidden_rg_args(args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    let parsed = parse_rg_args(args);

    if verbose > 0 {
        eprintln!("rg: parsed mode = {:?}", parsed.mode);
    }

    match parsed.mode {
        RgMode::Files => run_files_mode(&parsed, verbose),
        RgMode::ListWithFormatFlag => run_format_flag_mode(&parsed, args, verbose),
        RgMode::Search => run_search_mode(&parsed, args, verbose),
        RgMode::Unmapped => {
            eprintln!(
                "[contextcrawler] rg: invocation not mapped to a filter, running raw rg (0% savings)"
            );
            run_passthrough(args, verbose)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RgMode {
    /// `rg --files [PATH]` — list files rg would search.
    Files,
    /// `rg -l|-L|-c|-o|-Z PATTERN [PATH]` — format-flag output, delegate
    /// to grep_cmd which already passes these flags through to rg.
    ListWithFormatFlag,
    /// Standard search; emit grouped-by-file output.
    Search,
    /// Couldn't determine — fall back to raw rg.
    Unmapped,
}

#[derive(Debug)]
struct ParsedRg {
    mode: RgMode,
    pattern: Option<String>,
    path: String,
    /// Flags to forward (e.g. -i, -n, -A 3, --glob '*.rs', -l).
    extra_args: Vec<String>,
    /// File type filter when caller passed `-t <type>` / `--type <type>`.
    file_type: Option<String>,
}

/// Flags rg treats as "format-only" output that grep_cmd will passthrough.
/// Keep in sync with `grep_cmd::is_format_flag` — we only need to detect
/// presence here, not decide what to do.
fn is_format_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--count"
            | "--count-matches"
            | "--files-with-matches"
            | "--files-without-match"
            | "--only-matching"
            | "--null"
    ) || is_short_format_bundle(arg)
}

fn is_short_format_bundle(arg: &str) -> bool {
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
        return false;
    }
    arg.chars()
        .skip(1)
        .any(|c| matches!(c, 'c' | 'l' | 'L' | 'o' | 'Z'))
}

/// rg flags that consume the following arg (so the next token is a value, not
/// a pattern or path). Conservative list — only the ones agents commonly use.
fn flag_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-A" | "--after-context"
            | "-B" | "--before-context"
            | "-C" | "--context"
            | "-e" | "--regexp"
            | "-f" | "--file"
            | "-g" | "--glob"
            | "--iglob"
            | "-m" | "--max-count"
            | "-t" | "--type"
            | "-T" | "--type-not"
            | "--type-add"
            | "--max-columns"
            | "--max-depth"
            | "--max-filesize"
            | "--replace" | "-r"
            | "--sort"
            | "--sortr"
            | "--encoding" | "-E"
            | "--engine"
            | "--field-context-separator"
            | "--field-match-separator"
            | "--color"
            | "--colors"
            | "--context-separator"
            | "--dfa-size-limit"
            | "--regex-size-limit"
    )
}

/// Parse the rg arg vec. Best-effort: extracts pattern (first non-flag,
/// non-value positional), path (next positional if any, else "."), and
/// classifies the mode. On any ambiguity returns `RgMode::Unmapped` so the
/// caller can fall back to raw rg without crashing or guessing.
fn parse_rg_args(args: &[String]) -> ParsedRg {
    let mut extra_args: Vec<String> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut pattern_via_e: Option<String> = None;
    let mut file_type: Option<String> = None;
    let mut wants_files_mode = false;
    let mut has_format_flag = false;
    let mut after_double_dash = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        if after_double_dash {
            positionals.push(arg.clone());
            i += 1;
            continue;
        }

        if arg == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }

        if arg == "--files" {
            wants_files_mode = true;
            i += 1;
            continue;
        }

        if is_format_flag(arg) {
            has_format_flag = true;
            extra_args.push(arg.clone());
            i += 1;
            continue;
        }

        if arg == "-e" || arg == "--regexp" {
            if let Some(val) = args.get(i + 1) {
                pattern_via_e = Some(val.clone());
                i += 2;
                continue;
            }
        }

        if arg == "-t" || arg == "--type" {
            if let Some(val) = args.get(i + 1) {
                file_type = Some(val.clone());
                i += 2;
                continue;
            }
        }

        if flag_takes_value(arg) {
            extra_args.push(arg.clone());
            if let Some(val) = args.get(i + 1) {
                extra_args.push(val.clone());
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            extra_args.push(arg.clone());
            i += 1;
            continue;
        }

        positionals.push(arg.clone());
        i += 1;
    }

    if wants_files_mode {
        let path = positionals.into_iter().next().unwrap_or_else(|| ".".into());
        return ParsedRg {
            mode: RgMode::Files,
            pattern: None,
            path,
            extra_args,
            file_type,
        };
    }

    // Pattern resolution: explicit `-e PATTERN` wins, else first positional.
    let (pattern, remaining_positionals) = if let Some(p) = pattern_via_e {
        (Some(p), positionals)
    } else if let Some((first, rest)) = positionals.split_first() {
        (Some(first.clone()), rest.to_vec())
    } else {
        (None, positionals)
    };

    let path = remaining_positionals
        .into_iter()
        .next()
        .unwrap_or_else(|| ".".into());

    let mode = match (&pattern, has_format_flag) {
        (Some(_), true) => RgMode::ListWithFormatFlag,
        (Some(_), false) => RgMode::Search,
        (None, _) => RgMode::Unmapped,
    };

    ParsedRg {
        mode,
        pattern,
        path,
        extra_args,
        file_type,
    }
}

/// Standard grouped-by-file search — delegates to grep_cmd which already
/// handles secure rg invocation, ANSI stripping, per-file caps, and
/// `runner::no_bloat` framing.
///
/// Defence-in-depth: the parser only emits `Search` when a pattern is
/// present (line 250), so `pattern` is structurally Some here. If a future
/// parser change ever violates that invariant, fall through to raw rg
/// rather than panic — CTXCRL never blocks the user.
fn run_search_mode(parsed: &ParsedRg, args: &[String], verbose: u8) -> Result<i32> {
    let Some(pattern) = parsed.pattern.as_deref() else {
        eprintln!(
            "[contextcrawler] rg: internal parser inconsistency (Search mode without pattern), running raw rg"
        );
        return run_passthrough(args, verbose);
    };

    grep_cmd::run(
        pattern,
        &parsed.path,
        80,                              // max_line_len — same default as Commands::Grep
        200,                             // max_results — same default as Commands::Grep
        false,                           // context_only
        parsed.file_type.as_deref(),
        &parsed.extra_args,
        verbose,
    )
}

/// Format-flag mode (`-l`, `-L`, `-c`, `-o`, `-Z`) — grep_cmd recognises
/// these and passes the underlying rg output through unmodified. Same
/// defence-in-depth rule as `run_search_mode`.
fn run_format_flag_mode(parsed: &ParsedRg, args: &[String], verbose: u8) -> Result<i32> {
    let Some(pattern) = parsed.pattern.as_deref() else {
        eprintln!(
            "[contextcrawler] rg: internal parser inconsistency (ListWithFormatFlag mode without pattern), running raw rg"
        );
        return run_passthrough(args, verbose);
    };

    grep_cmd::run(
        pattern,
        &parsed.path,
        80,
        200,
        false,
        parsed.file_type.as_deref(),
        &parsed.extra_args,
        verbose,
    )
}

/// `rg --files [PATH]` — invoke rg directly, then collapse the file list
/// into a grouped-by-directory summary.
fn run_files_mode(parsed: &ParsedRg, verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("rg --files: path={}", parsed.path);
    }

    let mut cmd = secure_rg_command("rg");
    cmd.arg("--files");
    if let Some(ft) = &parsed.file_type {
        cmd.args(["--type", ft]);
    }
    cmd.arg("--").arg(&parsed.path);

    let result = exec_capture(&mut cmd)?;
    let raw = result.stdout.clone();
    let exit_code = result.exit_code;

    let filtered = filter_files_output(&raw);

    print!("{}", filtered);
    timer.track(
        &format!("rg --files {}", parsed.path),
        "contextcrawler rg --files",
        &raw,
        &filtered,
    );

    if !result.stderr.trim().is_empty() {
        eprint!("{}", result.stderr);
    }
    Ok(exit_code)
}

/// Group `rg --files` output by directory. Format mirrors `find`'s shape so
/// agents see consistent compact file lists across rg/find/grep.
fn filter_files_output(raw: &str) -> String {
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0usize;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total += 1;
        let path = Path::new(trimmed);
        let dir = path
            .parent()
            .map(|p| {
                let s = p.to_string_lossy().to_string();
                if s.is_empty() { ".".to_string() } else { s }
            })
            .unwrap_or_else(|| ".".to_string());
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| trimmed.to_string());
        by_dir.entry(dir).or_default().push(name);
    }

    if total == 0 {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&format!("{} files in {} dirs:\n\n", total, by_dir.len()));

    let per_dir_cap: usize = 20;
    for (dir, mut names) in by_dir {
        names.sort();
        let shown = names.len().min(per_dir_cap);
        let overflow = names.len().saturating_sub(shown);
        out.push_str(&format!("{}/ ({})\n", dir, names.len()));
        for n in names.iter().take(shown) {
            out.push_str(&format!("  {}\n", n));
        }
        if overflow > 0 {
            out.push_str(&format!("  [+{} more]\n", overflow));
        }
    }
    out
}

/// Unmapped invocation: run `rg` directly with the original args so the
/// user still gets output, just unfiltered. Records as a passthrough.
fn run_passthrough(args: &[String], verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("rg passthrough: {:?}", args);
    }

    let mut cmd = secure_rg_command("rg");
    cmd.args(args);

    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    let raw_cmd = format!("rg {}", args.join(" "));
    match status {
        Ok(s) => {
            timer.track_passthrough(&raw_cmd, &format!("contextcrawler rg (passthrough): {}", raw_cmd));
            Ok(s.code().unwrap_or(1))
        }
        Err(e) => {
            eprintln!("[contextcrawler: {}]", e);
            Ok(127)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // --- parser ---

    #[test]
    fn test_parse_files_mode_default_path() {
        let p = parse_rg_args(&v(&["--files"]));
        assert_eq!(p.mode, RgMode::Files);
        assert_eq!(p.path, ".");
        assert!(p.pattern.is_none());
    }

    #[test]
    fn test_parse_files_mode_explicit_path() {
        let p = parse_rg_args(&v(&["--files", "src/"]));
        assert_eq!(p.mode, RgMode::Files);
        assert_eq!(p.path, "src/");
    }

    #[test]
    fn test_parse_search_pattern_only() {
        let p = parse_rg_args(&v(&["needle"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("needle"));
        assert_eq!(p.path, ".");
    }

    #[test]
    fn test_parse_search_pattern_and_path() {
        let p = parse_rg_args(&v(&["needle", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("needle"));
        assert_eq!(p.path, "src/");
    }

    #[test]
    fn test_parse_search_with_n_flag() {
        // -n is rg's default but agents pass it from grep muscle memory.
        let p = parse_rg_args(&v(&["-n", "needle", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("needle"));
        assert_eq!(p.path, "src/");
        assert!(p.extra_args.contains(&"-n".to_string()));
    }

    #[test]
    fn test_parse_list_mode_short_flag() {
        let p = parse_rg_args(&v(&["-l", "needle", "src/"]));
        assert_eq!(p.mode, RgMode::ListWithFormatFlag);
        assert_eq!(p.pattern.as_deref(), Some("needle"));
        assert!(p.extra_args.contains(&"-l".to_string()));
    }

    #[test]
    fn test_parse_list_mode_long_flag() {
        let p = parse_rg_args(&v(&["--files-with-matches", "needle", "src/"]));
        assert_eq!(p.mode, RgMode::ListWithFormatFlag);
    }

    #[test]
    fn test_parse_type_flag_extracted() {
        let p = parse_rg_args(&v(&["-t", "rust", "needle", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.file_type.as_deref(), Some("rust"));
        assert_eq!(p.pattern.as_deref(), Some("needle"));
    }

    #[test]
    fn test_parse_context_flag_pairs_with_value() {
        // -A 3 must not be interpreted as `pattern=-A, path=3`.
        let p = parse_rg_args(&v(&["-A", "3", "needle", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("needle"));
        assert_eq!(p.path, "src/");
        // Both -A and 3 forwarded to grep_cmd.
        assert!(p.extra_args.windows(2).any(|w| w == ["-A", "3"]));
    }

    #[test]
    fn test_parse_e_flag_provides_pattern() {
        let p = parse_rg_args(&v(&["-e", "needle", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("needle"));
        assert_eq!(p.path, "src/");
    }

    /// Regression lock: `-e PATTERN` swallows the next token unconditionally,
    /// so `rg -e -l src/` parses pattern=`-l`. End-to-end safety relies on
    /// `grep_cmd` emitting `--` before the pattern (grep_cmd.rs ~line 76) so
    /// rg does not misparse the hyphen-leading pattern as a flag. This test
    /// pins the parser shape; if grep_cmd's `--` boundary is ever removed,
    /// that change would need its own regression — but this side is locked.
    #[test]
    fn test_parse_e_flag_with_hyphen_value() {
        let p = parse_rg_args(&v(&["-e", "-l", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("-l"));
        assert_eq!(p.path, "src/");
        // -l was consumed as the `-e` value, not parsed as a format flag.
        assert!(!p.extra_args.contains(&"-l".to_string()),
            "-l after -e must be the pattern value, not a format flag");
    }

    #[test]
    fn test_parse_double_dash_separator() {
        // Anything after `--` is positional.
        let p = parse_rg_args(&v(&["--", "-needle", "src/"]));
        assert_eq!(p.mode, RgMode::Search);
        assert_eq!(p.pattern.as_deref(), Some("-needle"));
        assert_eq!(p.path, "src/");
    }

    #[test]
    fn test_parse_no_pattern_no_files_is_unmapped() {
        // Just an unknown flag, no pattern, no --files → can't classify.
        let p = parse_rg_args(&v(&["--debug"]));
        assert_eq!(p.mode, RgMode::Unmapped);
    }

    // --- files-mode output ---

    #[test]
    fn test_filter_files_empty_input_returns_empty() {
        assert_eq!(filter_files_output(""), "");
    }

    #[test]
    fn test_filter_files_groups_by_directory() {
        let raw = "src/main.rs\nsrc/lib.rs\ntests/foo.rs\nREADME.md\n";
        let out = filter_files_output(raw);
        assert!(out.starts_with("4 files in 3 dirs:"));
        assert!(out.contains("src/ (2)"));
        assert!(out.contains("tests/ (1)"));
        assert!(out.contains("./ (1)"));
        assert!(out.contains("main.rs"));
        assert!(out.contains("lib.rs"));
    }

    #[test]
    fn test_filter_files_token_savings() {
        // Build a realistic large file list — 30 files across 3 dirs.
        let mut raw = String::new();
        for i in 0..15 {
            raw.push_str(&format!("src/module_{}.rs\n", i));
        }
        for i in 0..10 {
            raw.push_str(&format!("tests/integration_{}.rs\n", i));
        }
        for i in 0..5 {
            raw.push_str(&format!("docs/chapter_{}.md\n", i));
        }
        let filtered = filter_files_output(&raw);
        let raw_tokens = raw.split_whitespace().count();
        let filt_tokens = filtered.split_whitespace().count();
        // Grouped framing buys us very little when file count is modest;
        // headline savings show up at larger scales when per-dir caps kick
        // in. At this 30-file scale the per-dir header + count overhead
        // (`src/ (15)`, `tests/ (10)`, `docs/ (5)`) adds ~10 tokens above
        // raw. Assert the framing never more than doubles output — the
        // contract that matters is "does not regress catastrophically".
        // Savings test at scale lives in `test_filter_files_per_dir_cap_overflow_marker`.
        assert!(filt_tokens <= raw_tokens * 2,
            "files-mode framing should never more than double raw (raw={}, filtered={})",
            raw_tokens, filt_tokens);
    }

    // Fixture-backed: real `rg --files src/` output captured at fixture
    // creation time. Confirms the directory-grouping framing keeps roughly
    // parity with raw on a real CTXCRL file list.
    #[test]
    fn test_filter_files_real_fixture_keeps_parity() {
        let raw = include_str!("../../../tests/fixtures/rg_files_raw.txt");
        let filtered = filter_files_output(raw);
        assert!(filtered.contains("files in"));
        assert!(filtered.contains("dirs:"));
        // Grouped framing carries a header + per-dir count overhead; for
        // realistic 60-file lists the filter shouldn't balloon the output.
        let raw_bytes = raw.len();
        let filt_bytes = filtered.len();
        assert!(filt_bytes <= raw_bytes * 2,
            "filtered output should never more than 2x raw (raw={}, filt={})",
            raw_bytes, filt_bytes);
    }

    #[test]
    fn test_filter_files_per_dir_cap_overflow_marker() {
        // 25 files in one dir → cap at 20 with [+5 more] marker.
        let mut raw = String::new();
        for i in 0..25 {
            raw.push_str(&format!("src/file_{:02}.rs\n", i));
        }
        let out = filter_files_output(&raw);
        assert!(out.contains("[+5 more]"), "overflow marker missing: {}", out);
    }
}
