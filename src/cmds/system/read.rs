//! Reads source files with optional language-aware filtering to strip boilerplate.

use crate::cmds::system::intent as intent_extractor;
use crate::cmds::system::json_cmd;
use crate::cmds::system::read_cache;
use crate::core::config;
use crate::core::filter::{self, FilterLevel, Language};
use crate::core::tracking;
use crate::core::utils::format_tokens;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const JSON_MAX_DEPTH: usize = 5;

/// Text that identifies output the large-file cap has truncated.
///
/// Shared by the renderer that writes it and the repeat-read cache that must
/// refuse to stub over it, so the two cannot drift apart.
const TRUNCATION_MARKER: &str = "ContextCrawler omitted middle of file";

#[allow(clippy::too_many_arguments)]
pub fn run(
    file: &Path,
    level: FilterLevel,
    window: LineWindow,
    line_numbers: bool,
    intent: Option<&str>,
    force: bool,
    verbose: u8,
) -> Result<()> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Reading: {} (filter: {})", file.display(), level);
    }

    // Read file content
    let content = fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;

    let read_config = config::read();
    let ext = file.extension().and_then(|e| e.to_str());

    // Detect language from extension
    let lang = file
        .extension()
        .and_then(|e| e.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::Unknown);

    if verbose > 1 {
        eprintln!("Detected language: {:?}", lang);
    }

    let display_path = file.display().to_string();

    // #151: if --intent was provided and the file is big enough to benefit,
    // try surgical extraction first. Falls back to the regular render path
    // when the extractor returns None (small file, no matching sections,
    // unsupported format, etc.).
    let filtered = if let Some(extracted) = intent
        .and_then(|i| intent_extractor::extract_for_intent(&content, ext, lang, i, &display_path))
    {
        extracted
    } else {
        render_output(
            &content,
            ext,
            lang,
            level,
            &window,
            &read_config,
            true,
            &display_path,
            verbose,
        )
    };

    let ctxcrl_output = if line_numbers {
        format_with_line_numbers(&filtered)
    } else {
        filtered.clone()
    };

    // #236 runs *after* rendering, so the cache is sized and gated by what the
    // agent actually receives rather than by the raw file. Deciding before the
    // render made a capped read record the full file's token count and then
    // claim, on the next read, that the agent already had text it had never
    // been shown.
    let emitted = if let Some(stub) = repeat_read_stub(
        file,
        &content,
        &ctxcrl_output,
        force,
        line_numbers,
        &window,
        intent,
        &read_config,
    ) {
        stub
    } else {
        ctxcrl_output
    };

    print!("{}", emitted);
    timer.track(
        &format!("cat {}", file.display()),
        "contextcrawler read",
        &content,
        &emitted,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_stdin(
    level: FilterLevel,
    window: LineWindow,
    line_numbers: bool,
    intent: Option<&str>,
    verbose: u8,
) -> Result<()> {
    use std::io::{self, Read as IoRead};

    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Reading from stdin (filter: {})", level);
    }

    // Read from stdin
    let mut content = String::new();
    io::stdin()
        .lock()
        .read_to_string(&mut content)
        .context("Failed to read from stdin")?;

    // No file extension, so use Unknown language
    let lang = Language::Unknown;
    let read_config = config::read();

    if verbose > 1 {
        eprintln!("Language: {:?} (stdin has no extension)", lang);
    }

    let filtered = if let Some(extracted) = intent
        .and_then(|i| intent_extractor::extract_for_intent(&content, None, lang, i, "(stdin)"))
    {
        extracted
    } else {
        render_output(
            &content,
            None,
            lang,
            level,
            &window,
            &read_config,
            // Apply the cap to stdin too. Piping a huge unrecognised file via
            // `cat … | ctxcrl read -` should give the same protection as reading
            // it directly. The marker tells the consumer it was capped and how
            // to recover full content if they need it.
            true,
            "(stdin)",
            verbose,
        )
    };

    let ctxcrl_output = if line_numbers {
        format_with_line_numbers(&filtered)
    } else {
        filtered.clone()
    };
    print!("{}", ctxcrl_output);

    timer.track(
        "cat - (stdin)",
        "contextcrawler read -",
        &content,
        &ctxcrl_output,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_output(
    content: &str,
    ext: Option<&str>,
    lang: Language,
    level: FilterLevel,
    window: &LineWindow,
    read_config: &config::ReadConfig,
    allow_unknown_cap: bool,
    display_path: &str,
    verbose: u8,
) -> String {
    let input_tokens = tracking::estimate_tokens(content);
    let mut filtered = filter_content(content, ext, lang, level);

    // Safety: if filter emptied a non-empty file, fall back to raw content.
    if filtered.trim().is_empty() && !content.trim().is_empty() {
        if verbose > 0 {
            eprintln!(
                "contextcrawler: warning: filter produced empty output ({} bytes), showing raw content",
                content.len()
            );
        }
        filtered = content.to_string();
    }

    if verbose > 0 {
        let original_lines = content.lines().count();
        let filtered_lines = filtered.lines().count();
        let reduction = if original_lines > 0 {
            ((original_lines - filtered_lines) as f64 / original_lines as f64) * 100.0
        } else {
            0.0
        };
        eprintln!(
            "Lines: {} -> {} ({:.1}% reduction)",
            original_lines, filtered_lines, reduction
        );
    }

    // An explicit range is a deliberate, bounded request — capping it again
    // would silently shrink a window the caller already sized.
    if !window.has_range()
        && should_apply_unknown_extension_cap(
            ext,
            &lang,
            window.max_lines,
            window.tail_lines,
            input_tokens,
            read_config,
            allow_unknown_cap,
        )
    {
        return apply_unknown_extension_cap(&filtered, input_tokens, read_config, display_path);
    }

    apply_line_window(&filtered, window, &lang)
}

/// #236: decide whether this session has already been shown this exact file,
/// returning the recovery marker if so — and recording the read if not.
///
/// Keyed on the render mode as well as the path, so a repeat is only ever
/// recognised as one when the earlier read produced the same text. A windowed
/// (`--max-lines`, `--tail-lines`, `--start-line`/`--end-line`), numbered or
/// intent-scoped read renders something other than the file's full text, so
/// treating it as satisfied by a plain read would withhold content the agent
/// has never had.
///
/// Returns `None` — meaning emit in full — for every disabled, absent or
/// changed case, so a failure anywhere in the cache degrades to today's
/// behaviour rather than to silence.
#[allow(clippy::too_many_arguments)]
fn repeat_read_stub(
    file: &Path,
    content: &str,
    emitted: &str,
    force: bool,
    line_numbers: bool,
    window: &LineWindow,
    intent: Option<&str>,
    read_config: &config::ReadConfig,
) -> Option<String> {
    if !read_config.repeat_read_stub {
        return None;
    }
    // A read whose own render path already truncated the file, or replaced it
    // with an intent-scoped extract, carries its own recovery marker telling
    // the agent how to get the rest. Layering the repeat-read marker on top
    // would replace that guidance with a `--force` hint that re-renders the
    // same truncated view, so the full text becomes unreachable through the
    // route the agent is being pointed at. Leave those alone entirely.
    if intent.is_some() || emitted_is_truncated(emitted) {
        return None;
    }
    // Size the entry by what the agent actually received. Recording the raw
    // token count made the stub claim credit for text that was never emitted —
    // a 4,000-line file capped to 162 lines reported "65,723 tokens" withheld.
    //
    // Checked before any canonicalize/hash/DB work: most reads are small, and
    // `read` sits on a sub-10ms startup budget (council, codex).
    let tokens = tracking::estimate_tokens(emitted);
    if tokens < read_config.repeat_read_min_tokens {
        return None;
    }
    let session = read_cache::session_id()?;
    let mode = read_cache::RenderMode {
        line_numbers,
        max_lines: window.max_lines,
        tail_lines: window.tail_lines,
        start_line: window.start_line,
        end_line: window.end_line,
        intent: intent.map(str::to_string),
    };
    let key = read_cache::cache_key_with_mode(file, &mode);
    // Hash the source so a file edit is always detected.
    let sha = read_cache::content_sha(content);
    let prior = read_cache::load(&session, &key);
    match read_cache::decide(
        prior.as_ref(),
        &sha,
        tokens,
        force,
        read_config.repeat_read_min_tokens,
    ) {
        read_cache::Verdict::Stub(entry) => {
            Some(read_cache::render_stub(&file.display().to_string(), &entry))
        }
        read_cache::Verdict::Emit => {
            read_cache::record(&session, &key, &sha, tokens);
            None
        }
    }
}

/// Whether a rendered read already carries a truncation/recovery marker.
///
/// Matched on the marker the cap itself emits rather than by re-deriving the
/// cap predicate, so the two can never drift apart: if the renderer starts or
/// stops truncating, this follows automatically.
fn emitted_is_truncated(emitted: &str) -> bool {
    emitted.contains(TRUNCATION_MARKER)
}

fn filter_content(content: &str, ext: Option<&str>, lang: Language, level: FilterLevel) -> String {
    let filter = filter::get_filter(level);

    if ext.is_some_and(is_json_like_extension) {
        match json_cmd::filter_json_compact(content, JSON_MAX_DEPTH) {
            Ok(output) => output,
            Err(_err) => filter.filter(content, &lang),
        }
    } else {
        filter.filter(content, &lang)
    }
}

fn format_with_line_numbers(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let width = lines.len().to_string().len();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        out.push_str(&format!("{:>width$} │ {}\n", i + 1, line, width = width));
    }
    out
}

fn is_json_like_extension(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "json" | "xcstrings" | "geojson" | "ipynb" | "webmanifest" | "code-workspace"
    )
}

/// Prose files that carry no code structure worth preserving, so a large one
/// is safe to head/tail-cap (with the recovery marker) exactly like an unknown
/// extension. Deliberately narrow: free-form docs you skim (`md`/`txt`).
/// Structured config (json/yaml/toml), `sql`, and dependency lockfiles
/// (`Cargo.lock`/`Gemfile.lock` — inspected for exact pins) are intentionally
/// excluded; mid-file capping would corrupt an edit or hide a pin (council
/// finding). Telemetry motivation: untouched markdown (e.g. AGENTS.md read at
/// 0% savings) was the single biggest input sink across real sessions.
fn is_prose_cappable_extension(ext: &str) -> bool {
    matches!(ext.to_ascii_lowercase().as_str(), "md" | "markdown" | "txt")
}

fn should_apply_unknown_extension_cap(
    ext: Option<&str>,
    lang: &Language,
    max_lines: Option<usize>,
    tail_lines: Option<usize>,
    input_tokens: usize,
    read_config: &config::ReadConfig,
    allow_unknown_cap: bool,
) -> bool {
    // Cap applies to truly unknown extensions AND to large prose/data files
    // that the language filter leaves untouched (markdown/txt/lock).
    let cappable = *lang == Language::Unknown || ext.is_some_and(is_prose_cappable_extension);
    if !allow_unknown_cap
        || !cappable
        || max_lines.is_some()
        || tail_lines.is_some()
        || input_tokens <= read_config.token_threshold
    {
        return false;
    }
    if let Some(ext) = ext {
        if is_json_like_extension(ext) {
            return false;
        }
        // Honour the user's passthrough allowlist — source-code files in
        // languages contextcrawler doesn't yet filter (e.g. .svelte, .zig)
        // should pass through verbatim so the LLM can edit them safely.
        let lower = ext.to_ascii_lowercase();
        if read_config
            .passthrough_extensions
            .iter()
            .any(|allowed| allowed.trim_start_matches('.').eq_ignore_ascii_case(&lower))
        {
            return false;
        }
    }
    true
}

fn apply_unknown_extension_cap(
    content: &str,
    input_tokens: usize,
    read_config: &config::ReadConfig,
    display_path: &str,
) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    let head = read_config.head_lines.min(total_lines);
    let tail = read_config.tail_lines.min(total_lines.saturating_sub(head));

    if total_lines <= head + tail || total_lines == 0 {
        return content.to_string();
    }

    let omitted_lines = total_lines - head - tail;
    let omitted_pct = (omitted_lines as f64 / total_lines as f64) * 100.0;
    let mut result = Vec::with_capacity(head + tail + 2);
    result.extend(lines.iter().take(head).copied().map(str::to_string));
    // Two-line marker: a visually-unmissable divider plus an info line that
    // tells the reader exactly what was dropped AND how to recover the full
    // file. The escape-hatch text means an LLM that sees a capped output can
    // re-read with `contextcrawler proxy cat <path>` without needing to know
    // about the cap in advance.
    result.push(format!(
        "[───────────────────────── {} ─────────────────────────]",
        TRUNCATION_MARKER
    ));
    result.push(format!(
        "[omitted {} of {} lines ({:.1}% · ~{} tokens). Full file: `contextcrawler proxy cat {}`]",
        omitted_lines,
        total_lines,
        omitted_pct,
        format_tokens(input_tokens),
        display_path,
    ));
    result.extend(
        lines
            .iter()
            .skip(total_lines - tail)
            .copied()
            .map(str::to_string),
    );

    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Which slice of a file to render.
///
/// Bundled rather than passed as four more positional arguments —
/// `render_output` already carried ten, and the repo's own Rust patterns call
/// for a struct past five optional fields.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LineWindow {
    pub max_lines: Option<usize>,
    pub tail_lines: Option<usize>,
    /// 1-indexed, inclusive — `sed -n 'A,Bp'` semantics (#207).
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
}

impl LineWindow {
    /// True when an explicit range was requested.
    fn has_range(&self) -> bool {
        self.start_line.is_some() || self.end_line.is_some()
    }
}

/// Take a 1-indexed, inclusive line range, `sed -n 'A,Bp'` style.
///
/// Either bound may be omitted: start-only runs to EOF, end-only starts at
/// line 1. Bounds past EOF clamp; an inverted range yields nothing. `--start 0`
/// is treated as line 1 — it is a user slip, not a reason to return an empty
/// file. The file's trailing-newline state is preserved so the output is a
/// faithful excerpt rather than a subtly reformatted one.
fn apply_line_range(content: &str, start: Option<usize>, end: Option<usize>) -> String {
    if start.is_none() && end.is_none() {
        return content.to_string();
    }
    let lines: Vec<&str> = content.lines().collect();
    // 1-indexed inclusive -> 0-indexed half-open.
    let from = start.unwrap_or(1).max(1) - 1;
    let to = end.map(|e| e.min(lines.len())).unwrap_or(lines.len());
    if from >= to || from >= lines.len() {
        return String::new();
    }
    let mut result = lines[from..to].join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    result
}

fn apply_line_window(content: &str, window: &LineWindow, lang: &Language) -> String {
    // An explicit range is the most specific instruction available, so it wins
    // over head/tail caps rather than compounding with them.
    if window.has_range() {
        return apply_line_range(content, window.start_line, window.end_line);
    }
    apply_line_window_caps(content, window.max_lines, window.tail_lines, lang)
}

fn apply_line_window_caps(
    content: &str,
    max_lines: Option<usize>,
    tail_lines: Option<usize>,
    lang: &Language,
) -> String {
    if let Some(tail) = tail_lines {
        if tail == 0 {
            return String::new();
        }
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(tail);
        let mut result = lines[start..].join("\n");
        if content.ends_with('\n') {
            result.push('\n');
        }
        return result;
    }

    if let Some(max) = max_lines {
        return filter::smart_truncate(content, max, lang);
    }

    content.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_rust_file() -> Result<()> {
        let mut file = NamedTempFile::with_suffix(".rs")?;
        writeln!(
            file,
            r#"// Comment
fn main() {{
    println!("Hello");
}}"#
        )?;

        // Just verify it doesn't panic
        run(
            file.path(),
            FilterLevel::Minimal,
            LineWindow::default(),
            false,
            None,
            false,
            0,
        )?;
        Ok(())
    }

    #[test]
    fn test_stdin_support_signature() {
        // Test that run_stdin has correct signature and compiles
        // We don't actually run it because it would hang waiting for stdin
        // Compile-time verification that the function exists with correct signature
    }

    #[test]
    fn test_apply_line_window_tail_lines() {
        let input = "a\nb\nc\nd\n";
        let output = apply_line_window_caps(input, None, Some(2), &Language::Unknown);
        assert_eq!(output, "c\nd\n");
    }

    #[test]
    fn test_apply_line_window_tail_lines_no_trailing_newline() {
        let input = "a\nb\nc\nd";
        let output = apply_line_window_caps(input, None, Some(2), &Language::Unknown);
        assert_eq!(output, "c\nd");
    }

    #[test]
    fn test_apply_line_window_max_lines_still_works() {
        let input = "a\nb\nc\nd\n";
        let output = apply_line_window_caps(input, Some(2), None, &Language::Unknown);
        assert!(output.starts_with("a\n"));
        assert!(output.contains("more lines"));
    }

    // --- #207: explicit line ranges (`--start-line` / `--end-line`) ---
    //
    // Agents invoke `read <file> --start N --end M`. Those flags did not
    // exist, so clap errored and the command fell back to raw passthrough —
    // the whole file, unfiltered, at 0 savings. Erroring to raw is the worst
    // possible outcome for a flag whose entire purpose is to read less.

    fn range(input: &str, start: Option<usize>, end: Option<usize>) -> String {
        apply_line_range(input, start, end)
    }

    #[test]
    fn line_range_is_one_indexed_and_inclusive() {
        // Matches `sed -n '2,3p'`, which is the idiom this replaces.
        assert_eq!(range("a\nb\nc\nd\n", Some(2), Some(3)), "b\nc\n");
    }

    #[test]
    fn line_range_start_only_runs_to_end_of_file() {
        assert_eq!(range("a\nb\nc\nd\n", Some(3), None), "c\nd\n");
    }

    #[test]
    fn line_range_end_only_starts_at_line_one() {
        assert_eq!(range("a\nb\nc\nd\n", None, Some(2)), "a\nb\n");
    }

    #[test]
    fn line_range_end_past_eof_clamps_to_last_line() {
        assert_eq!(range("a\nb\n", Some(2), Some(999)), "b\n");
    }

    /// Asymmetric on purpose, matching `sed -n 'A,Bp'`: an end past EOF clamps,
    /// but a start past EOF selects nothing rather than the final line.
    #[test]
    fn line_range_start_past_eof_returns_empty_not_the_last_line() {
        assert_eq!(range("a\nb\n", Some(999), Some(1000)), "");
        assert_eq!(range("a\nb\n", Some(3), None), "");
    }

    #[test]
    fn line_range_start_zero_is_treated_as_line_one() {
        // `--start 0` is a user slip, not a reason to return nothing.
        assert_eq!(range("a\nb\nc\n", Some(0), Some(2)), "a\nb\n");
    }

    #[test]
    fn line_range_inverted_returns_empty() {
        assert_eq!(range("a\nb\nc\n", Some(3), Some(1)), "");
    }

    #[test]
    fn line_range_preserves_missing_trailing_newline() {
        assert_eq!(range("a\nb\nc", Some(2), Some(3)), "b\nc");
    }

    #[test]
    fn line_range_takes_precedence_over_max_lines() {
        // Both supplied should not happen (clap conflicts), but the window
        // helper must still be deterministic rather than silently blending.
        let window = LineWindow {
            max_lines: Some(2),
            start_line: Some(2),
            end_line: Some(3),
            ..LineWindow::default()
        };
        assert_eq!(
            apply_line_window("a\nb\nc\nd\n", &window, &Language::Unknown),
            "b\nc\n"
        );
    }

    #[test]
    fn no_range_leaves_content_untouched() {
        assert_eq!(range("a\nb\n", None, None), "a\nb\n");
    }

    #[test]
    fn test_render_output_xcstrings_uses_json_path() {
        // Build 1000 array entries with commas between them, no trailing
        // comma before `]` (the upstream version had one — invalid JSON per
        // serde_json strict parse, which is what filter_json_compact uses).
        let mut entries = String::from("{\n  \"entries\": [\n");
        for i in 0..1_000usize {
            let sep = if i + 1 < 1_000 { "," } else { "" };
            entries.push_str(&format!(
                "    {{\"id\": {}, \"value\": \"entry-{:04}\"}}{}\n",
                i, i, sep
            ));
        }
        entries.push_str("  ]\n}\n");

        let read_config = config::ReadConfig::default();
        let output = render_output(
            &entries,
            Some("xcstrings"),
            Language::from_extension("xcstrings"),
            FilterLevel::None,
            &LineWindow::default(),
            &read_config,
            true,
            "fixture.xcstrings",
            0,
        );

        let input_tokens = tracking::estimate_tokens(&entries);
        let output_tokens = tracking::estimate_tokens(&output);
        let savings = 100.0 - (output_tokens as f64 / input_tokens as f64 * 100.0);

        assert!(
            savings >= 60.0,
            "Expected ≥60% token savings, got {:.1}%\ninput tokens: {}\noutput tokens: {}\noutput:\n{}",
            savings,
            input_tokens,
            output_tokens,
            output
        );
        // compact_json renders Object keys unquoted (`entries:`), not
        // `"entries":`. Match either form so this test stays robust if the
        // formatter is later changed to quote keys.
        assert!(
            output.contains("entries:") || output.contains("\"entries\""),
            "output should reference the entries key, got:\n{}",
            output
        );
        assert!(output.contains("... +"));
    }

    #[test]
    fn test_render_output_unknown_extension_cap() {
        let mut input = String::new();
        for i in 0..200usize {
            input.push_str(&format!(
                "line {:03} repeated content repeated content repeated content repeated content repeated content repeated content repeated content repeated content repeated content repeated content\n",
                i
            ));
        }

        let read_config = config::ReadConfig::default();
        let output = render_output(
            &input,
            Some("unknowntype"),
            Language::Unknown,
            FilterLevel::None,
            &LineWindow::default(),
            &read_config,
            true,
            "fixture.unknowntype",
            0,
        );

        // Verify cap structure: head lines first, two-line marker in the
        // middle (divider + info line with escape hatch), then tail lines.
        let input_lines: Vec<&str> = input.lines().collect();
        let output_lines: Vec<&str> = output.lines().collect();
        let head = read_config.head_lines;
        let tail = read_config.tail_lines;

        // Head: first N lines preserved verbatim.
        assert_eq!(&output_lines[..head], &input_lines[..head]);
        // Marker line 1: visually-unmissable divider.
        assert!(
            output_lines[head].contains("ContextCrawler omitted middle"),
            "expected divider on marker line 1, got: {:?}",
            output_lines[head]
        );
        // Marker line 2: info + escape hatch with file path.
        let marker = output_lines[head + 1];
        assert!(marker.contains("omitted"));
        assert!(marker.contains("contextcrawler proxy cat fixture.unknowntype"));
        // Tail: last N lines preserved verbatim.
        assert_eq!(
            &output_lines[output_lines.len() - tail..],
            &input_lines[input_lines.len() - tail..]
        );

        // Symmetric default: head and tail are equal (80/80).
        assert_eq!(head, tail, "default head/tail must be symmetric");

        let input_tokens = tracking::estimate_tokens(&input);
        let output_tokens = tracking::estimate_tokens(&output);
        let savings = 100.0 - (output_tokens as f64 / input_tokens as f64 * 100.0);
        assert!(
            savings > 0.0,
            "cap must reduce tokens, got {:.1}% ({} -> {})",
            savings,
            input_tokens,
            output_tokens
        );
    }

    #[test]
    fn test_default_tail_lines_is_symmetric_80() {
        let cfg = config::ReadConfig::default();
        assert_eq!(cfg.head_lines, 80);
        assert_eq!(cfg.tail_lines, 80);
        assert!(cfg.passthrough_extensions.is_empty());
    }

    #[test]
    fn test_passthrough_extensions_allowlist_skips_cap() {
        let mut input = String::new();
        for i in 0..400usize {
            input.push_str(&format!("svelte-line-{} content content content\n", i));
        }

        let mut read_config = config::ReadConfig::default();
        read_config.passthrough_extensions = vec![".svelte".to_string()];

        let output = render_output(
            &input,
            Some("svelte"),
            Language::Unknown,
            FilterLevel::None,
            &LineWindow::default(),
            &read_config,
            true,
            "Component.svelte",
            0,
        );

        // Allowlisted: should NOT contain the marker; full content preserved.
        assert!(
            !output.contains("ContextCrawler omitted middle"),
            "passthrough_extensions allowlist must skip the cap"
        );
        assert_eq!(output.lines().count(), input.lines().count());
    }

    #[test]
    fn test_passthrough_extensions_accepts_with_or_without_dot() {
        let cfg_no_dot = config::ReadConfig {
            passthrough_extensions: vec!["zig".to_string()],
            ..config::ReadConfig::default()
        };
        let cfg_with_dot = config::ReadConfig {
            passthrough_extensions: vec![".zig".to_string()],
            ..config::ReadConfig::default()
        };

        // Both shapes must reach the same passthrough decision.
        for cfg in [&cfg_no_dot, &cfg_with_dot] {
            assert!(!should_apply_unknown_extension_cap(
                Some("zig"),
                &Language::Unknown,
                None,
                None,
                10_000,
                cfg,
                true,
            ));
        }
    }

    #[test]
    fn test_large_markdown_gets_capped() {
        // Real-telemetry motivation: untouched markdown was the biggest 0%
        // input sink. A large .md (Language::Data) must now hit the cap.
        let mut input = String::new();
        for i in 0..1500usize {
            input.push_str(&format!("doc line {} with prose words here aplenty\n", i));
        }
        let cfg = config::ReadConfig::default();
        let output = render_output(
            &input,
            Some("md"),
            Language::Data,
            FilterLevel::None,
            &LineWindow::default(),
            &cfg,
            true,
            "AGENTS.md",
            0,
        );
        assert!(
            output.contains("ContextCrawler omitted middle"),
            "large markdown must be capped with the recovery marker"
        );
        let saved = 100.0
            - (tracking::estimate_tokens(&output) as f64
                / tracking::estimate_tokens(&input) as f64
                * 100.0);
        assert!(
            saved > 60.0,
            "expected >60% savings on capped md, got {:.1}%",
            saved
        );
    }

    #[test]
    fn test_small_markdown_not_capped() {
        // Below the token threshold: leave it whole, no marker.
        let input = "# Title\n\nA short note.\nNothing to cap here.\n";
        let cfg = config::ReadConfig::default();
        let output = render_output(
            &input,
            Some("md"),
            Language::Data,
            FilterLevel::None,
            &LineWindow::default(),
            &cfg,
            true,
            "small.md",
            0,
        );
        assert!(!output.contains("ContextCrawler omitted middle"));
    }

    #[test]
    fn test_structured_data_and_sql_not_capped() {
        // Config/data/sql are Data but NOT prose-cappable: capping mid-file
        // would corrupt an edit, so they must pass through untouched.
        let mut input = String::new();
        for i in 0..1500usize {
            input.push_str(&format!("key_{}: value with enough tokens to exceed\n", i));
        }
        let cfg = config::ReadConfig::default();
        // `lock` is excluded too: lockfiles are inspected for exact pins, so
        // mid-file capping could hide them (council finding).
        for ext in ["yaml", "toml", "sql", "csv", "lock"] {
            let output = render_output(
                &input,
                Some(ext),
                Language::Data,
                FilterLevel::None,
                &LineWindow::default(),
                &cfg,
                true,
                &format!("data.{}", ext),
                0,
            );
            assert!(
                !output.contains("ContextCrawler omitted middle"),
                ".{} must not be capped (edit-safety)",
                ext
            );
            assert_eq!(output.lines().count(), input.lines().count());
        }
    }

    #[test]
    fn test_markdown_passthrough_allowlist_overrides_cap() {
        // A user who allowlists .md must still get full content.
        let mut input = String::new();
        for i in 0..1500usize {
            input.push_str(&format!("doc line {} with prose words here aplenty\n", i));
        }
        let cfg = config::ReadConfig {
            passthrough_extensions: vec!["md".to_string()],
            ..config::ReadConfig::default()
        };
        let output = render_output(
            &input,
            Some("md"),
            Language::Data,
            FilterLevel::None,
            &LineWindow::default(),
            &cfg,
            true,
            "AGENTS.md",
            0,
        );
        assert!(!output.contains("ContextCrawler omitted middle"));
        assert_eq!(output.lines().count(), input.lines().count());
    }

    #[test]
    fn test_stdin_path_gets_cap_with_stdin_marker() {
        let mut input = String::new();
        // Default threshold is 5000 tokens. Build comfortably above it.
        for i in 0..1500usize {
            input.push_str(&format!(
                "stdin-line-{} more content here for tokens abc def\n",
                i
            ));
        }

        let read_config = config::ReadConfig::default();
        assert!(
            tracking::estimate_tokens(&input) > read_config.token_threshold,
            "fixture must exceed default token threshold"
        );
        let output = render_output(
            &input,
            None,
            Language::Unknown,
            FilterLevel::None,
            &LineWindow::default(),
            &read_config,
            true,
            "(stdin)",
            0,
        );

        // stdin path must also be capped — codex P2 feedback.
        assert!(output.contains("ContextCrawler omitted middle"));
        assert!(output.contains("contextcrawler proxy cat (stdin)"));
        // Input had ~3200 tokens of "stdin-line-N more content here for tokens"
        // (8 tokens/line * 400 lines). Output retains head+tail = 160 lines.
        assert!(output.lines().count() < input.lines().count());
    }

    #[test]
    fn test_workspace_extension_routes_to_data() {
        assert_eq!(Language::from_extension("workspace"), Language::Data);
        assert_eq!(Language::from_extension("code-workspace"), Language::Data);
    }

    fn ctxcrl_bin() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join("contextcrawler")
    }

    #[test]
    #[ignore]
    fn test_read_two_valid_files_concatenated() {
        let bin = ctxcrl_bin();
        assert!(bin.exists(), "Run `cargo build` first");

        let mut f1 = NamedTempFile::with_suffix(".txt").unwrap();
        let mut f2 = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f1, "alpha\nbravo").unwrap();
        writeln!(f2, "charlie\ndelta").unwrap();

        let output = std::process::Command::new(&bin)
            .args([
                "read",
                &f1.path().to_string_lossy(),
                &f2.path().to_string_lossy(),
            ])
            .output()
            .expect("failed to run ctxcrl read");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("alpha"), "first file content missing");
        assert!(stdout.contains("charlie"), "second file content missing");
    }

    #[test]
    #[ignore]
    fn test_read_valid_and_nonexistent() {
        let bin = ctxcrl_bin();
        assert!(bin.exists(), "Run `cargo build` first");

        let mut f1 = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(f1, "valid content").unwrap();

        let output = std::process::Command::new(&bin)
            .args([
                "read",
                &f1.path().to_string_lossy(),
                "/tmp/ctxcrl_nonexistent_file.txt",
            ])
            .output()
            .expect("failed to run ctxcrl read");

        assert!(
            !output.status.success(),
            "should exit non-zero on missing file"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("valid content"),
            "valid file should still be printed"
        );
        assert!(
            stderr.contains("ctxcrl_nonexistent_file"),
            "should report missing file on stderr"
        );
    }

    // --- #236 repeat-read elimination, at the gate `run()` actually calls ---

    mod repeat_read {
        use super::super::{repeat_read_stub, LineWindow, TRUNCATION_MARKER};
        use crate::cmds::system::read_cache::TestCacheEnv;
        use crate::core::config::ReadConfig;
        use crate::core::tracking;
        use std::io::Write;

        /// A file comfortably over the 500-token floor.
        fn big_file(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
            let path = dir.path().join(name);
            let mut f = std::fs::File::create(&path).expect("create");
            for i in 0..400 {
                writeln!(f, "fn f{i}() {{ println!(\"line {i}\"); }}").expect("write");
            }
            path
        }

        fn stub(
            path: &std::path::Path,
            content: &str,
            force: bool,
            cfg: &ReadConfig,
        ) -> Option<String> {
            repeat_read_stub(
                path,
                content,
                content,
                force,
                false,
                &LineWindow::default(),
                None,
                cfg,
            )
        }

        #[test]
        fn second_identical_read_is_stubbed_first_is_not() {
            let _env = TestCacheEnv::new("sess-repeat-1");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            assert!(
                stub(&path, &content, false, &cfg).is_none(),
                "a first read must always emit in full"
            );
            let second = stub(&path, &content, false, &cfg).expect("second read stubs");
            assert!(second.contains("unchanged since your earlier read"));
            assert!(
                second.contains("--force"),
                "stub must carry the recovery command"
            );
        }

        #[test]
        fn changed_content_is_never_stubbed() {
            let _env = TestCacheEnv::new("sess-repeat-2");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            stub(&path, &content, false, &cfg);
            let edited = format!("{content}\n// edited");
            assert!(
                stub(&path, &edited, false, &cfg).is_none(),
                "the agent has not seen the edited file — it must be emitted"
            );
            // ...and the new content is what is now remembered.
            assert!(
                stub(&path, &edited, false, &cfg).is_some(),
                "the edited content becomes the new baseline"
            );
        }

        #[test]
        fn force_emits_and_refreshes() {
            let _env = TestCacheEnv::new("sess-repeat-3");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            stub(&path, &content, false, &cfg);
            assert!(
                stub(&path, &content, true, &cfg).is_none(),
                "--force must always emit"
            );
        }

        /// A differently-rendered read must never inherit a plain read's cache
        /// entry — it produces different text, so the agent has not seen it.
        #[test]
        fn a_plain_read_never_satisfies_a_differently_rendered_one() {
            let _env = TestCacheEnv::new("sess-repeat-4");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            // Prime the cache with a plain whole-file read.
            stub(&path, &content, false, &cfg);
            stub(&path, &content, false, &cfg).expect("precondition: plain read stubs");

            for (label, out) in [
                (
                    "--max-lines",
                    repeat_read_stub(
                        &path,
                        &content,
                        &content,
                        false,
                        false,
                        &LineWindow {
                            max_lines: Some(20),
                            ..LineWindow::default()
                        },
                        None,
                        &cfg,
                    ),
                ),
                (
                    "--tail-lines",
                    repeat_read_stub(
                        &path,
                        &content,
                        &content,
                        false,
                        false,
                        &LineWindow {
                            tail_lines: Some(20),
                            ..LineWindow::default()
                        },
                        None,
                        &cfg,
                    ),
                ),
                (
                    "--intent",
                    repeat_read_stub(
                        &path,
                        &content,
                        &content,
                        false,
                        false,
                        &LineWindow::default(),
                        Some("x"),
                        &cfg,
                    ),
                ),
                (
                    "--line-numbers",
                    repeat_read_stub(
                        &path,
                        &content,
                        &content,
                        false,
                        true,
                        &LineWindow::default(),
                        None,
                        &cfg,
                    ),
                ),
            ] {
                assert!(
                    out.is_none(),
                    "{label} renders different text than the plain read that primed the cache"
                );
            }
        }

        /// The 84x `nl -ba` case: repeats of the *same* rendering are the whole
        /// point, and the first cut of #236 missed them by refusing to cache
        /// anything but a plain read.
        #[test]
        fn identical_line_numbered_reads_are_stubbed() {
            let _env = TestCacheEnv::new("sess-repeat-8");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            let first = repeat_read_stub(
                &path,
                &content,
                &content,
                false,
                true,
                &LineWindow::default(),
                None,
                &cfg,
            );
            assert!(first.is_none(), "first --line-numbers read emits in full");
            let second = repeat_read_stub(
                &path,
                &content,
                &content,
                false,
                true,
                &LineWindow::default(),
                None,
                &cfg,
            );
            assert!(
                second.is_some(),
                "a repeated --line-numbers read of unchanged content must be stubbed"
            );
        }

        #[test]
        fn different_windows_do_not_share_a_cache_entry() {
            let _env = TestCacheEnv::new("sess-repeat-9");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            repeat_read_stub(
                &path,
                &content,
                &content,
                false,
                false,
                &LineWindow {
                    max_lines: Some(20),
                    ..LineWindow::default()
                },
                None,
                &cfg,
            );
            assert!(
                repeat_read_stub(
                    &path,
                    &content,
                    &content,
                    false,
                    false,
                    &LineWindow {
                        max_lines: Some(20),
                        ..LineWindow::default()
                    },
                    None,
                    &cfg
                )
                .is_some(),
                "the same window repeated is a repeat"
            );
            assert!(
                repeat_read_stub(
                    &path,
                    &content,
                    &content,
                    false,
                    false,
                    &LineWindow {
                        max_lines: Some(50),
                        ..LineWindow::default()
                    },
                    None,
                    &cfg
                )
                .is_none(),
                "a wider window shows lines the agent has not seen"
            );
        }

        /// A read the large-file cap truncated must never be stubbed.
        ///
        /// Found by driving the real binary: a 4,000-line markdown file was
        /// capped to 162 lines on the first read, and the second read then
        /// claimed "unchanged since your earlier read — 65,723 tokens". The
        /// agent had never been shown those tokens, and the `--force` command
        /// the stub points at re-renders capped, so the full text was not
        /// reachable by the route being advertised.
        #[test]
        fn a_capped_read_is_never_stubbed() {
            let _env = TestCacheEnv::new("sess-capped");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "big.md");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            // Model what the renderer emits when the cap fires: a head/tail
            // window carrying the truncation marker.
            let capped = format!(
                "line 1\n[───── {} ─────]\n[omitted 3800 of 4000 lines]\nline 4000\n",
                TRUNCATION_MARKER
            );

            let first = repeat_read_stub(
                &path,
                &content,
                &capped,
                false,
                false,
                &LineWindow::default(),
                None,
                &cfg,
            );
            assert!(first.is_none(), "first read always emits");
            let second = repeat_read_stub(
                &path,
                &content,
                &capped,
                false,
                false,
                &LineWindow::default(),
                None,
                &cfg,
            );
            assert!(
                second.is_none(),
                "a truncated read carries its own recovery marker — the \
                 repeat-read stub must not replace it and claim the agent \
                 already has the whole file"
            );
        }

        /// The stub must be sized by what was emitted, not by the source file.
        #[test]
        fn stub_reports_emitted_tokens_not_raw_file_tokens() {
            let _env = TestCacheEnv::new("sess-tokens");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            // A windowed read: the agent receives far less than the file holds.
            // Wide enough to clear the 500-token floor, still well short of
            // the whole file.
            let window = LineWindow {
                max_lines: Some(200),
                ..LineWindow::default()
            };
            let emitted: String = content.lines().take(200).collect::<Vec<_>>().join("\n");
            let emitted_tokens = tracking::estimate_tokens(&emitted);
            let raw_tokens = tracking::estimate_tokens(&content);
            assert!(
                emitted_tokens < raw_tokens,
                "precondition: the window is smaller than the file"
            );

            repeat_read_stub(&path, &content, &emitted, false, false, &window, None, &cfg);
            let stub =
                repeat_read_stub(&path, &content, &emitted, false, false, &window, None, &cfg)
                    .expect("repeat of the same window stubs");
            assert!(
                stub.contains(&emitted_tokens.to_string()),
                "stub must report what the agent received ({emitted_tokens}), got: {stub}"
            );
            assert!(
                !stub.contains(&raw_tokens.to_string()),
                "stub must not claim credit for the whole file ({raw_tokens}), got: {stub}"
            );
        }

        #[test]
        fn small_files_are_never_stubbed() {
            let _env = TestCacheEnv::new("sess-repeat-5");
            let dir = tempfile::tempdir().expect("dir");
            let path = dir.path().join("tiny.rs");
            std::fs::write(&path, "fn tiny() {}\n").expect("write");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            assert!(stub(&path, &content, false, &cfg).is_none());
            assert!(
                stub(&path, &content, false, &cfg).is_none(),
                "a file under the token floor is not worth a recovery turn"
            );
        }

        #[test]
        fn disabled_in_config_never_stubs() {
            let _env = TestCacheEnv::new("sess-repeat-6");
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig {
                repeat_read_stub: false,
                ..ReadConfig::default()
            };

            assert!(stub(&path, &content, false, &cfg).is_none());
            assert!(
                stub(&path, &content, false, &cfg).is_none(),
                "repeat_read_stub = false must restore verbatim behaviour"
            );
        }

        #[test]
        fn without_a_session_id_nothing_is_stubbed() {
            let env = TestCacheEnv::new("sess-repeat-7");
            env.clear_session();
            let dir = tempfile::tempdir().expect("dir");
            let path = big_file(&dir, "a.rs");
            let content = std::fs::read_to_string(&path).expect("read");
            let cfg = ReadConfig::default();

            assert!(stub(&path, &content, false, &cfg).is_none());
            assert!(
                stub(&path, &content, false, &cfg).is_none(),
                "no host session id means the feature stays inert"
            );
        }
    }

    #[test]
    #[ignore]
    fn test_read_stdin_dedup_warning() {
        let bin = ctxcrl_bin();
        assert!(bin.exists(), "Run `cargo build` first");

        let output = std::process::Command::new(&bin)
            .args(["read", "-", "-"])
            .stdin(std::process::Stdio::piped())
            .output()
            .expect("failed to run ctxcrl read");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("stdin specified more than once"),
            "should warn about duplicate stdin, got stderr: {}",
            stderr
        );
    }
}
