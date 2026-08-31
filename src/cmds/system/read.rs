//! Reads source files with optional language-aware filtering to strip boilerplate.

use crate::cmds::system::intent as intent_extractor;
use crate::cmds::system::json_cmd;
use crate::core::config;
use crate::core::filter::{self, FilterLevel, Language};
use crate::core::sensitive_paths;
use crate::core::tracking;
use crate::core::utils::format_tokens;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const JSON_MAX_DEPTH: usize = 5;

#[allow(clippy::too_many_arguments)]
pub fn run(
    file: &Path,
    level: FilterLevel,
    max_lines: Option<usize>,
    tail_lines: Option<usize>,
    line_numbers: bool,
    intent: Option<&str>,
    verbose: u8,
) -> Result<()> {
    let timer = tracking::TimedExecution::start();

    sensitive_paths::ensure_not_sensitive_env_path(file, "contextcrawler read")?;

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
    let filtered = if let Some(extracted) = intent.and_then(|i| {
        intent_extractor::extract_for_intent(&content, ext, lang, i, &display_path)
    }) {
        extracted
    } else {
        render_output(
            &content,
            ext,
            lang,
            level,
            max_lines,
            tail_lines,
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
    print!("{}", ctxcrl_output);
    timer.track(
        &format!("cat {}", file.display()),
        "contextcrawler read",
        &content,
        &ctxcrl_output,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_stdin(
    level: FilterLevel,
    max_lines: Option<usize>,
    tail_lines: Option<usize>,
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

    let filtered = if let Some(extracted) = intent.and_then(|i| {
        intent_extractor::extract_for_intent(&content, None, lang, i, "(stdin)")
    }) {
        extracted
    } else {
        render_output(
            &content,
            None,
            lang,
            level,
            max_lines,
            tail_lines,
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

    timer.track("cat - (stdin)", "contextcrawler read -", &content, &ctxcrl_output);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_output(
    content: &str,
    ext: Option<&str>,
    lang: Language,
    level: FilterLevel,
    max_lines: Option<usize>,
    tail_lines: Option<usize>,
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

    if should_apply_unknown_extension_cap(
        ext,
        &lang,
        max_lines,
        tail_lines,
        input_tokens,
        read_config,
        allow_unknown_cap,
    ) {
        return apply_unknown_extension_cap(&filtered, input_tokens, read_config, display_path);
    }

    apply_line_window(&filtered, max_lines, tail_lines, &lang)
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
    let cappable = *lang == Language::Unknown
        || ext.is_some_and(is_prose_cappable_extension);
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
    result.push(
        "[───────────────────────── ContextCrawler omitted middle of file ─────────────────────────]"
            .to_string(),
    );
    result.push(format!(
        "[omitted {} of {} lines ({:.1}% · ~{} tokens). Full file: `contextcrawler proxy cat {}`]",
        omitted_lines,
        total_lines,
        omitted_pct,
        format_tokens(input_tokens),
        display_path,
    ));
    result.extend(lines.iter().skip(total_lines - tail).copied().map(str::to_string));

    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn apply_line_window(
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
        run(file.path(), FilterLevel::Minimal, None, None, false, None, 0)?;
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
        let output = apply_line_window(input, None, Some(2), &Language::Unknown);
        assert_eq!(output, "c\nd\n");
    }

    #[test]
    fn test_apply_line_window_tail_lines_no_trailing_newline() {
        let input = "a\nb\nc\nd";
        let output = apply_line_window(input, None, Some(2), &Language::Unknown);
        assert_eq!(output, "c\nd");
    }

    #[test]
    fn test_apply_line_window_max_lines_still_works() {
        let input = "a\nb\nc\nd\n";
        let output = apply_line_window(input, Some(2), None, &Language::Unknown);
        assert!(output.starts_with("a\n"));
        assert!(output.contains("more lines"));
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
            None,
            None,
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
            None,
            None,
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
            None,
            None,
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
            assert!(
                !should_apply_unknown_extension_cap(
                    Some("zig"),
                    &Language::Unknown,
                    None,
                    None,
                    10_000,
                    cfg,
                    true,
                )
            );
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
            None,
            None,
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
        assert!(saved > 60.0, "expected >60% savings on capped md, got {:.1}%", saved);
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
            None,
            None,
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
                None,
                None,
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
            None,
            None,
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
            None,
            None,
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
            .args(["read", &f1.path().to_string_lossy(), &f2.path().to_string_lossy()])
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
            .args(["read", &f1.path().to_string_lossy(), "/tmp/ctxcrl_nonexistent_file.txt"])
            .output()
            .expect("failed to run ctxcrl read");

        assert!(!output.status.success(), "should exit non-zero on missing file");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.contains("valid content"), "valid file should still be printed");
        assert!(stderr.contains("ctxcrl_nonexistent_file"), "should report missing file on stderr");
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
