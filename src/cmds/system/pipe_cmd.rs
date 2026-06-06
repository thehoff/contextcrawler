use anyhow::Result;
use std::io::Read;

use crate::core::stream::RAW_CAP;

pub fn resolve_filter(name: &str) -> Option<fn(&str) -> String> {
    match name {
        "cargo-test" | "cargo" => Some(crate::cmds::rust::cargo_cmd::filter_cargo_test),
        "pytest" => Some(crate::cmds::python::pytest_cmd::filter_pytest_output),
        "go-test" => Some(go_test_wrapper),
        "go-build" => Some(crate::cmds::go::go_cmd::filter_go_build),
        "tsc" => Some(crate::cmds::js::tsc_cmd::filter_tsc_output),
        "vitest" => Some(vitest_wrapper),
        "grep" | "rg" => Some(grep_wrapper),
        "find" | "fd" => Some(find_wrapper),
        "git-log" => Some(git_log_wrapper),
        "git-diff" => Some(git_diff_wrapper),
        "git-status" => Some(crate::cmds::git::git::format_status_output),
        "mypy" => Some(crate::cmds::python::mypy_cmd::filter_mypy_output_piped),
        "ruff-check" => Some(crate::cmds::python::ruff_cmd::filter_ruff_check_json),
        "ruff-format" => Some(crate::cmds::python::ruff_cmd::filter_ruff_format),
        "prettier" => Some(crate::cmds::js::prettier_cmd::filter_prettier_output),
        _ => None,
    }
}

fn go_test_wrapper(input: &str) -> String {
    crate::cmds::go::go_cmd::filter_go_test_json(input)
}

fn git_log_wrapper(input: &str) -> String {
    crate::cmds::git::git::filter_log_output(input, 50, false, false)
}

fn git_diff_wrapper(input: &str) -> String {
    crate::cmds::git::git::compact_diff(input, 200)
}

fn vitest_wrapper(input: &str) -> String {
    use crate::cmds::js::vitest_cmd::VitestParser;
    use crate::parser::{FormatMode, OutputParser, TokenFormatter};
    let result = VitestParser::parse(input);
    match result {
        crate::parser::ParseResult::Full(data) => data.format(FormatMode::Compact),
        crate::parser::ParseResult::Degraded(data, _) => data.format(FormatMode::Compact),
        crate::parser::ParseResult::Passthrough(raw) => raw,
    }
}

fn grep_wrapper(input: &str) -> String {
    use crate::core::utils::truncate;
    use std::collections::HashMap;

    let mut by_file: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    let mut total = 0;

    for line in input.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            if let Ok(_line_num) = parts[1].parse::<usize>() {
                total += 1;
                by_file.entry(parts[0]).or_default().push((parts[1], parts[2]));
            }
        }
    }

    if total == 0 {
        return input.to_string();
    }

    let mut out = format!("{} matches in {}F:\n\n", total, by_file.len());
    let mut files: Vec<_> = by_file.iter().collect();
    files.sort_by_key(|(f, _)| *f);

    for (file, matches) in files {
        out.push_str(&format!("[file] {} ({}):\n", file, matches.len()));
        for (line_num, content) in matches.iter().take(5) {
            out.push_str(&format!(
                "  {:>4}: {}\n",
                line_num,
                truncate(content.trim(), 200)
            ));
        }
        if matches.len() > 5 {
            let rest: Vec<&str> = matches.iter().skip(5).map(|(ln, _)| *ln).collect();
            out.push_str(&format!(
                "  +{} more at L: {}\n",
                matches.len() - 5,
                rest.join(",")
            ));
        }
        out.push('\n');
    }

    out
}

fn find_wrapper(input: &str) -> String {
    use std::collections::HashMap;

    let paths: Vec<&str> = input.lines().filter(|l| !l.trim().is_empty()).collect();

    if paths.is_empty() {
        return input.to_string();
    }

    let mut by_dir: HashMap<&str, Vec<&str>> = HashMap::new();

    for path in &paths {
        let dir = match path.rfind('/') {
            Some(pos) => &path[..pos],
            None => ".",
        };
        let name = match path.rfind('/') {
            Some(pos) => &path[pos + 1..],
            None => path,
        };
        by_dir.entry(dir).or_default().push(name);
    }

    let mut out = format!("{} files in {} dirs:\n\n", paths.len(), by_dir.len());
    let mut dirs: Vec<_> = by_dir.iter().collect();
    dirs.sort_by_key(|(d, _)| *d);

    for (dir, files) in dirs.iter().take(20) {
        out.push_str(&format!("{}/  ({})\n", dir, files.len()));
        for f in files.iter().take(5) {
            out.push_str(&format!("  {}\n", f));
        }
        if files.len() > 5 {
            out.push_str(&format!("  +{}\n", files.len() - 5));
        }
    }

    if dirs.len() > 20 {
        out.push_str(&format!("\n+{} more dirs\n", dirs.len() - 20));
    }

    out
}

pub fn auto_detect_filter(input: &str) -> fn(&str) -> String {
    let end = input.len().min(1024);
    // Avoid panic: byte 1024 may fall inside a multi-byte UTF-8 char
    let end = input.floor_char_boundary(end);
    let first_1k = &input[..end];

    if first_1k.contains("test result:") && first_1k.contains("passed;") {
        return crate::cmds::rust::cargo_cmd::filter_cargo_test;
    }

    if first_1k.contains("=== test session starts") {
        return crate::cmds::python::pytest_cmd::filter_pytest_output;
    }

    let first_trimmed = first_1k.trim_start();
    if first_trimmed.starts_with('{') && first_1k.contains("\"Action\"") {
        return go_test_wrapper;
    }

    if first_1k.contains(": error:") && first_1k.contains(".py:") {
        return crate::cmds::python::mypy_cmd::filter_mypy_output_piped;
    }

    // grep/rg: lines matching file:number:content
    if first_1k
        .lines()
        .take(5)
        .filter(|l| !l.trim().is_empty())
        .any(|l| {
            let parts: Vec<_> = l.splitn(3, ':').collect();
            parts.len() == 3 && parts[1].parse::<usize>().is_ok()
        })
    {
        return grep_wrapper;
    }

    if first_1k.contains("\"testResults\"") || first_1k.contains("\"numTotalTests\"") {
        return vitest_wrapper;
    }

    // find/fd: all non-empty lines look like file paths, minimum 3 lines
    let path_like_lines: usize = first_1k
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && !t.contains(':')
                && (t.starts_with('.') || t.starts_with('/') || t.contains('/'))
        })
        .count();
    let nonempty_lines: usize = first_1k.lines().filter(|l| !l.trim().is_empty()).count();
    if nonempty_lines >= 3 && path_like_lines == nonempty_lines {
        return find_wrapper;
    }

    identity_filter
}

fn identity_filter(input: &str) -> String {
    input.to_string()
}

fn apply_filter(filter_fn: fn(&str) -> String, input: &str) -> String {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| filter_fn(input)))
        .unwrap_or_else(|_| {
            eprintln!("[contextcrawler] warning: filter panicked — passing through raw output");
            input.to_string()
        })
}

pub fn run(filter_name: Option<&str>, passthrough: bool) -> Result<()> {
    if passthrough {
        std::io::copy(&mut std::io::stdin(), &mut std::io::stdout())
            .map_err(|e| anyhow::anyhow!("Failed to relay stdin: {}", e))?;
        return Ok(());
    }

    let mut buf = String::new();
    std::io::stdin()
        .take((RAW_CAP + 1) as u64)
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("Failed to read stdin: {}", e))?;
    if buf.len() > RAW_CAP {
        anyhow::bail!("stdin exceeds {} byte limit", RAW_CAP);
    }

    let filter_fn = match filter_name {
        Some(name) => resolve_filter(name).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown filter '{}'. Available: cargo-test, pytest, go-test, go-build, \
                 tsc, vitest, grep, rg, find, fd, git-log, git-diff, git-status, \
                 mypy, ruff-check, ruff-format, prettier",
                name
            )
        })?,
        None => auto_detect_filter(&buf),
    };

    let output = apply_filter(filter_fn, &buf);
    print!("{}", output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_filter_cargo_test() {
        let f = resolve_filter("cargo-test").expect("cargo-test filter must exist");
        let out = f("test result: ok. 5 passed; 0 failed");
        assert!(out.contains("passed") || out.contains("PASS"), "out={}", out);
    }

    #[test]
    fn test_resolve_filter_cargo_alias() {
        assert!(resolve_filter("cargo").is_some());
    }

    #[test]
    fn test_resolve_filter_grep() {
        let f = resolve_filter("grep").expect("grep filter must exist");
        let input = "src/main.rs:42:fn main() {\nsrc/lib.rs:10:pub fn helper() {}\n";
        let out = f(input);
        assert!(
            out.contains("main.rs") || out.contains("matches"),
            "out={}",
            out
        );
    }

    #[test]
    fn test_resolve_filter_rg_alias() {
        assert!(resolve_filter("rg").is_some());
    }

    #[test]
    fn test_resolve_filter_pytest() {
        assert!(resolve_filter("pytest").is_some());
    }

    #[test]
    fn test_resolve_filter_go_test() {
        assert!(resolve_filter("go-test").is_some());
    }

    #[test]
    fn test_resolve_filter_tsc() {
        assert!(resolve_filter("tsc").is_some());
    }

    #[test]
    fn test_resolve_filter_vitest() {
        assert!(resolve_filter("vitest").is_some());
    }

    #[test]
    fn test_resolve_filter_git_log() {
        assert!(resolve_filter("git-log").is_some());
    }

    #[test]
    fn test_resolve_filter_git_diff() {
        assert!(resolve_filter("git-diff").is_some());
    }

    #[test]
    fn test_resolve_filter_git_status() {
        assert!(resolve_filter("git-status").is_some());
    }

    #[test]
    fn test_resolve_filter_unknown_returns_none() {
        assert!(resolve_filter("nonexistent-filter").is_none());
    }

    #[test]
    fn test_auto_detect_cargo_test() {
        let input = "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_auto_detect_pytest() {
        let input = "=== test session starts ===\ncollected 3 items\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_auto_detect_grep_format() {
        let input = "src/main.rs:42:fn main() {\nsrc/lib.rs:10:pub fn helper() {}\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_auto_detect_go_test_ndjson() {
        let input = r#"{"Time":"2024-01-01T00:00:00Z","Action":"run","Package":"example/pkg"}
{"Time":"2024-01-01T00:00:01Z","Action":"pass","Package":"example/pkg","Elapsed":0.5}
"#;
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_auto_detect_unknown_returns_identity() {
        let input = "some random text that doesn't match any filter pattern\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert_eq!(out, input);
    }

    #[test]
    fn test_git_log_wrapper() {
        let input = "abc1234 Fix bug in parser (2 days ago) <alice>\n\
                     def5678 Add new feature (3 days ago) <bob>\n";
        let out = git_log_wrapper(input);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_git_diff_wrapper() {
        let input = "diff --git a/src/main.rs b/src/main.rs\n\
                     --- a/src/main.rs\n\
                     +++ b/src/main.rs\n\
                     @@ -1,3 +1,4 @@\n\
                     +// new comment\n\
                      fn main() {}\n";
        let out = git_diff_wrapper(input);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_resolve_filter_find() {
        let f = resolve_filter("find").expect("find filter must exist");
        let input = "./src/main.rs\n./src/lib.rs\n./tests/foo.rs\n";
        let out = f(input);
        assert!(out.contains("3 files"), "out={}", out);
    }

    #[test]
    fn test_resolve_filter_fd_alias() {
        assert!(resolve_filter("fd").is_some());
    }

    #[test]
    fn test_auto_detect_find_paths() {
        let input = "./src/main.rs\n./src/lib.rs\n./src/cmd/mod.rs\n./tests/foo.rs\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(out.contains("4 files"), "out={}", out);
    }

    #[test]
    fn test_auto_detect_find_absolute_paths() {
        let input = "/home/user/src/main.rs\n/home/user/src/lib.rs\n/home/user/tests/foo.rs\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(out.contains("3 files"), "out={}", out);
    }

    #[test]
    fn test_auto_detect_find_not_triggered_for_few_lines() {
        let input = "./src/main.rs\n./src/lib.rs\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert_eq!(out, input);
    }

    #[test]
    fn test_auto_detect_find_not_triggered_for_grep_output() {
        let input = "src/main.rs:42:fn main() {\nsrc/lib.rs:10:pub fn helper() {}\nsrc/a.rs:1:x\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(
            !out.contains("files"),
            "should not trigger find filter: out={}",
            out
        );
    }

    #[test]
    fn test_auto_detect_empty_input_is_identity() {
        let f = auto_detect_filter("");
        let out = f("");
        assert_eq!(out, "");
    }

    #[test]
    fn test_auto_detect_multibyte_at_1024_boundary() {
        // Build input where byte 1024 falls inside a multi-byte char (é = 2 bytes)
        let mut input = "a".repeat(1023);
        input.push('é'); // 2-byte char starting at byte 1023, ends at 1025
        let f = auto_detect_filter(&input);
        let out = f(&input);
        assert_eq!(out, input);
    }

    #[test]
    fn test_auto_detect_single_line_unknown() {
        let input = "hello world\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert_eq!(out, input);
    }

    #[test]
    fn test_resolve_filter_go_build() {
        assert!(resolve_filter("go-build").is_some());
    }

    #[test]
    fn test_resolve_filter_mypy() {
        assert!(resolve_filter("mypy").is_some());
    }

    #[test]
    fn test_resolve_filter_ruff_check() {
        assert!(resolve_filter("ruff-check").is_some());
    }

    #[test]
    fn test_resolve_filter_ruff_format() {
        assert!(resolve_filter("ruff-format").is_some());
    }

    #[test]
    fn test_resolve_filter_prettier() {
        assert!(resolve_filter("prettier").is_some());
    }

    #[test]
    fn test_panicking_filter_returns_passthrough() {
        fn panicking_filter(_input: &str) -> String {
            panic!("filter bug");
        }
        let input = "some output\n";
        let result = super::apply_filter(panicking_filter, input);
        assert_eq!(result, input);
    }

    fn count_tokens(s: &str) -> usize {
        s.split_whitespace().count()
    }

    #[test]
    fn test_grep_wrapper_token_savings() {
        // Realistic rg output: 200 matches across 10 files (20 per file → 10 shown + truncation)
        let mut input = String::new();
        for file_idx in 1..=10 {
            for line in 1..=20 {
                input.push_str(&format!(
                    "src/cmds/module{}/handler.rs:{}:    let result = process_request(ctx, &payload).await?;\n",
                    file_idx, line * 10
                ));
            }
        }
        let output = grep_wrapper(&input);
        let savings = 100.0 - (count_tokens(&output) as f64 / count_tokens(&input) as f64 * 100.0);
        assert!(
            savings >= 60.0,
            "grep filter: expected ≥60% savings, got {:.1}% (in={}, out={})",
            savings, count_tokens(&input), count_tokens(&output)
        );
    }

    #[test]
    fn test_grep_wrapper_varied_content_savings() {
        // Realistic varied output: 12 files, 15 matches each, every match a
        // different code line of varying length (some >200 chars to exercise
        // truncation). count > 5 per file → compact "+N more at L:" line.
        let snippets = [
            // First 5 are shown with content (mixed lengths; index 4 is >200 chars
            // to exercise the truncate helper on a displayed line).
            "    let config = Config::load(path)?;",
            "    self.dispatch(req)",
            "    let sum = total();",
            "    process(v)?;",
            "    let very_long_line = format!(\"this is an intentionally long diagnostic message that exceeds the two hundred character truncation boundary so that the truncate helper actually has to do some real work here and cut it off cleanly with an ellipsis at the end okay then\");",
            // Remaining 10 collapse to a comma-joined line-number list; they are
            // still substantial real code lines in the input.
            "        tracing::warn!(\"retrying connection to upstream endpoint {} after transient failure\", endpoint);",
            "    return Err(anyhow!(\"unexpected token {:?} at position {} while parsing the expression\", tok, pos));",
            "    let mut buffer: Vec<u8> = Vec::with_capacity(expected_payload_size_in_bytes);",
            "    while let Some(item) = queue.pop_front() { worker.submit(item).context(\"submit failed\")?; }",
            "    let decoded = serde_json::from_slice::<Envelope>(&raw).map_err(|e| ParseError::from(e))?;",
            "    self.metrics.record_latency(start.elapsed().as_millis() as u64, &route_label);",
            "    for (key, value) in headers.iter() { request.insert_header(key.clone(), value.clone()); }",
            "    let response = client.post(&url).json(&body).send().await.context(\"request failed\")?;",
            "    debug_assert!(index < self.len(), \"index out of bounds in the internal ring buffer slot\");",
            "    let checksum = compute_crc32(&payload).wrapping_add(seed).rotate_left(shift_amount);",
        ];
        let mut input = String::new();
        for file_idx in 1..=12 {
            for (i, snip) in snippets.iter().enumerate() {
                input.push_str(&format!(
                    "src/module{}/file{}.rs:{}:{}\n",
                    file_idx,
                    file_idx,
                    (i + 1) * 7,
                    snip
                ));
            }
        }
        let output = grep_wrapper(&input);
        let savings = 100.0 - (count_tokens(&output) as f64 / count_tokens(&input) as f64 * 100.0);
        assert!(
            savings >= 60.0,
            "grep varied filter: expected ≥60% savings, got {:.1}% (in={}, out={})",
            savings,
            count_tokens(&input),
            count_tokens(&output)
        );
        // Still surfaces real content snippets...
        assert!(
            output.contains("Config::load"),
            "expected a real content snippet in output: {}",
            output
        );
        // ...and a comma-joined line-number list on a "+N more at L:" line.
        let has_compact_list = output.lines().any(|l| l.contains("more at L:") && l.contains(','));
        assert!(
            has_compact_list,
            "expected a comma-joined '+N more at L:' line: {}",
            output
        );
    }

    #[test]
    fn test_grep_wrapper_no_overflow_line_at_boundary() {
        // A file with exactly 5 matches must NOT emit a "+N more at L:" line.
        let input = "src/a.rs:1:fn one() {}\n\
                     src/a.rs:2:fn two() {}\n\
                     src/a.rs:3:fn three() {}\n\
                     src/a.rs:4:fn four() {}\n\
                     src/a.rs:5:fn five() {}\n";
        let output = grep_wrapper(input);
        assert!(
            !output.contains("more at L:"),
            "≤5 matches must not emit an overflow line: {}",
            output
        );
    }

    #[test]
    fn test_find_wrapper_token_savings() {
        // Realistic find output: 500 files across 30 dirs (20-dir cap + 10-file cap both trigger)
        let mut input = String::new();
        for dir in 1..=30 {
            for file in 1..=17 {
                input.push_str(&format!(
                    "./src/components/feature{}/sub_{}/component_{}.tsx\n",
                    dir, dir, file
                ));
            }
        }
        let output = find_wrapper(&input);
        let savings = 100.0 - (count_tokens(&output) as f64 / count_tokens(&input) as f64 * 100.0);
        assert!(
            savings >= 60.0,
            "find filter: expected ≥60% savings, got {:.1}% (in={}, out={})",
            savings, count_tokens(&input), count_tokens(&output)
        );
    }

    #[test]
    fn test_auto_detect_mypy_output() {
        let input = "src/app.py:42: error: Argument 1 has incompatible type [arg-type]\n\
                     src/utils.py:10: error: Missing return statement [return]\n\
                     Found 2 errors in 2 files\n";
        let f = auto_detect_filter(input);
        let out = f(input);
        assert!(!out.is_empty());
    }
}
