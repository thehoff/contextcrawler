//! Filters TypeScript compiler errors, grouping them by file and error code.

use crate::core::runner;
use crate::core::stream::{BlockHandler, BlockStreamFilter};
use crate::core::utils::{check_forbidden_node_args, secure_node_command, tool_exists, truncate};
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};

lazy_static! {
    // Non-pretty tsc: `file(line,col): error TSxxxx: message` (the `--pretty false`
    // / CI format). Capture order: 1=file 2=line 3=col 4=severity 5=code 6=message.
    static ref TSC_ERROR: Regex =
        Regex::new(r"^(.+?)\((\d+),(\d+)\):\s+(error|warning)\s+(TS\d+):\s+(.+)$").unwrap();

    // Pretty tsc (the DEFAULT in a TTY and many CI configs):
    // `file:line:col - error TSxxxx: message`. Same capture order as TSC_ERROR so
    // both call sites can try one then the other without re-indexing groups.
    // Without this, pretty output matched nothing and the filter reported
    // "TypeScript compilation completed" while hiding every error (lying success).
    static ref TSC_ERROR_PRETTY: Regex =
        Regex::new(r"^(.+?):(\d+):(\d+)\s+-\s+(error|warning)\s+(TS\d+):\s+(.+)$").unwrap();
}

/// Match a tsc diagnostic header in either the non-pretty `file(line,col):` or
/// the pretty `file:line:col -` form. Both regexes share capture-group order
/// (1=file 2=line 3=col 4=severity 5=code 6=message).
fn match_tsc_error(line: &str) -> Option<regex::Captures<'_>> {
    TSC_ERROR
        .captures(line)
        .or_else(|| TSC_ERROR_PRETTY.captures(line))
}

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    // Issue #37: gate user-forwarded args before they reach tsc/npx.
    check_forbidden_node_args(args).map_err(|m| anyhow!(m))?;

    let tsc_exists = tool_exists("tsc");

    let mut cmd = if tsc_exists {
        secure_node_command("tsc")
    } else {
        let mut c = secure_node_command("npx");
        c.arg("tsc");
        c
    };

    for arg in args {
        cmd.arg(arg);
    }

    if verbose > 0 {
        let tool = if tsc_exists { "tsc" } else { "npx tsc" };
        eprintln!("Running: {} {}", tool, args.join(" "));
    }

    runner::run_streamed(
        cmd,
        "tsc",
        &args.join(" "),
        Box::new(BlockStreamFilter::new(TscHandler::new())),
        runner::RunOptions::with_tee("tsc"),
    )
}

struct TscHandler {
    error_count: usize,
    files: HashSet<String>,
    code_counts: HashMap<String, usize>,
}

impl TscHandler {
    fn new() -> Self {
        Self {
            error_count: 0,
            files: HashSet::new(),
            code_counts: HashMap::new(),
        }
    }
}

impl BlockHandler for TscHandler {
    fn should_skip(&mut self, line: &str) -> bool {
        line.starts_with("Found ")
    }

    fn is_block_start(&mut self, line: &str) -> bool {
        if let Some(caps) = match_tsc_error(line) {
            self.error_count += 1;
            self.files.insert(caps[1].to_string());
            *self.code_counts.entry(caps[5].to_string()).or_insert(0) += 1;
            true
        } else {
            false
        }
    }

    fn is_block_continuation(&mut self, line: &str, _block: &[String]) -> bool {
        line.starts_with("  ") || line.starts_with('\t')
    }

    fn format_summary(&self, exit_code: i32, raw: &str) -> Option<String> {
        if self.error_count == 0 {
            // Config errors (TS5083/TS18003/TS5057) and tsc crashes carry no
            // `file(line,col):` prefix, so they never increment error_count. On
            // a non-zero exit with zero recognised diagnostics, surface the raw
            // output instead of lying with "No errors found".
            return if exit_code == 0 {
                Some("TypeScript: No errors found\n".to_string())
            } else {
                Some(crate::core::display_helpers::format_tool_failure(
                    "TypeScript",
                    raw,
                    exit_code,
                ))
            };
        }

        let mut result = format!(
            "TypeScript: {} errors in {} files\n",
            self.error_count,
            self.files.len()
        );

        if self.code_counts.len() > 1 {
            let mut counts: Vec<_> = self.code_counts.iter().collect();
            counts.sort_by(|a, b| b.1.cmp(a.1));
            let codes_str: Vec<String> = counts
                .iter()
                .take(5)
                .map(|(code, count)| format!("{} ({}x)", code, count))
                .collect();
            result.push_str(&format!("Top codes: {}\n", codes_str.join(", ")));
        }

        Some(result)
    }
}

/// Non-streaming tsc filter. Reachable only via the `contextcrawler pipe tsc`
/// path (`pipe_cmd::resolve_filter`), which pipes stdin through an
/// `fn(&str) -> String` and therefore has NO exit code to act on. The live
/// `run()` path uses the streaming [`TscHandler::format_summary`] instead, which
/// is exit-aware. Because no exit status is available here, this variant cannot
/// misreport a failed exit as success — it only ever sees raw text.
pub(crate) fn filter_tsc_output(output: &str) -> String {
    struct TsError {
        file: String,
        line: usize,
        code: String,
        message: String,
        context_lines: Vec<String>,
    }

    let mut errors: Vec<TsError> = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        if let Some(caps) = match_tsc_error(line) {
            let mut err = TsError {
                file: caps[1].to_string(),
                line: caps[2].parse().unwrap_or(0),
                code: caps[5].to_string(),
                message: caps[6].to_string(),
                context_lines: Vec::new(),
            };

            // Capture continuation lines (indented context from tsc)
            i += 1;
            while i < lines.len() {
                let next = lines[i];
                if !next.is_empty()
                    && (next.starts_with("  ") || next.starts_with('\t'))
                    && match_tsc_error(next).is_none()
                {
                    err.context_lines.push(next.trim().to_string());
                    i += 1;
                } else {
                    break;
                }
            }

            errors.push(err);
        } else {
            i += 1;
        }
    }

    if errors.is_empty() {
        if output.contains("Found 0 errors") {
            return "TypeScript: No errors found".to_string();
        }
        return "TypeScript compilation completed".to_string();
    }

    // Group by file
    let mut by_file: HashMap<String, Vec<&TsError>> = HashMap::new();
    for err in &errors {
        by_file.entry(err.file.clone()).or_default().push(err);
    }

    // Count by error code for summary
    let mut by_code: HashMap<String, usize> = HashMap::new();
    for err in &errors {
        *by_code.entry(err.code.clone()).or_insert(0) += 1;
    }

    let mut result = String::new();
    result.push_str(&format!(
        "TypeScript: {} errors in {} files\n",
        errors.len(),
        by_file.len()
    ));

    // Top error codes summary (compact, one line)
    let mut code_counts: Vec<_> = by_code.iter().collect();
    code_counts.sort_by(|a, b| b.1.cmp(a.1));

    if code_counts.len() > 1 {
        let codes_str: Vec<String> = code_counts
            .iter()
            .take(5)
            .map(|(code, count)| format!("{} ({}x)", code, count))
            .collect();
        result.push_str(&format!("Top codes: {}\n\n", codes_str.join(", ")));
    }

    // Files sorted by error count (most errors first)
    let mut files_sorted: Vec<_> = by_file.iter().collect();
    files_sorted.sort_by_key(|b| std::cmp::Reverse(b.1.len()));

    // Show every error per file — no limits
    for (file, file_errors) in &files_sorted {
        result.push_str(&format!("{} ({} errors)\n", file, file_errors.len()));

        for err in *file_errors {
            result.push_str(&format!(
                "  L{}: {} {}\n",
                err.line,
                err.code,
                truncate(&err.message, 120)
            ));
            for ctx in &err.context_lines {
                result.push_str(&format!("    {}\n", truncate(ctx, 120)));
            }
        }
        result.push('\n');
    }

    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_tsc_output() {
        let output = r#"
src/server/api/auth.ts(12,5): error TS2322: Type 'string' is not assignable to type 'number'.
src/server/api/auth.ts(15,10): error TS2345: Argument of type 'number' is not assignable to parameter of type 'string'.
src/components/Button.tsx(8,3): error TS2339: Property 'onClick' does not exist on type 'ButtonProps'.
src/components/Button.tsx(10,5): error TS2322: Type 'string' is not assignable to type 'number'.

Found 4 errors in 2 files.
"#;
        let result = filter_tsc_output(output);
        assert!(result.contains("TypeScript: 4 errors in 2 files"));
        assert!(result.contains("auth.ts (2 errors)"));
        assert!(result.contains("Button.tsx (2 errors)"));
        assert!(result.contains("TS2322"));
        assert!(!result.contains("Found 4 errors")); // Summary line should be replaced
    }

    #[test]
    fn test_every_error_message_shown() {
        let output = "\
src/api.ts(10,5): error TS2322: Type 'string' is not assignable to type 'number'.
src/api.ts(20,5): error TS2322: Type 'boolean' is not assignable to type 'string'.
src/api.ts(30,5): error TS2322: Type 'null' is not assignable to type 'object'.
";
        let result = filter_tsc_output(output);
        // Each error message must be individually visible, not collapsed
        assert!(result.contains("Type 'string' is not assignable to type 'number'"));
        assert!(result.contains("Type 'boolean' is not assignable to type 'string'"));
        assert!(result.contains("Type 'null' is not assignable to type 'object'"));
        assert!(result.contains("L10:"));
        assert!(result.contains("L20:"));
        assert!(result.contains("L30:"));
    }

    #[test]
    fn test_continuation_lines_preserved() {
        let output = "\
src/app.tsx(10,3): error TS2322: Type '{ children: Element; }' is not assignable to type 'Props'.
  Property 'children' does not exist on type 'Props'.
src/app.tsx(20,5): error TS2345: Argument of type 'number' is not assignable to parameter of type 'string'.
";
        let result = filter_tsc_output(output);
        assert!(result.contains("Property 'children' does not exist on type 'Props'"));
        assert!(result.contains("L10:"));
        assert!(result.contains("L20:"));
    }

    #[test]
    fn test_pretty_format_errors_recognised() {
        // tsc's DEFAULT (pretty) format: `file:line:col - error TSxxxx`, with a
        // code frame the filter should ignore. Regression: pretty output used to
        // match nothing and report "TypeScript compilation completed", hiding
        // every error (lying success). Caught by the proof harness.
        let output = "\
src/api/client.ts:42:7 - error TS2322: Type 'string | undefined' is not assignable to type 'string'.

42       baseUrl: process.env.API_BASE,
         ~~~~~~~

src/components/Cart.tsx:115:9 - error TS2532: Object is possibly 'undefined'.

115         total += items[i].price;
            ~~~~~~~~~~~~~~~~~~~~~~~~

Found 2 errors in 2 files.
";
        let result = filter_tsc_output(output);
        assert!(
            result.contains("TypeScript: 2 errors in 2 files"),
            "pretty errors must be counted, got:\n{result}"
        );
        assert!(result.contains("TS2322"));
        assert!(result.contains("TS2532"));
        assert!(result.contains("client.ts"));
        assert!(result.contains("Cart.tsx"));
        // The exact lying-success string must never appear when errors exist.
        assert!(!result.contains("compilation completed"));
    }

    #[test]
    fn test_pretty_and_non_pretty_mixed_count() {
        // Defensive: both forms recognised in one stream, no double counting.
        let output = "\
src/a.ts:1:1 - error TS1000: pretty form.
src/b.ts(2,2): error TS1001: non-pretty form.
";
        let result = filter_tsc_output(output);
        assert!(
            result.contains("TypeScript: 2 errors in 2 files"),
            "{result}"
        );
    }

    #[test]
    fn test_no_file_limit() {
        // 15 files with errors — all must appear
        let mut output = String::new();
        for i in 1..=15 {
            output.push_str(&format!(
                "src/file{}.ts({},1): error TS2322: Error in file {}.\n",
                i, i, i
            ));
        }
        let result = filter_tsc_output(&output);
        assert!(result.contains("15 errors in 15 files"));
        for i in 1..=15 {
            assert!(
                result.contains(&format!("file{}.ts", i)),
                "file{}.ts missing from output",
                i
            );
        }
    }

    #[test]
    fn test_filter_no_errors() {
        let output = "Found 0 errors. Watching for file changes.";
        let result = filter_tsc_output(output);
        assert!(result.contains("No errors found"));
    }

    // --- Streaming handler tests ---

    use crate::core::stream::tests::run_block_filter;

    #[test]
    fn test_tsc_stream_errors() {
        let input = "\
src/server/api/auth.ts(12,5): error TS2322: Type 'string' is not assignable to type 'number'.
src/server/api/auth.ts(15,10): error TS2345: Argument of type 'number' is not assignable to parameter of type 'string'.
src/components/Button.tsx(8,3): error TS2339: Property 'onClick' does not exist on type 'ButtonProps'.

Found 3 errors in 2 files.
";
        let mut f = BlockStreamFilter::new(TscHandler::new());
        let result = run_block_filter(&mut f, input, 1);
        assert!(result.contains("TS2322"), "got: {}", result);
        assert!(result.contains("TS2345"), "got: {}", result);
        assert!(result.contains("3 errors in 2 files"), "got: {}", result);
        assert!(!result.contains("Found 3"), "got: {}", result);
    }

    #[test]
    fn test_tsc_stream_no_errors() {
        let input = "Found 0 errors. Watching for file changes.\n";
        let mut f = BlockStreamFilter::new(TscHandler::new());
        let result = run_block_filter(&mut f, input, 0);
        assert!(result.contains("No errors found"), "got: {}", result);
    }

    #[test]
    fn test_tsc_stream_config_error_not_reported_as_success() {
        // Regression: a tsc config error (TS5083) carries no `file(line,col):`
        // prefix, so error_count stays 0. On a non-zero exit the filter must
        // NOT print "No errors found" and MUST surface the real error.
        let input = "error TS5083: Cannot read file 'tsconfig.json'.\n";
        let mut f = BlockStreamFilter::new(TscHandler::new());
        let result = run_block_filter(&mut f, input, 1);
        assert!(
            !result.contains("No errors found"),
            "must not claim success on failed run: {}",
            result
        );
        assert!(
            result.contains("TS5083"),
            "must surface real error: {}",
            result
        );
        assert!(result.contains("failed (exit 1)"), "got: {}", result);
    }

    #[test]
    fn test_tsc_stream_continuation_lines() {
        let input = "\
src/app.tsx(10,3): error TS2322: Type '{ children: Element; }' is not assignable to type 'Props'.
  Property 'children' does not exist on type 'Props'.
src/app.tsx(20,5): error TS2345: Argument of type 'number' is not assignable.
";
        let mut f = BlockStreamFilter::new(TscHandler::new());
        let result = run_block_filter(&mut f, input, 1);
        assert!(
            result.contains("Property 'children' does not exist"),
            "got: {}",
            result
        );
        assert!(result.contains("TS2322"), "got: {}", result);
        assert!(result.contains("TS2345"), "got: {}", result);
    }
}
