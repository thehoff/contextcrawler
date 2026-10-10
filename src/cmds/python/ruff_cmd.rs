//! Filters Ruff linter and formatter output.

use crate::core::config;
use crate::core::runner;
use crate::core::utils::{secure_python_command, truncate};
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct RuffLocation {
    #[allow(dead_code)]
    row: usize,
    #[allow(dead_code)]
    column: usize,
}

#[derive(Debug, Deserialize)]
struct RuffFix {
    #[allow(dead_code)]
    applicability: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuffDiagnostic {
    code: String,
    #[allow(dead_code)]
    message: String,
    #[allow(dead_code)]
    location: RuffLocation,
    #[allow(dead_code)]
    end_location: Option<RuffLocation>,
    filename: String,
    fix: Option<RuffFix>,
}

/// `ruff` subcommands that are NOT `check`.
///
/// Ruff's default command is `check`, so a bare path (`ruff src/`) still
/// routes to `ruff check`. An explicit subcommand must run as itself —
/// routing `ruff server` through `ruff check server` would try to lint files
/// named "server".
const NON_CHECK_SUBCOMMANDS: &[&str] = &[
    "format", "version", "rule", "linter", "clean", "server", "analyze", "config",
];

/// Whether `args` selects the default `check` command (handled by the filter
/// path) versus an explicit subcommand that must run verbatim.
fn is_check_invocation(args: &[String]) -> bool {
    match args.first() {
        None => true,
        Some(first) => {
            first == "check"
                || (!first.starts_with('-') && !NON_CHECK_SUBCOMMANDS.contains(&first.as_str()))
        }
    }
}

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    let is_check = is_check_invocation(args);

    let is_format = args.iter().any(|a| a == "format");

    // When ruff itself would not emit JSON, we inject `--output-format=json`
    // so `filter_ruff_check_json` can parse the output. Record that injection
    // so the no-bloat guard can keep the filter's summary over the raw `[]`
    // payload. If the user supplied `--output-format` themselves, their
    // requested format is what should come back, and the guard stays in charge.
    let user_requested_output_format = args.iter().any(|a| a.starts_with("--output-format"));
    let injected_json = is_check && !user_requested_output_format;

    // Strip PYTHONPATH / PYTHONSTARTUP / PIP_* from inherited env to
    // prevent sitecustomize.py / startup-file hijack. See issue #36.
    let mut cmd = secure_python_command("ruff");

    if is_check {
        if !user_requested_output_format {
            cmd.arg("check").arg("--output-format=json");
        } else {
            cmd.arg("check");
        }

        let start_idx = if !args.is_empty() && args[0] == "check" {
            1
        } else {
            0
        };
        for arg in &args[start_idx..] {
            cmd.arg(arg);
        }

        if args
            .iter()
            .skip(start_idx)
            .all(|a| a.starts_with('-') || a.contains('='))
        {
            cmd.arg(".");
        }
    } else {
        for arg in args {
            cmd.arg(arg);
        }
    }

    if verbose > 0 {
        eprintln!("Running: ruff {}", args.join(" "));
    }

    // Only the injected-JSON case opts out of the no-bloat guard: there the
    // raw payload is a bare `[]` we caused to exist, and the filter's summary
    // is strictly more useful. When the user asked for JSON, keep the guard so
    // their requested output survives.
    let opts = if injected_json {
        runner::RunOptions::stdout_only().keep_filtered()
    } else {
        runner::RunOptions::stdout_only()
    };

    runner::run_filtered(
        cmd,
        "ruff",
        &args.join(" "),
        move |stdout| {
            if is_check && !stdout.trim().is_empty() {
                filter_ruff_check_json(stdout)
            } else if is_format {
                filter_ruff_format(stdout)
            } else {
                stdout.trim().to_string()
            }
        },
        opts,
    )
}

/// Filter ruff check JSON output - group by rule and file
pub fn filter_ruff_check_json(output: &str) -> String {
    let diagnostics: Result<Vec<RuffDiagnostic>, _> = serde_json::from_str(output);

    let diagnostics = match diagnostics {
        Ok(d) => d,
        Err(e) => {
            // Fallback if JSON parsing fails
            return format!(
                "Ruff check (JSON parse failed: {})\n{}",
                e,
                truncate(output, config::limits().passthrough_max_chars)
            );
        }
    };

    if diagnostics.is_empty() {
        return "Ruff: No issues found".to_string();
    }

    let total_issues = diagnostics.len();
    let fixable_count = diagnostics.iter().filter(|d| d.fix.is_some()).count();

    // Count unique files
    let unique_files: std::collections::HashSet<_> =
        diagnostics.iter().map(|d| &d.filename).collect();
    let total_files = unique_files.len();

    // Group by rule code
    let mut by_rule: HashMap<String, usize> = HashMap::new();
    for diag in &diagnostics {
        *by_rule.entry(diag.code.clone()).or_insert(0) += 1;
    }

    // Group by file
    let mut by_file: HashMap<&str, usize> = HashMap::new();
    for diag in &diagnostics {
        *by_file.entry(&diag.filename).or_insert(0) += 1;
    }

    let mut file_counts: Vec<_> = by_file.iter().collect();
    file_counts.sort_by(|a, b| b.1.cmp(a.1));

    // Build output
    let mut result = String::new();
    result.push_str(&format!(
        "Ruff: {} issues in {} files",
        total_issues, total_files
    ));

    if fixable_count > 0 {
        result.push_str(&format!(" ({} fixable)", fixable_count));
    }
    result.push('\n');

    // Show top rules
    let mut rule_counts: Vec<_> = by_rule.iter().collect();
    rule_counts.sort_by(|a, b| b.1.cmp(a.1));

    if !rule_counts.is_empty() {
        result.push_str("Top rules:\n");
        for (rule, count) in rule_counts.iter().take(10) {
            result.push_str(&format!("  {} ({}x)\n", rule, count));
        }
        result.push('\n');
    }

    // Show top files
    result.push_str("Top files:\n");
    for (file, count) in file_counts.iter().take(10) {
        let short_path = compact_path(file);
        result.push_str(&format!("  {} ({} issues)\n", short_path, count));

        // Show top 3 rules in this file
        let mut file_rules: HashMap<String, usize> = HashMap::new();
        for diag in diagnostics.iter().filter(|d| &d.filename == *file) {
            *file_rules.entry(diag.code.clone()).or_insert(0) += 1;
        }

        let mut file_rule_counts: Vec<_> = file_rules.iter().collect();
        file_rule_counts.sort_by(|a, b| b.1.cmp(a.1));

        for (rule, count) in file_rule_counts.iter().take(3) {
            result.push_str(&format!("    {} ({})\n", rule, count));
        }
    }

    if file_counts.len() > 10 {
        result.push_str(&format!("\n... +{} more files\n", file_counts.len() - 10));
    }

    if fixable_count > 0 {
        result.push_str(&format!(
            "\n[hint] Run `ruff check --fix` to auto-fix {} issues\n",
            fixable_count
        ));
    }

    result.trim().to_string()
}

/// Filter ruff format output - show files that need formatting
pub fn filter_ruff_format(output: &str) -> String {
    let mut files_to_format: Vec<String> = Vec::new();
    let mut files_checked = 0;

    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        // Count "would reformat" lines (check mode) - case insensitive
        if lower.contains("would reformat:") {
            // Extract filename from "Would reformat: path/to/file.py"
            if let Some(filename) = trimmed.split(':').nth(1) {
                files_to_format.push(filename.trim().to_string());
            }
        }

        // Count total checked files - look for patterns like "3 files left unchanged"
        if lower.contains("left unchanged") {
            // Find "X file(s) left unchanged" pattern specifically
            // Split by comma to handle "2 files would be reformatted, 3 files left unchanged"
            let parts: Vec<&str> = trimmed.split(',').collect();
            for part in parts {
                let part_lower = part.to_lowercase();
                if part_lower.contains("left unchanged") {
                    let words: Vec<&str> = part.split_whitespace().collect();
                    // Look for number before "file" or "files"
                    for (i, word) in words.iter().enumerate() {
                        if (word == &"file" || word == &"files") && i > 0 {
                            if let Ok(count) = words[i - 1].parse::<usize>() {
                                files_checked = count;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    let output_lower = output.to_lowercase();

    // Check if all files are formatted
    if files_to_format.is_empty() && output_lower.contains("left unchanged") {
        return "Ruff format: All files formatted correctly".to_string();
    }

    let mut result = String::new();

    if output_lower.contains("would reformat") {
        // Check mode: show files that need formatting
        if files_to_format.is_empty() {
            result.push_str("Ruff format: All files formatted correctly\n");
        } else {
            result.push_str(&format!(
                "Ruff format: {} files need formatting\n",
                files_to_format.len()
            ));

            for (i, file) in files_to_format.iter().take(10).enumerate() {
                result.push_str(&format!("{}. {}\n", i + 1, compact_path(file)));
            }

            if files_to_format.len() > 10 {
                result.push_str(&format!(
                    "\n... +{} more files\n",
                    files_to_format.len() - 10
                ));
            }

            if files_checked > 0 {
                result.push_str(&format!("\n{} files already formatted\n", files_checked));
            }

            result.push_str("\n[hint] Run `ruff format` to format these files\n");
        }
    } else {
        // Write mode or other output - show summary
        result.push_str(output.trim());
    }

    result.trim().to_string()
}

/// Compact file path (remove common prefixes)
fn compact_path(path: &str) -> String {
    let path = path.replace('\\', "/");

    if let Some(pos) = path.rfind("/src/") {
        format!("src/{}", &path[pos + 5..])
    } else if let Some(pos) = path.rfind("/lib/") {
        format!("lib/{}", &path[pos + 5..])
    } else if let Some(pos) = path.rfind("/tests/") {
        format!("tests/{}", &path[pos + 7..])
    } else if let Some(pos) = path.rfind('/') {
        path[pos + 1..].to_string()
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_ruff_check_no_issues() {
        let output = "[]";
        let result = filter_ruff_check_json(output);
        assert!(result.contains("Ruff"));
        assert!(result.contains("No issues found"));
    }

    #[test]
    fn test_filter_ruff_check_with_issues() {
        let output = r#"[
  {
    "code": "F401",
    "message": "`os` imported but unused",
    "location": {"row": 1, "column": 8},
    "end_location": {"row": 1, "column": 10},
    "filename": "src/main.py",
    "fix": {"applicability": "safe"}
  },
  {
    "code": "F401",
    "message": "`sys` imported but unused",
    "location": {"row": 2, "column": 8},
    "end_location": {"row": 2, "column": 11},
    "filename": "src/main.py",
    "fix": null
  },
  {
    "code": "E501",
    "message": "Line too long (100 > 88 characters)",
    "location": {"row": 10, "column": 89},
    "end_location": {"row": 10, "column": 100},
    "filename": "src/utils.py",
    "fix": null
  }
]"#;
        let result = filter_ruff_check_json(output);
        assert!(result.contains("3 issues"));
        assert!(result.contains("2 files"));
        assert!(result.contains("1 fixable"));
        assert!(result.contains("F401"));
        assert!(result.contains("E501"));
        assert!(result.contains("main.py"));
        assert!(result.contains("utils.py"));
    }

    #[test]
    fn test_filter_ruff_format_all_formatted() {
        let output = "5 files left unchanged";
        let result = filter_ruff_format(output);
        assert!(result.contains("Ruff format"));
        assert!(result.contains("All files formatted correctly"));
    }

    #[test]
    fn test_filter_ruff_format_needs_formatting() {
        let output = r#"Would reformat: src/main.py
Would reformat: tests/test_utils.py
2 files would be reformatted, 3 files left unchanged"#;
        let result = filter_ruff_format(output);
        assert!(result.contains("2 files need formatting"));
        assert!(result.contains("main.py"));
        assert!(result.contains("test_utils.py"));
        assert!(result.contains("3 files already formatted"));
    }

    #[test]
    fn test_compact_path() {
        assert_eq!(
            compact_path("/Users/foo/project/src/main.py"),
            "src/main.py"
        );
        assert_eq!(compact_path("/home/user/app/lib/utils.py"), "lib/utils.py");
        assert_eq!(
            compact_path("C:\\Users\\foo\\project\\tests\\test.py"),
            "tests/test.py"
        );
        assert_eq!(compact_path("relative/file.py"), "file.py");
    }

    #[test]
    fn test_is_check_invocation_defaults_to_check() {
        // No args, an explicit `check`, or a bare path all mean `ruff check`.
        assert!(is_check_invocation(&[]));
        assert!(is_check_invocation(&["check".to_string()]));
        assert!(is_check_invocation(&[
            "check".to_string(),
            "src/".to_string()
        ]));
        assert!(is_check_invocation(&[".".to_string()]));
        assert!(is_check_invocation(&["src/main.py".to_string()]));
        // A leading flag is left to ruff itself (unchanged behaviour).
        assert!(!is_check_invocation(&[
            "--select".to_string(),
            "E501".to_string()
        ]));
    }

    #[test]
    fn test_is_check_invocation_excludes_subcommands() {
        // Every non-check subcommand must run as itself, never as
        // `ruff check <subcommand>`.
        for sub in NON_CHECK_SUBCOMMANDS {
            assert!(
                !is_check_invocation(&[sub.to_string()]),
                "`ruff {sub}` must not be routed through check"
            );
        }
        assert!(!is_check_invocation(&[
            "rule".to_string(),
            "F401".to_string()
        ]));
        assert!(!is_check_invocation(&["server".to_string()]));
        assert!(!is_check_invocation(&["clean".to_string()]));
        assert!(!is_check_invocation(&["analyze".to_string()]));
        assert!(!is_check_invocation(&[
            "config".to_string(),
            "list".to_string()
        ]));
    }
}
