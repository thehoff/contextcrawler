//! Filters pytest output to show only failures and the summary line.

use crate::core::runner;
use crate::core::utils::{
    check_forbidden_pytest_args, secure_python_command, strip_ansi, tool_exists, truncate,
};
use anyhow::Result;

#[derive(Debug, PartialEq)]
enum ParseState {
    Header,
    TestProgress,
    Failures,
    Errors,
    Summary,
}

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    // Reject pytest flags that load arbitrary user-controlled code
    // (`-p /path/to/plugin.py`, `--rootdir <attacker-path>`). See #36.
    if let Err(msg) = check_forbidden_pytest_args(args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    // `secure_python_command` strips PYTHONPATH / PYTHONSTARTUP / PIP_*
    // from the inherited env so a tainted parent can't sideload a
    // sitecustomize.py / startup script / pip index. See issue #36.
    let mut cmd = if tool_exists("pytest") {
        secure_python_command("pytest")
    } else {
        let mut c = secure_python_command("python");
        c.arg("-m").arg("pytest");
        c
    };

    let has_tb_flag = args.iter().any(|a| a.starts_with("--tb"));
    let has_quiet_flag = args.iter().any(|a| a == "-q" || a == "--quiet");

    if !has_tb_flag {
        cmd.arg("--tb=short");
    }
    if !has_quiet_flag {
        cmd.arg("-q");
    }

    for arg in args {
        cmd.arg(arg);
    }

    if verbose > 0 {
        eprintln!("Running: pytest --tb=short -q {}", args.join(" "));
    }

    // Exit-aware: a crashed pytest (collection/import error with no parseable
    // summary) must surface the real error instead of "No tests collected".
    runner::run_filtered_with_exit(
        cmd,
        "pytest",
        &args.join(" "),
        filter_pytest_output,
        runner::RunOptions::stdout_only().tee("pytest"),
    )
}

pub(crate) fn filter_pytest_output(output: &str, exit_code: i32) -> String {
    // Strip ANSI escapes up-front: pytest emits coloured output when it
    // detects a TTY (or when forced), and colour codes wrapping the
    // `=== ... ===` section markers / `FAILED`/`passed` summary tokens
    // would evade the `starts_with`/`contains` state machine below,
    // silently hiding failures (G6 #100).
    //
    // Codex G6 follow-up — no user-visible colour regression: this
    // filter emits a fully synthesised compact summary (see
    // `build_pytest_summary`: "Pytest: N passed, M failed", "[FAIL]
    // <name>", truncated error lines). It never echoes pytest's
    // original lines verbatim, so pytest's TTY colour was already
    // discarded by the reformatting before this change. Stripping
    // here only affects the matcher's input — there is no original
    // colour left to preserve, so no split matcher/display paths.
    let output = strip_ansi(output);
    let output = output.as_str();

    let mut state = ParseState::Header;
    let mut test_files: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut current_failure: Vec<String> = Vec::new();
    let mut summary_line = String::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // State transitions
        if trimmed.starts_with("===") && trimmed.contains("test session starts") {
            state = ParseState::Header;
            continue;
        } else if trimmed.starts_with("===") && trimmed.contains("FAILURES") {
            // Flush any in-progress error block before switching sections.
            if !current_failure.is_empty() {
                failures.push(current_failure.join("\n"));
                current_failure.clear();
            }
            state = ParseState::Failures;
            continue;
        } else if trimmed.starts_with("===") && trimmed.contains("ERRORS") {
            // pytest emits a dedicated `=== ERRORS ===` section for
            // collection/import/fixture errors. Without collecting it, the
            // tracebacks were silently dropped. Flush any in-progress block first.
            if !current_failure.is_empty() {
                failures.push(current_failure.join("\n"));
                current_failure.clear();
            }
            state = ParseState::Errors;
            continue;
        } else if trimmed.starts_with("===") && trimmed.contains("short test summary") {
            state = ParseState::Summary;
            // Save current failure if any
            if !current_failure.is_empty() {
                failures.push(current_failure.join("\n"));
                current_failure.clear();
            }
            continue;
        } else if trimmed.starts_with("===")
            && (trimmed.contains("passed")
                || trimmed.contains("failed")
                || trimmed.contains("skipped")
                || trimmed.contains("error"))
        {
            summary_line = trimmed.to_string();
            continue;
        // quiet mode (-q): bare summary without === wrapper, e.g. "5 failed, 1698 passed, 2 skipped in 108.89s"
        // " error" is included so a pure-error quiet summary ("3 errors in 1.23s") is captured.
        } else if summary_line.is_empty()
            && !trimmed.starts_with("===")
            && !trimmed.starts_with("FAILED")
            && !trimmed.starts_with("ERROR")
            && (trimmed.contains(" passed")
                || trimmed.contains(" failed")
                || trimmed.contains(" skipped")
                || trimmed.contains(" error"))
            && trimmed.contains(" in ")
        {
            summary_line = trimmed.to_string();
            continue;
        }

        // Process based on state
        match state {
            ParseState::Header => {
                if trimmed.starts_with("collected") {
                    state = ParseState::TestProgress;
                }
            }
            ParseState::TestProgress => {
                // Lines like "tests/test_foo.py ....  [ 40%]"
                if !trimmed.is_empty()
                    && !trimmed.starts_with("===")
                    && (trimmed.contains(".py") || trimmed.contains("%]"))
                {
                    test_files.push(trimmed.to_string());
                }
            }
            ParseState::Failures | ParseState::Errors => {
                // Collect failure/error details (both sections share block layout)
                if trimmed.starts_with("___") {
                    // New failure/error section
                    if !current_failure.is_empty() {
                        failures.push(current_failure.join("\n"));
                        current_failure.clear();
                    }
                    current_failure.push(trimmed.to_string());
                } else if !trimmed.is_empty() && !trimmed.starts_with("===") {
                    current_failure.push(trimmed.to_string());
                }
            }
            ParseState::Summary => {
                // FAILED / ERROR test lines
                if trimmed.starts_with("FAILED") || trimmed.starts_with("ERROR") {
                    failures.push(trimmed.to_string());
                }
            }
        }
    }

    // Save last failure if any
    if !current_failure.is_empty() {
        failures.push(current_failure.join("\n"));
    }

    // A crashed pytest (e.g. a top-level collection/import error that aborts
    // before any summary line is printed) would otherwise be misreported as
    // "No tests collected" while discarding the traceback. On a non-zero exit
    // with nothing parseable, surface the raw output instead.
    if exit_code != 0 && summary_line.is_empty() && failures.is_empty() {
        return crate::core::display_helpers::format_tool_failure("pytest", output, exit_code);
    }

    // Build compact output
    build_pytest_summary(&summary_line, &test_files, &failures)
}

fn build_pytest_summary(summary: &str, _test_files: &[String], failures: &[String]) -> String {
    // Parse summary line
    let (passed, failed, skipped, errors) = parse_summary_line(summary);

    // Success is gated on BOTH failed == 0 AND errors == 0. pytest reports
    // collection/import/fixture failures as `errors` (e.g. "5 passed, 2 errors"),
    // which must never be summarised as a clean "Pytest: N passed".
    if failed == 0 && errors == 0 && passed > 0 {
        return format!("Pytest: {} passed", passed);
    }

    // Pure-error runs (e.g. "3 errors", 0 tests collected) must surface the
    // errors, not claim "No tests collected".
    if passed == 0 && failed == 0 && skipped == 0 && errors == 0 {
        return "Pytest: No tests collected".to_string();
    }

    let mut result = String::new();
    result.push_str(&format!("Pytest: {} passed, {} failed", passed, failed));
    if errors > 0 {
        result.push_str(&format!(", {} errors", errors));
    }
    if skipped > 0 {
        result.push_str(&format!(", {} skipped", skipped));
    }
    result.push('\n');

    if failures.is_empty() {
        return result.trim().to_string();
    }

    // Show failures (limit to key information)
    result.push_str("\nFailures:\n");

    for (i, failure) in failures.iter().take(5).enumerate() {
        // Extract test name and key error info
        let lines: Vec<&str> = failure.lines().collect();

        // First line is usually test name (after ___)
        if let Some(first_line) = lines.first() {
            if first_line.starts_with("___") {
                // Extract test name between ___
                let test_name = first_line.trim_matches('_').trim();
                result.push_str(&format!("{}. [FAIL] {}\n", i + 1, test_name));
            } else if first_line.starts_with("FAILED") {
                // Summary format: "FAILED tests/test_foo.py::test_bar - AssertionError"
                let parts: Vec<&str> = first_line.split(" - ").collect();
                if let Some(test_path) = parts.first() {
                    let test_name = test_path.trim_start_matches("FAILED ");
                    result.push_str(&format!("{}. [FAIL] {}\n", i + 1, test_name));
                }
                if parts.len() > 1 {
                    result.push_str(&format!("     {}\n", truncate(parts[1], 100)));
                }
                continue;
            } else if first_line.starts_with("ERROR") {
                // Summary format: "ERROR tests/test_foo.py - ImportError: ..."
                let parts: Vec<&str> = first_line.split(" - ").collect();
                if let Some(test_path) = parts.first() {
                    let test_name = test_path.trim_start_matches("ERROR ");
                    result.push_str(&format!("{}. [ERROR] {}\n", i + 1, test_name));
                }
                if parts.len() > 1 {
                    result.push_str(&format!("     {}\n", truncate(parts[1], 100)));
                }
                continue;
            }
        }

        // Show relevant error lines (assertions, errors, file locations)
        let mut relevant_lines = 0;
        for line in &lines[1..] {
            let line_lower = line.to_lowercase();
            let is_relevant = line.trim().starts_with('>')
                || line.trim().starts_with('E')
                || line_lower.contains("assert")
                || line_lower.contains("error")
                || line.contains(".py:");

            if is_relevant && relevant_lines < 3 {
                result.push_str(&format!("     {}\n", truncate(line, 100)));
                relevant_lines += 1;
            }
        }

        if i < failures.len() - 1 {
            result.push('\n');
        }
    }

    if failures.len() > 5 {
        result.push_str(&format!("\n... +{} more failures\n", failures.len() - 5));
    }

    result.trim().to_string()
}

fn parse_summary_line(summary: &str) -> (usize, usize, usize, usize) {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut errors = 0;

    // Parse lines like "=== 4 passed, 1 failed, 2 errors in 0.50s ==="
    let parts: Vec<&str> = summary.split(',').collect();

    for part in parts {
        let words: Vec<&str> = part.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                if word.contains("passed") {
                    if let Ok(n) = words[i - 1].parse::<usize>() {
                        passed = n;
                    }
                } else if word.contains("failed") {
                    if let Ok(n) = words[i - 1].parse::<usize>() {
                        failed = n;
                    }
                } else if word.contains("skipped") {
                    if let Ok(n) = words[i - 1].parse::<usize>() {
                        skipped = n;
                    }
                // "error"/"errors" — collection/import/fixture errors. Must be
                // counted so the success branch can be gated on errors == 0.
                } else if word.contains("error") {
                    if let Ok(n) = words[i - 1].parse::<usize>() {
                        errors = n;
                    }
                }
            }
        }
    }

    (passed, failed, skipped, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_pytest_all_pass() {
        let output = r#"=== test session starts ===
platform darwin -- Python 3.11.0
collected 5 items

tests/test_foo.py .....                                            [100%]

=== 5 passed in 0.50s ==="#;

        let result = filter_pytest_output(output, 0);
        assert!(result.contains("Pytest"));
        assert!(result.contains("5 passed"));
    }

    #[test]
    fn test_filter_pytest_with_failures() {
        let output = r#"=== test session starts ===
collected 5 items

tests/test_foo.py ..F..                                            [100%]

=== FAILURES ===
___ test_something ___

    def test_something():
>       assert False
E       assert False

tests/test_foo.py:10: AssertionError

=== short test summary info ===
FAILED tests/test_foo.py::test_something - assert False
=== 4 passed, 1 failed in 0.50s ==="#;

        let result = filter_pytest_output(output, 1);
        assert!(result.contains("4 passed, 1 failed"));
        assert!(result.contains("test_something"));
        assert!(result.contains("assert False"));
    }

    /// G6 #100: pytest colourises output on a TTY. ANSI escapes
    /// wrapping the `=== ... ===` section markers and the summary line
    /// must be stripped before the state machine runs, or failures are
    /// silently hidden.
    #[test]
    fn test_filter_pytest_ansi_wrapped_failures_still_detected() {
        // `\x1b[31m` (red) / `\x1b[0m` (reset) wrapping the markers.
        let output = "=== test session starts ===\n\
collected 5 items\n\n\
tests/test_foo.py ..F..\n\n\
\x1b[31m=== FAILURES ===\x1b[0m\n\
___ test_something ___\n\
\x1b[31mE       assert False\x1b[0m\n\
=== short test summary info ===\n\
\x1b[31mFAILED tests/test_foo.py::test_something - assert False\x1b[0m\n\
\x1b[31m=== 4 passed, 1 failed in 0.50s ===\x1b[0m";

        let result = filter_pytest_output(output, 1);
        assert!(
            result.contains("4 passed, 1 failed"),
            "ANSI-wrapped summary must still be detected, got: {result:?}"
        );
        assert!(
            result.contains("test_something"),
            "ANSI-wrapped failure must still surface, got: {result:?}"
        );
        assert!(
            !result.contains('\x1b'),
            "no raw ANSI escapes should survive into the filtered output"
        );
    }

    #[test]
    fn test_filter_pytest_multiple_failures() {
        let output = r#"=== test session starts ===
collected 3 items

tests/test_foo.py FFF                                              [100%]

=== FAILURES ===
___ test_one ___
E   AssertionError: expected 5

___ test_two ___
E   ValueError: invalid value

=== short test summary info ===
FAILED tests/test_foo.py::test_one - AssertionError: expected 5
FAILED tests/test_foo.py::test_two - ValueError: invalid value
FAILED tests/test_foo.py::test_three - KeyError
=== 3 failed in 0.20s ==="#;

        let result = filter_pytest_output(output, 1);
        assert!(result.contains("3 failed"));
        assert!(result.contains("test_one"));
        assert!(result.contains("test_two"));
        assert!(result.contains("expected 5"));
    }

    #[test]
    fn test_filter_pytest_no_tests() {
        let output = r#"=== test session starts ===
collected 0 items

=== no tests ran in 0.00s ==="#;

        // exit 0: genuinely empty/no-test run — keep the "No tests collected" message.
        let result = filter_pytest_output(output, 0);
        assert!(result.contains("No tests collected"));
    }

    #[test]
    fn test_parse_summary_line() {
        assert_eq!(parse_summary_line("=== 5 passed in 0.50s ==="), (5, 0, 0, 0));
        assert_eq!(
            parse_summary_line("=== 4 passed, 1 failed in 0.50s ==="),
            (4, 1, 0, 0)
        );
        assert_eq!(
            parse_summary_line("=== 3 passed, 1 failed, 2 skipped in 1.0s ==="),
            (3, 1, 2, 0)
        );
        // error(s) count is now parsed (was silently dropped — the lying-success bug).
        // (passed, failed, skipped, errors)
        assert_eq!(
            parse_summary_line("=== 5 passed, 2 errors in 1.23s ==="),
            (5, 0, 0, 2)
        );
    }

    #[test]
    fn test_filter_pytest_quiet_mode_failures() {
        // In -q mode, the final summary line has NO === wrapper
        // This was causing "No tests collected" to be reported incorrectly
        let output = r#"=== test session starts ===
platform linux -- Python 3.12.11, pytest-8.1.0
collected 1705 items

.......F.......

=== FAILURES ===
___ test_something ___

E   AssertionError: expected True

=== short test summary info ===
FAILED tests/test_foo.py::test_something - AssertionError
5 failed, 1698 passed, 2 skipped in 108.89s"#;

        let result = filter_pytest_output(output, 1);
        assert!(
            !result.contains("No tests collected"),
            "Should not report 'No tests collected' when tests ran. Got: {}",
            result
        );
        assert!(
            result.contains("1698") || result.contains("5 failed"),
            "Should show actual test counts. Got: {}",
            result
        );
    }

    #[test]
    fn test_filter_pytest_only_skipped() {
        // If only skipped tests, should NOT say "No tests collected"
        let output = r#"=== test session starts ===
collected 3 items

=== 3 skipped in 0.10s ==="#;

        let result = filter_pytest_output(output, 0);
        assert!(
            !result.contains("No tests collected"),
            "Should not say 'No tests collected' when tests were skipped. Got: {}",
            result
        );
    }

    /// Regression (lying-success): `5 passed, 2 errors` must NOT be summarised
    /// as a clean "Pytest: 5 passed", and the error tracebacks must surface.
    #[test]
    fn test_filter_pytest_passed_with_collection_errors() {
        let output = r#"=== test session starts ===
collected 5 items / 1 error

tests/test_foo.py .....                                            [100%]

=== ERRORS ===
___ ERROR collecting tests/test_bad.py ___
ImportError: cannot import name 'missing' from 'app'

=== short test summary info ===
ERROR tests/test_bad.py - ImportError: cannot import name 'missing'
=== 5 passed, 2 errors in 1.23s ==="#;

        let result = filter_pytest_output(output, 1);
        assert!(
            !result.contains("Pytest: 5 passed\n") && result != "Pytest: 5 passed",
            "Must NOT report clean success when there are errors. Got: {}",
            result
        );
        assert!(
            result.contains("2 errors"),
            "Error count must be surfaced. Got: {}",
            result
        );
        assert!(
            result.contains("ImportError") || result.contains("test_bad"),
            "Real error token must surface. Got: {}",
            result
        );
    }

    /// Regression: pure-error run (0 tests, only collection errors) must surface
    /// the errors, never claim "No tests collected".
    #[test]
    fn test_filter_pytest_pure_errors_not_no_tests() {
        let output = r#"=== test session starts ===
collected 0 items / 3 errors

=== ERRORS ===
___ ERROR collecting tests/test_a.py ___
ModuleNotFoundError: No module named 'app'

=== short test summary info ===
ERROR tests/test_a.py - ModuleNotFoundError: No module named 'app'
=== 3 errors in 0.42s ==="#;

        let result = filter_pytest_output(output, 1);
        assert!(
            !result.contains("No tests collected"),
            "Pure-error run must not report 'No tests collected'. Got: {}",
            result
        );
        assert!(
            result.contains("3 errors"),
            "Error count must be surfaced. Got: {}",
            result
        );
        assert!(
            result.contains("ModuleNotFoundError") || result.contains("test_a"),
            "Real error token must surface. Got: {}",
            result
        );
    }

    /// Regression: a crashed pytest with a non-zero exit and no parseable
    /// summary must surface the raw error, not "No tests collected".
    #[test]
    fn test_filter_pytest_crash_surfaces_raw() {
        let output = "INTERNALERROR> Traceback (most recent call last):\n\
INTERNALERROR>   File \"conftest.py\", line 3, in <module>\n\
INTERNALERROR> RuntimeError: boom during collection";

        let result = filter_pytest_output(output, 2);
        assert!(
            !result.contains("No tests collected"),
            "Crash must not report 'No tests collected'. Got: {}",
            result
        );
        assert!(
            result.contains("INTERNALERROR") || result.contains("RuntimeError"),
            "Real error must surface. Got: {}",
            result
        );
    }
}
