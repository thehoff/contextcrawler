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
        }

        // Capture the pytest summary line: it may be `===`-wrapped (non-quiet)
        // or bare (quiet mode and `--collect-only`). A test can print a
        // lookalike ("1 passed in 0.01s") mid-run, so keep the LAST matching
        // line — the genuine summary is always emitted at the end.
        //
        // `FAILED`/`ERROR` short-summary entries and traceback detail lines
        // (`> ...`, `E   ...`) are never the run summary, even if they happen
        // to end in a duration-like token.
        let is_detail = trimmed.starts_with("FAILED")
            || trimmed.starts_with("ERROR")
            || trimmed.starts_with('>')
            || trimmed.starts_with("E ");
        if !is_detail && looks_like_summary_line(trimmed) {
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
    let duration = parse_duration(summary);

    // Success is gated on BOTH failed == 0 AND errors == 0. pytest reports
    // collection/import/fixture failures as `errors` (e.g. "5 passed, 2 errors"),
    // which must never be summarised as a clean "Pytest: N passed".
    if failed == 0 && errors == 0 && passed > 0 {
        return match &duration {
            Some(d) => format!("Pytest: {} passed in {}", passed, d),
            None => format!("Pytest: {} passed", passed),
        };
    }

    // `--collect-only` prints no pass/fail counts — only "<N> tests collected
    // in <t>s". Surface the collected count instead of misreporting an empty
    // result as "No tests collected".
    if passed == 0 && failed == 0 && skipped == 0 && errors == 0 {
        if let Some(collected) = parse_collected_line(summary) {
            return match &duration {
                Some(d) => format!("Pytest: {} tests collected in {}", collected, d),
                None => format!("Pytest: {} tests collected", collected),
            };
        }
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
    if let Some(d) = &duration {
        result.push_str(&format!(" in {}", d));
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

/// Does this line look like pytest's terminal summary line — a run/collection
/// count followed by a duration (`... in <secs>s`)?
///
/// Covers the `===`-wrapped form (`=== 4 passed, 1 failed in 0.50s ===`), the
/// bare quiet form (`5 failed, 1698 passed in 108.89s`), the pure-error form
/// (`3 errors in 1.23s`), the empty-run form (`no tests ran in 0.00s`) and
/// `--collect-only` (`3 tests collected in 0.02s`).
fn looks_like_summary_line(line: &str) -> bool {
    if parse_duration(line).is_none() {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    lower.contains("passed")
        || lower.contains("failed")
        || lower.contains("skipped")
        || lower.contains("error")
        || lower.contains("collected")
        || lower.contains("no tests ran")
}

/// Extract the duration token from a pytest summary line, e.g. `0.02s` from
/// `=== 1 passed in 0.02s ===`. Returns `None` when the line has no
/// conventional `in <seconds>s` tail.
fn parse_duration(line: &str) -> Option<String> {
    let idx = line.rfind(" in ")?;
    let token = line[idx + 4..].trim().split_whitespace().next()?;
    let seconds = token.strip_suffix('s')?;
    if seconds.starts_with(|c: char| c.is_ascii_digit()) {
        Some(token.to_string())
    } else {
        None
    }
}

/// Extract the collected-test count from a `--collect-only` summary line
/// (`3 tests collected in 0.02s`) — the count precedes the `tests` noun.
fn parse_collected_line(summary: &str) -> Option<usize> {
    let words: Vec<&str> = summary.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if word.trim_matches('=') == "collected" {
            return words[..i]
                .iter()
                .rev()
                .find_map(|w| w.parse::<usize>().ok());
        }
    }
    None
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
        assert_eq!(
            parse_summary_line("=== 5 passed in 0.50s ==="),
            (5, 0, 0, 0)
        );
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

    /// Regression (upstream rtk#4426): pytest's quiet summary
    /// `1 passed, 1 error in 0.02s` — the line this binary asks for via `-q` —
    /// must not collapse to a clean pass. Singular `error`, no `===` wrapper.
    #[test]
    fn test_filter_pytest_quiet_fixture_error() {
        let output = r#".E                                                                   [100%]
=== ERRORS ===
___ ERROR at setup of test_e ___
E   RuntimeError: fixture

=== short test summary info ===
ERROR test_e.py::test_e - RuntimeError: fixture
1 passed, 1 error in 0.02s"#;

        let result = filter_pytest_output(output, 1);
        assert!(
            result != "Pytest: 1 passed" && !result.contains("Pytest: 1 passed\n"),
            "fixture error must not read as a clean pass. Got: {result}"
        );
        assert!(
            result.contains("1 error"),
            "singular error count must be kept. Got: {result}"
        );
        assert!(
            result.contains("test_e") || result.contains("RuntimeError"),
            "the fixture error itself must surface. Got: {result}"
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

    /// The success summary must carry pytest's duration, e.g. `1 passed in 0.02s`.
    #[test]
    fn test_filter_pytest_summary_includes_duration() {
        let output = "=== test session starts ===\n\
collected 1 item\n\n\
tests/test_foo.py .                                                [100%]\n\n\
=== 1 passed in 0.02s ===";

        let result = filter_pytest_output(output, 0);
        assert_eq!(result, "Pytest: 1 passed in 0.02s");
    }

    /// Duration must also survive on the bare quiet summary form.
    #[test]
    fn test_filter_pytest_quiet_summary_includes_duration() {
        let output = "1 passed in 0.02s";
        let result = filter_pytest_output(output, 0);
        assert_eq!(result, "Pytest: 1 passed in 0.02s");
    }

    /// `--collect-only` (which rtk runs with `-q`) ends with
    /// `<N> tests collected in <t>s` and no pass/fail counts. That must report
    /// the collected count, never "No tests collected".
    #[test]
    fn test_filter_pytest_collect_only_reports_collected() {
        let output = "tests/test_foo.py::test_one\n\
tests/test_foo.py::test_two\n\
tests/test_foo.py::test_three\n\n\
3 tests collected in 0.01s";

        let result = filter_pytest_output(output, 0);
        assert!(
            !result.contains("No tests collected"),
            "--collect-only must not report 'No tests collected'. Got: {result}"
        );
        assert_eq!(result, "Pytest: 3 tests collected in 0.01s");
    }

    /// Same, but with the non-quiet `===`-wrapped collect-only summary line.
    #[test]
    fn test_filter_pytest_collect_only_wrapped() {
        let output = "=== test session starts ===\n\
collected 2 items\n\n\
<Module test_foo.py>\n\
  <Function test_one>\n\
  <Function test_two>\n\n\
=== 2 tests collected in 0.03s ===";

        let result = filter_pytest_output(output, 0);
        assert!(
            !result.contains("No tests collected"),
            "collect-only must report the collected count. Got: {result}"
        );
        assert_eq!(result, "Pytest: 2 tests collected in 0.03s");
    }

    /// A test that prints a summary lookalike (`1 passed in 0.01s`) mid-run
    /// must not shadow the genuine, final summary line.
    #[test]
    fn test_filter_pytest_quiet_last_summary_wins() {
        let output = "=== test session starts ===\n\
collected 2 items\n\n\
tests/test_foo.py ..                                               [100%]\n\
1 passed in 0.01s\n\
=== 2 passed in 0.05s ===";

        let result = filter_pytest_output(output, 0);
        assert_eq!(
            result, "Pytest: 2 passed in 0.05s",
            "the last matching summary line must win. Got: {result}"
        );
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(
            parse_duration("=== 5 passed in 0.50s ==="),
            Some("0.50s".to_string())
        );
        assert_eq!(
            parse_duration("5 failed, 1698 passed, 2 skipped in 108.89s"),
            Some("108.89s".to_string())
        );
        assert_eq!(
            parse_duration("=== 3 errors in 1.23s ==="),
            Some("1.23s".to_string())
        );
        assert_eq!(
            parse_duration("no tests ran in 0.00s"),
            Some("0.00s".to_string())
        );
        assert_eq!(parse_duration("no duration here"), None);
    }

    #[test]
    fn test_parse_collected_line() {
        assert_eq!(parse_collected_line("3 tests collected in 0.02s"), Some(3));
        assert_eq!(
            parse_collected_line("=== 12 tests collected in 0.02s ==="),
            Some(12)
        );
        assert_eq!(parse_collected_line("1 passed in 0.02s"), None);
        assert_eq!(parse_collected_line(""), None);
    }
}
