//! Shared command execution skeleton for filter modules.

use anyhow::{Context, Result};
use std::process::Command;

use crate::core::stream::{self, FilterMode, StdinMode, StreamFilter};
use crate::core::tracking;

pub fn print_with_hint(filtered: &str, raw: &str, tee_label: &str, exit_code: i32) {
    if let Some(hint) = crate::core::tee::tee_and_hint(raw, tee_label, exit_code) {
        println!("{}\n{}", filtered, hint);
    } else {
        println!("{}", filtered);
    }
}

/// No-bloat guard: a filter must never cost more than it saves.
///
/// Given the `baseline` a filter is tracked against and the `filtered`
/// output the filter produced, return whichever costs fewer *tokens*.
/// When the filtered form is the same size or larger than the baseline,
/// the wrapper has added framing/summary without saving anything — in that
/// case the raw baseline is returned so the caller emits *and* tracks it.
///
/// The comparison uses [`tracking::estimate_tokens`], the same unit
/// `TimedExecution::track` records savings in (#111 G3). Comparing by byte
/// length here while tracking measured tokens could let the emitted text and
/// the recorded savings disagree on direction — this keeps them consistent.
///
/// Callers MUST emit exactly the returned string and pass that same value
/// to `timer.track(..)` as the output, so what the user sees and what the
/// tracking DB records always agree. See issue #95.
///
/// Note `baseline` is whatever the caller chose to track against — usually
/// raw command output, but for filters that deliberately measure against a
/// synthetic baseline (e.g. `git add` tracks against `git diff --cached
/// --stat`, issue #89) it is that synthetic string. The guard compares the
/// filtered output against that same baseline, so an intentional compact
/// summary that costs fewer tokens than its synthetic baseline survives
/// untouched.
pub fn no_bloat<'a>(baseline: &'a str, filtered: &'a str) -> &'a str {
    if tracking::estimate_tokens(filtered) >= tracking::estimate_tokens(baseline) {
        baseline
    } else {
        filtered
    }
}

#[derive(Default)]
pub struct RunOptions<'a> {
    pub tee_label: Option<&'a str>,
    pub filter_stdout_only: bool,
    pub skip_filter_on_failure: bool,
    pub no_trailing_newline: bool,
    /// Forward contextcrawler's own stdin to the child process. Needed for
    /// commands that can read from a pipe (e.g. `cat file | contextcrawler wc`);
    /// without it the child gets an empty stdin and reports zero.
    pub inherit_stdin: bool,
}

impl<'a> RunOptions<'a> {
    pub fn with_tee(label: &'a str) -> Self {
        Self {
            tee_label: Some(label),
            ..Default::default()
        }
    }

    pub fn stdout_only() -> Self {
        Self {
            filter_stdout_only: true,
            ..Default::default()
        }
    }

    pub fn tee(mut self, label: &'a str) -> Self {
        self.tee_label = Some(label);
        self
    }

    pub fn early_exit_on_failure(mut self) -> Self {
        self.skip_filter_on_failure = true;
        self
    }

    pub fn no_trailing_newline(mut self) -> Self {
        self.no_trailing_newline = true;
        self
    }

    pub fn inherit_stdin(mut self) -> Self {
        self.inherit_stdin = true;
        self
    }
}

pub type CaptureFilter<'a> = Box<dyn Fn(&str) -> String + 'a>;
pub type ExitAwareCaptureFilter<'a> = Box<dyn Fn(&str, i32) -> String + 'a>;

pub enum RunMode<'a> {
    Filtered(CaptureFilter<'a>),
    /// Like `Filtered`, but the filter is also handed the child's exit code so
    /// it can avoid reporting success on a non-zero exit (issue: upstream
    /// f69ad6e — a failed `go build` with no recognised error line was printing
    /// "Go build: Success" while the real exit code was non-zero).
    FilteredWithExit(ExitAwareCaptureFilter<'a>),
    Streamed(Box<dyn StreamFilter + 'a>),
    Passthrough,
}

/// Shared capture-filter execution path used by both `Filtered` and
/// `FilteredWithExit`. The filter receives the captured text and the child's
/// exit code; exit-blind filters simply ignore the second argument. The
/// no-bloat guard (issue #95) and exit-code propagation (CTXCRL rule #5) are
/// applied identically for both modes.
fn run_captured_filter<F>(
    mut cmd: Command,
    tool_name: &str,
    cmd_label: &str,
    filter_fn: F,
    opts: RunOptions<'_>,
    timer: tracking::TimedExecution,
) -> Result<i32>
where
    F: Fn(&str, i32) -> String,
{
    let stdin_mode = if opts.inherit_stdin {
        StdinMode::Inherit
    } else {
        StdinMode::Null
    };
    let result = stream::run_streaming(&mut cmd, stdin_mode, FilterMode::CaptureOnly)
        .with_context(|| format!("Failed to run {}", tool_name))?;

    let exit_code = result.exit_code;
    let raw = &result.raw;
    let raw_stdout = &result.raw_stdout;

    if opts.skip_filter_on_failure && exit_code != 0 {
        if !result.raw_stdout.trim().is_empty() {
            print!("{}", result.raw_stdout);
        }
        if !result.raw_stderr.trim().is_empty() {
            eprint!("{}", result.raw_stderr);
        }
        timer.track(cmd_label, &format!("contextcrawler {}", cmd_label), raw, raw);
        return Ok(exit_code);
    }

    let text_to_filter = if opts.filter_stdout_only {
        raw_stdout
    } else {
        raw
    };
    let filtered = filter_fn(text_to_filter, exit_code);

    let raw_for_tracking = if opts.filter_stdout_only {
        raw_stdout
    } else {
        raw
    };

    // No-bloat guard (issue #95): if the filtered output is the same
    // size or larger than the raw it was tracked against, the filter
    // is costing more than it saves — emit the raw output instead so
    // print and track agree and savings never go negative.
    let emitted = no_bloat(raw_for_tracking, &filtered);

    if let Some(label) = opts.tee_label {
        print_with_hint(emitted, raw, label, exit_code);
    } else if opts.no_trailing_newline {
        print!("{}", emitted);
    } else {
        println!("{}", emitted);
    }

    timer.track(
        cmd_label,
        &format!("contextcrawler {}", cmd_label),
        raw_for_tracking,
        emitted,
    );
    Ok(exit_code)
}

pub fn run(
    mut cmd: Command,
    tool_name: &str,
    args_display: &str,
    mode: RunMode<'_>,
    opts: RunOptions<'_>,
) -> Result<i32> {
    let timer = tracking::TimedExecution::start();
    let cmd_label = format!("{} {}", tool_name, args_display);

    match mode {
        RunMode::Filtered(filter_fn) => run_captured_filter(
            cmd,
            tool_name,
            &cmd_label,
            move |text, _exit_code| filter_fn(text),
            opts,
            timer,
        ),
        RunMode::FilteredWithExit(filter_fn) => run_captured_filter(
            cmd,
            tool_name,
            &cmd_label,
            move |text, exit_code| filter_fn(text, exit_code),
            opts,
            timer,
        ),
        RunMode::Streamed(filter) => {
            let stdin_mode = if opts.inherit_stdin {
                StdinMode::Inherit
            } else {
                StdinMode::Null
            };
            let result =
                stream::run_streaming(&mut cmd, stdin_mode, FilterMode::Streaming(filter))
                    .with_context(|| format!("Failed to run {}", tool_name))?;

            if let Some(label) = opts.tee_label {
                if let Some(hint) =
                    crate::core::tee::tee_and_hint(&result.raw, label, result.exit_code)
                {
                    println!("{}", hint);
                }
            }

            timer.track(
                &cmd_label,
                &format!("contextcrawler {}", cmd_label),
                &result.raw,
                &result.filtered,
            );
            Ok(result.exit_code)
        }
        RunMode::Passthrough => {
            let result =
                stream::run_streaming(&mut cmd, StdinMode::Inherit, FilterMode::Passthrough)
                    .with_context(|| format!("Failed to run {}", tool_name))?;

            timer.track_passthrough(&cmd_label, &format!("contextcrawler {} (passthrough)", cmd_label));
            Ok(result.exit_code)
        }
    }
}

pub fn run_filtered<F>(
    cmd: Command,
    tool_name: &str,
    args_display: &str,
    filter_fn: F,
    opts: RunOptions<'_>,
) -> Result<i32>
where
    F: Fn(&str) -> String,
{
    run(
        cmd,
        tool_name,
        args_display,
        RunMode::Filtered(Box::new(filter_fn)),
        opts,
    )
}

/// Like [`run_filtered`], but the filter additionally receives the child's
/// exit code. Use this when a filter's summary message must not contradict the
/// real exit status (e.g. a build filter that should never print "Success" on
/// a non-zero exit). Exit-code propagation is unchanged — the child's code is
/// still returned verbatim (CTXCRL rule #5).
pub fn run_filtered_with_exit<F>(
    cmd: Command,
    tool_name: &str,
    args_display: &str,
    filter_fn: F,
    opts: RunOptions<'_>,
) -> Result<i32>
where
    F: Fn(&str, i32) -> String,
{
    run(
        cmd,
        tool_name,
        args_display,
        RunMode::FilteredWithExit(Box::new(filter_fn)),
        opts,
    )
}

pub fn run_passthrough(tool: &str, args: &[std::ffi::OsString], verbose: u8) -> Result<i32> {
    if verbose > 0 {
        eprintln!("{} passthrough: {:?}", tool, args);
    }
    let mut cmd = crate::core::utils::resolved_command(tool);
    cmd.args(args);
    let args_str = tracking::args_display(args);
    run(
        cmd,
        tool,
        &args_str,
        RunMode::Passthrough,
        RunOptions::default(),
    )
}

/// Same as `run_passthrough`, but the caller supplies a pre-built
/// `Command`. Used by hardened wrappers (e.g. cargo, issue #34) that
/// need to pre-strip env vars before the spawn — `resolved_command(tool)`
/// alone doesn't suffice once any subprocess hardening is required.
pub fn run_passthrough_cmd(
    mut cmd: Command,
    tool: &str,
    args: &[std::ffi::OsString],
    verbose: u8,
) -> Result<i32> {
    if verbose > 0 {
        eprintln!("{} passthrough: {:?}", tool, args);
    }
    cmd.args(args);
    let args_str = tracking::args_display(args);
    run(
        cmd,
        tool,
        &args_str,
        RunMode::Passthrough,
        RunOptions::default(),
    )
}

pub fn run_streamed(
    cmd: Command,
    tool_name: &str,
    args_display: &str,
    filter: Box<dyn StreamFilter + '_>,
    opts: RunOptions<'_>,
) -> Result<i32> {
    run(
        cmd,
        tool_name,
        args_display,
        RunMode::Streamed(filter),
        opts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- no-bloat guard (issue #95) ---

    #[test]
    fn no_bloat_emits_raw_when_filter_inflates() {
        // A no-match grep: raw is empty, the "0 matches" convenience message
        // is pure overhead. The guard must pick the raw (empty) output.
        let raw = "";
        let filtered = "0 matches for 'needle'";
        assert_eq!(no_bloat(raw, filtered), raw);
    }

    #[test]
    fn no_bloat_emits_raw_when_equal_size() {
        // Equal byte length is still "no saving" — guard prefers raw so the
        // filter never costs anything and tracking shows 0%, not negative.
        let raw = "abcdef";
        let filtered = "uvwxyz";
        assert_eq!(no_bloat(raw, filtered), raw);
    }

    #[test]
    fn no_bloat_keeps_filtered_when_it_saves() {
        // A normal large-output filter (filtered << raw) is unaffected:
        // the compact form is returned untouched.
        let raw = "line one\nline two\nline three\nline four\nline five\n";
        let filtered = "5 lines";
        assert_eq!(no_bloat(raw, filtered), filtered);
        assert!(no_bloat(raw, filtered).len() < raw.len());
    }

    #[test]
    fn no_bloat_keeps_intentional_summary_against_synthetic_baseline() {
        // `git add` tracks the compact shortstat against a synthetic
        // `git diff --cached --stat` baseline (issue #89), NOT raw git-add
        // output (which is silent). The compact summary is shorter than that
        // multi-line baseline, so the guard leaves it intact — the
        // informational filter is not regressed.
        let synthetic_baseline = "\
 src/core/runner.rs   | 42 ++++++++++
 src/cmds/git/git.rs  | 17 +++++--
 src/cmds/system/grep_cmd.rs | 13 ++++-
 3 files changed, 64 insertions(+), 8 deletions(-)";
        let compact = "ok 3 files changed, 64 insertions(+), 8 deletions(-)";
        assert!(compact.len() < synthetic_baseline.len());
        assert_eq!(no_bloat(synthetic_baseline, compact), compact);
    }

    #[test]
    fn no_bloat_picks_lower_token_output_when_bytes_disagree() {
        // #111 G3: `no_bloat` must compare the same unit `track()` records
        // (estimated tokens), not raw bytes. Here `filtered` is fewer bytes
        // than `baseline` but the byte saving rounds away — both estimate to
        // the SAME token count. A byte comparison would (wrongly) claim the
        // filter saved something and emit `filtered`; the token comparison
        // sees no real saving and emits `baseline`, matching what tracking
        // would record (0 tokens saved).
        let baseline = "abcdefgh"; // 8 bytes  -> 2 tokens
        let filtered = "abcde"; //    5 bytes  -> 2 tokens
        // Bytes and tokens disagree on direction:
        assert!(filtered.len() < baseline.len(), "filtered is fewer bytes");
        assert_eq!(
            tracking::estimate_tokens(filtered),
            tracking::estimate_tokens(baseline),
            "but both estimate to the same token count"
        );
        // Byte-based comparison would have returned `filtered`; the
        // token-based guard returns `baseline` so emit and tracking agree.
        assert_eq!(no_bloat(baseline, filtered), baseline);
    }

    #[test]
    fn no_bloat_keeps_filtered_when_it_saves_tokens() {
        // Sanity: a genuine token saving still keeps the filtered output.
        let baseline = "this is a long noisy line of command output";
        let filtered = "3 lines";
        assert!(
            tracking::estimate_tokens(filtered) < tracking::estimate_tokens(baseline)
        );
        assert_eq!(no_bloat(baseline, filtered), filtered);
    }
}
