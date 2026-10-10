//! Shared command execution skeleton for filter modules.

use anyhow::{Context, Result};
use std::process::Command;

use crate::core::stream::{self, FilterMode, StdinMode, StreamFilter};
use crate::core::tracking;

/// Write the payload `parts` in order, then flush.
///
/// Split out from [`emit_stdout`] so the broken-pipe / write-error handling
/// can be exercised against an in-memory or deliberately failing writer.
///
/// Returns `Ok(true)` once everything is written, `Ok(false)` when the reader
/// closed the pipe (`BrokenPipe` — the normal end of a piped stream), and
/// `Err` for any other failure (EAGAIN, ENOSPC, EDQUOT, ...).
fn write_payload<W: std::io::Write>(writer: &mut W, parts: &[&str]) -> std::io::Result<bool> {
    for part in parts {
        match writer.write_all(part.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    match writer.flush() {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(e),
    }
}

/// Emit the final payload to stdout, without panicking.
///
/// The std `print!`/`println!` macros panic if the write fails. We write
/// directly so a broken pipe is reported (`Ok(false)` — the caller exits 0)
/// and any other write error is surfaced (`Err`) instead of aborting with a
/// backtrace.
fn emit_stdout(parts: &[&str]) -> Result<bool> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_payload(&mut handle, parts).context("failed to write output to stdout")
}

/// Best-effort write of captured stderr to our stderr.
///
/// Mirrors [`emit_stdout`] without the error channel: this is supplementary
/// output for a run whose exit code is already known, so a write failure is
/// ignored rather than masking the result.
fn write_stderr(text: &str) {
    use std::io::Write;
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_all(text.as_bytes());
    let _ = handle.flush();
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

/// Pick the text to emit for a capture filter.
///
/// Normally the [`no_bloat`] guard decides (fall back to `baseline` when the
/// filtered form is not strictly smaller). `keep_filtered` opts out: used when
/// the tool injected a machine-readable format the user did not request, so the
/// filter's summary is more useful even when it is marginally longer.
fn select_emitted<'a>(baseline: &'a str, filtered: &'a str, keep_filtered: bool) -> &'a str {
    if keep_filtered {
        filtered
    } else {
        no_bloat(baseline, filtered)
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
    /// Keep the filtered form even when the no-bloat guard would fall back to
    /// the baseline because the filtered text is not strictly shorter.
    ///
    /// Set only when the tool *injected* a machine-readable format the user
    /// did not request (e.g. ruff's `--output-format=json`): the raw injected
    /// payload (`[]`) carries less information than the filter's summary
    /// ("Ruff: No issues found"), so the summary wins despite being longer.
    /// When the user asked for that format themselves this stays unset and the
    /// raw output is preserved by the guard.
    pub keep_filtered: bool,
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

    /// Keep the filtered output even when it is not smaller than the baseline.
    /// See [`RunOptions::keep_filtered`].
    pub fn keep_filtered(mut self) -> Self {
        self.keep_filtered = true;
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
        // This path already forwards stderr, so the success-path forwarding
        // below must not fire in addition to it (it returns early).
        let stdout_result = if result.raw_stdout.trim().is_empty() {
            Ok(true)
        } else {
            emit_stdout(&[result.raw_stdout.as_str()])
        };
        if !result.raw_stderr.trim().is_empty() {
            write_stderr(&result.raw_stderr);
        }
        timer.track(
            cmd_label,
            &format!("contextcrawler {}", cmd_label),
            raw,
            raw,
        );
        return match stdout_result {
            Ok(true) => Ok(exit_code),
            // Reader closed the pipe: a clean end of output, not a failure.
            Ok(false) => Ok(0),
            Err(e) => Err(e),
        };
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

    // No-bloat guard (issue #95): if the filtered output is the same size or
    // larger than the raw it was tracked against, the filter is costing more
    // than it saves — emit the raw output instead so print and track agree and
    // savings never go negative. `keep_filtered` (set when the tool injected a
    // machine-readable format itself) overrides the guard so the more useful
    // summary survives even when it is longer (e.g. ruff's injected JSON emits
    // `[]` where `Ruff: No issues found` is clearer).
    let emitted = select_emitted(raw_for_tracking, &filtered, opts.keep_filtered);

    // A stdout-only filter never sees stderr, so a child that wrote nothing to
    // stdout but did write warnings/deprecations to stderr would otherwise lose
    // them. On a successful run, forward captured stderr when stdout is empty.
    // The failure path above already forwarded stderr and returned early, so
    // this cannot double-print it.
    let forward_stderr = opts.filter_stdout_only
        && exit_code == 0
        && raw_stdout.trim().is_empty()
        && !result.raw_stderr.trim().is_empty();

    let hint = opts
        .tee_label
        .and_then(|label| crate::core::tee::tee_and_hint(raw, label, exit_code));

    // Assemble the payload (mirrors the previous print!/println! shapes:
    // `filtered\nhint\n`, `filtered\n`, or `filtered`) and write it through the
    // non-panicking helper. A tee label takes precedence over
    // `no_trailing_newline`, exactly as `print_with_hint` did.
    let mut parts: [&str; 4] = [""; 4];
    let part_count = if opts.tee_label.is_some() {
        if let Some(hint) = hint.as_deref() {
            parts[0] = emitted;
            parts[1] = "\n";
            parts[2] = hint;
            parts[3] = "\n";
            4
        } else {
            parts[0] = emitted;
            parts[1] = "\n";
            2
        }
    } else if opts.no_trailing_newline {
        parts[0] = emitted;
        1
    } else {
        parts[0] = emitted;
        parts[1] = "\n";
        2
    };

    let write_result = emit_stdout(&parts[..part_count]);

    if forward_stderr {
        write_stderr(&result.raw_stderr);
    }

    timer.track(
        cmd_label,
        &format!("contextcrawler {}", cmd_label),
        raw_for_tracking,
        emitted,
    );

    match write_result {
        Ok(true) => Ok(exit_code),
        // BrokenPipe: the reader went away (e.g. `| head`); exit cleanly.
        Ok(false) => Ok(0),
        // EAGAIN / ENOSPC / EDQUOT / anything else: surface the real error.
        Err(e) => Err(e),
    }
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
            let result = stream::run_streaming(&mut cmd, stdin_mode, FilterMode::Streaming(filter))
                .with_context(|| format!("Failed to run {}", tool_name))?;

            if let Some(label) = opts.tee_label {
                if let Some(hint) =
                    crate::core::tee::tee_and_hint(&result.raw, label, result.exit_code)
                {
                    // Non-panicking write; a broken pipe here is not fatal.
                    let _ = emit_stdout(&[hint.as_str(), "\n"]);
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

            timer.track_passthrough(
                &cmd_label,
                &format!("contextcrawler {} (passthrough)", cmd_label),
            );
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
        assert!(tracking::estimate_tokens(filtered) < tracking::estimate_tokens(baseline));
        assert_eq!(no_bloat(baseline, filtered), filtered);
    }

    // --- keep_filtered override (injected machine-readable format) ---

    #[test]
    fn keep_filtered_overrides_no_bloat_for_injected_format() {
        // Clean ruff run with injected `--output-format=json`: the raw stdout
        // is `[]`, which is shorter than the filter's summary message.
        let raw = "[]";
        let summary = "Ruff: No issues found";
        // The guard alone would keep the (shorter) raw JSON…
        assert_eq!(no_bloat(raw, summary), raw);
        // …but the injected-format override keeps the useful summary even
        // though it is longer.
        assert_eq!(select_emitted(raw, summary, true), summary);
        // Without the override the guard still governs.
        assert_eq!(select_emitted(raw, summary, false), raw);
    }

    #[test]
    fn select_emitted_falls_back_to_shorter_filtered_form() {
        // No override: a genuinely shorter filtered form is kept.
        let raw = "line one\nline two\nline three\n";
        let filtered = "3 lines";
        assert_eq!(select_emitted(raw, filtered, false), filtered);
    }

    // --- stdout payload emission must not panic ---

    struct FailingWriter(std::io::ErrorKind);

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(self.0, "boom"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_payload_writes_every_part() {
        let mut out: Vec<u8> = Vec::new();
        assert!(write_payload(&mut out, &["a", "\n", "b", "\n"]).unwrap());
        assert_eq!(out, b"a\nb\n");
    }

    #[test]
    fn write_payload_maps_broken_pipe_to_ok_false() {
        // A downstream reader quitting (`| head`) closes the pipe: this is a
        // clean end of output the caller turns into exit 0, never a panic.
        let mut w = FailingWriter(std::io::ErrorKind::BrokenPipe);
        assert!(!write_payload(&mut w, &["x"]).unwrap());
    }

    #[test]
    fn write_payload_surfaces_other_write_errors() {
        // EAGAIN-like and generic failures must be returned, not swallowed and
        // not escalated to a panic.
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::Other] {
            let mut w = FailingWriter(kind);
            assert!(
                write_payload(&mut w, &["x"]).is_err(),
                "{kind:?} must surface as an error"
            );
        }
    }
}
