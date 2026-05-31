//! Runs a command and produces a heuristic summary of its output.

use crate::core::stream::exec_capture;
use crate::core::tracking;
use crate::core::output_summary::{summarize_command_output, CommandOutputSummaryOptions};
use anyhow::{Context, Result};
use std::process::Command;

// See cmds/rust/runner.rs: argv mode rejects shell metacharacters so
// agent-rewritten input cannot smuggle pipes/redirects/chains into the child,
// and refuses to spawn a known shell binary so an agent cannot trivially
// reintroduce sh -c by emitting `sh -c '<payload>'` as the whole argv.
const SHELL_METACHARS: &[char] = &['|', ';', '&', '<', '>', '`', '$', '\n'];
const SHELL_BINARIES: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh", "ash",
    "sh.exe", "bash.exe", "zsh.exe", "dash.exe", "ksh.exe", "fish.exe",
    "tcsh.exe", "csh.exe", "ash.exe",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "busybox", "busybox.exe", "toybox",
    "env", "nice", "nohup", "time", "timeout", "gtimeout",
    "ionice", "chroot", "setpriv", "unshare", "taskset", "stdbuf",
    "script", "xargs", "watch", "sudo", "doas",
    "su", "runuser", "pkexec",
];

fn is_shell_binary(bin: &str) -> bool {
    let basename = std::path::Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin);
    SHELL_BINARIES.iter().any(|s| s.eq_ignore_ascii_case(basename))
}

fn build_command(command: &str, use_shell: bool) -> Result<Command> {
    if use_shell {
        let cmd = if cfg!(target_os = "windows") {
            let mut c = Command::new("cmd");
            c.args(["/C", command]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", command]);
            c
        };
        return Ok(cmd);
    }
    if let Some(meta) = command.chars().find(|c| SHELL_METACHARS.contains(c)) {
        anyhow::bail!(
            "command contains shell metacharacter '{}'; pass --shell to opt into sh -c semantics",
            meta
        );
    }
    let tokens = shlex::split(command)
        .ok_or_else(|| anyhow::anyhow!("command has unbalanced quotes"))?;
    let (bin, rest) = tokens
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("command is empty"))?;
    if is_shell_binary(bin) {
        anyhow::bail!(
            "refusing to spawn shell binary '{}' in argv mode; pass --shell if you need sh -c semantics",
            bin
        );
    }
    let mut c = Command::new(bin);
    c.args(rest);
    Ok(c)
}

/// Run a command and provide a heuristic summary
pub fn run(command: &str, use_shell: bool, verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Running and summarizing: {}", command);
    }

    let mut cmd = build_command(command, use_shell)?;
    let result = exec_capture(&mut cmd).context("Failed to execute command")?;

    let raw = format!("{}\n{}", result.stdout, result.stderr);

    // If the capture cap fired, a synthesised summary built from a prefix
    // of the real output would silently mislead the caller (wrong test /
    // error counts, partial JSON structure, etc). Prepend an explicit
    // truncation marker so the summary cannot be mistaken for complete data.
    let truncation_note = if result.truncated_stdout || result.truncated_stderr {
        Some(format!(
            "[!] OUTPUT TRUNCATED — summary built from a {} MiB prefix only; rerun with `contextcrawler proxy` for raw output.\n",
            crate::core::stream::DEFAULT_CAPTURE_STREAM_MAX / (1024 * 1024)
        ))
    } else {
        None
    };

    let summary = summarize_command_output(
        &raw,
        CommandOutputSummaryOptions::new(command, result.success()),
    );
    if let Some(note) = &truncation_note {
        println!("{}{}", note, summary);
    } else {
        println!("{}", summary);
    }
    timer.track(command, "contextcrawler summary", &raw, &summary);
    Ok(result.exit_code)
}

