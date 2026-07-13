//! Matches shell commands against known CTXCRL rewrite rules to decide how to handle them.

use lazy_static::lazy_static;
use regex::{Regex, RegexSet};
use std::borrow::Cow;

use super::lexer::{extract_substitutions, split_on_operators, tokenize, TokenKind};
use super::rules::{IGNORED_EXACT, IGNORED_PREFIXES, RULES};

/// Result of classifying a command.
#[derive(Debug, PartialEq)]
pub enum Classification {
    Supported {
        ctxcrl_equivalent: &'static str,
        category: &'static str,
        estimated_savings_pct: f64,
        status: super::report::CtxcrlStatus,
    },
    Unsupported {
        base_command: String,
    },
    Ignored,
}

/// Average token counts per category for estimation when no output_len available.
pub fn category_avg_tokens(category: &str, subcmd: &str) -> usize {
    match category {
        "Git" => match subcmd {
            "log" | "diff" | "show" => 200,
            _ => 40,
        },
        "Cargo" => match subcmd {
            "test" => 500,
            _ => 150,
        },
        "Tests" => 800,
        "Files" => 100,
        "Build" => 300,
        "Infra" => 120,
        "Network" => 150,
        "GitHub" => 200,
        "GitLab" => 200,
        "PackageManager" => 150,
        _ => 150,
    }
}

lazy_static! {
    static ref REGEX_SET: RegexSet =
        RegexSet::new(RULES.iter().map(|r| r.pattern)).expect("invalid regex patterns");
    static ref COMPILED: Vec<Regex> = RULES
        .iter()
        .map(|r| Regex::new(r.pattern).expect("invalid regex"))
        .collect();
    static ref ENV_PREFIX: Regex = {
        let double_quoted = r#""(?:[^"\\]|\\.)*""#;
        let single_quoted = r#"'(?:[^'\\]|\\.)*'"#;
        let unquoted = r#"[^\s]*"#;
        let env_value = format!("(?:{}|{}|{})", double_quoted, single_quoted, unquoted);
        let env_assign = format!(r#"[A-Z_][A-Z0-9_]*={}"#, env_value);
        Regex::new(&format!(r#"^(?:sudo\s+|env\s+|{}\s+)+"#, env_assign)).unwrap()
    };
    // Git global options that appear before the subcommand: -C <path>, -c <key=val>,
    // --git-dir <dir>, --work-tree <dir>, and flag-only options (#163)
    // #84: support quoted values for -C/-c/--git-dir/--work-tree, e.g.
    // `git -c "core.editor=vim -w" merge` — `\S+` alone stops at the inner space.
    static ref GIT_GLOBAL_OPT: Regex =
        Regex::new(r#"^(?:(?:-C\s+(?:"[^"]+"|'[^']+'|\S+)|-c\s+(?:"[^"]+"|'[^']+'|\S+)|--git-dir(?:=(?:"[^"]+"|'[^']+'|\S+)|\s+(?:"[^"]+"|'[^']+'|\S+))|--work-tree(?:=(?:"[^"]+"|'[^']+'|\S+)|\s+(?:"[^"]+"|'[^']+'|\S+))|--no-pager|--no-optional-locks|--bare|--literal-pathspecs)\s+)+"#).unwrap();
    // rustup `+toolchain` selector after `cargo` (e.g. `cargo +nightly test`,
    // `cargo +stable build`). Stripped during `normalise_command` so the
    // classifier sees the bare `cargo <subcommand>` and the rule pattern matches.
    // The toolchain token is preserved in the rewrite path (`cmd_part_norm`)
    // so the executed command keeps its toolchain selector — mirrors how the
    // git `-C <dir>` global opt is stripped for classification but re-prepended
    // in the rewrite. Restricted to `+<word/.-/>` so it can never smuggle a
    // flag or shell metacharacter.
    static ref CARGO_TOOLCHAIN_OPT: Regex =
        Regex::new(r"^\+[A-Za-z0-9][A-Za-z0-9._-]*\s+").unwrap();
    // Issue #1362: each capture expects a SINGLE file argument (`\S+$`). Multi-file
    // invocations like `head -3 a b c` fail to match so the segment is passed through
    // to the native `head`/`tail` binary — which already handles multi-file with
    // `==> name <==` banners that `ctxcrl read --max-lines` cannot reproduce.
    static ref HEAD_N: Regex = Regex::new(r"^head\s+-(\d+)\s+(\S+)$").unwrap();
    static ref HEAD_N_SPACE: Regex = Regex::new(r"^head\s+-n\s+(\d+)\s+(\S+)$").unwrap();
    static ref HEAD_LINES: Regex = Regex::new(r"^head\s+--lines=(\d+)\s+(\S+)$").unwrap();
    static ref HEAD_LINES_SPACE: Regex = Regex::new(r"^head\s+--lines\s+(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_N: Regex = Regex::new(r"^tail\s+-(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_N_SPACE: Regex = Regex::new(r"^tail\s+-n\s+(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_LINES_EQ: Regex = Regex::new(r"^tail\s+--lines=(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_LINES_SPACE: Regex = Regex::new(r"^tail\s+--lines\s+(\d+)\s+(\S+)$").unwrap();
    // #195: shell-wrapper prefix. Matches `sh`/`bash`/`zsh` followed by a
    // combined `-c`/`-lc`/`-ic` etc. flag whose effect is "read the script
    // from the next argument", then an opening quote. The flag class is
    // restricted to letters that combine harmlessly with `-c` (`l` login,
    // `i` interactive, `e`/`x` debug). A flag we don't model (e.g.
    // `-o pipefail`, `-s`, separate `-l -c`) fails to match → no unwrap.
    // Capture 1 = the opening quote char so the inner span and matching
    // closing quote can be located by `unwrap_shell_wrapper`.
    static ref SHELL_WRAPPER_PREFIX: Regex =
        Regex::new(r#"^(?:sh|bash|zsh)\s+-[liex]*c\s+(['"])"#).unwrap();
    // #195: `sudo` carrying flags before the inner command. Bare `sudo ` (no
    // flags) is already handled by ENV_PREFIX; this catches `sudo -u user`,
    // `sudo -E`, `sudo -H -u user`, etc. so the inner command can be
    // classified/filtered while the spawned command KEEPS sudo (privileges
    // intact). Each alternative is one flag-with-its-argument or a value-less
    // flag; value-taking forms are listed FIRST so they win the leftmost match:
    //   `-u user` / `--user=user` / `--user user`  (and -g/-p/-C/-h/-r/-t/-U)
    //   `-E`, `-H`, `-k`, `-n`, `-b`, `-s`, `-i` ... value-less short flags
    // A flag we don't model ends the run → no strip → raw passthrough (safe).
    static ref SUDO_FLAGS_PREFIX: Regex = Regex::new(
        r#"^sudo\s+(?:(?:-[ugpChrtU]|--(?:user|group|prompt|close-from|host|role|type|other-user))(?:=\S+\s+|\s+\S+\s+)|-[EHknbsiABPS]+\s+|--(?:preserve-env|set-home|reset-timestamp|non-interactive|background|shell|login|askpass|preserve-groups)\s+)+"#
    ).unwrap();
}

const GOLANGCI_GLOBAL_OPT_WITH_VALUE: &[&str] = &[
    "-c",
    "--color",
    "--config",
    "--cpu-profile-path",
    "--mem-profile-path",
    "--trace-path",
];

#[derive(Debug, Clone, Copy)]
struct GolangciRunParts<'a> {
    global_segment: &'a str,
    run_segment: &'a str,
}

/// Classify a single (already-split) command.
pub fn classify_command(cmd: &str) -> Classification {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Classification::Ignored;
    }

    // #87: $VAR-prefixed commands are shell expansions, not classifiable commands.
    if trimmed.starts_with('$') {
        return Classification::Ignored;
    }

    // Check ignored
    for exact in IGNORED_EXACT {
        if trimmed == *exact {
            return Classification::Ignored;
        }
    }
    for prefix in IGNORED_PREFIXES {
        if trimmed.starts_with(prefix) {
            return Classification::Ignored;
        }
    }

    // Normalise: strip env prefixes (sudo, env VAR=val), absolute paths
    // (/usr/bin/grep -> grep, #485), and git/golangci global opts (#163, #83).
    let cmd_normalized = normalise_command(trimmed);
    let cmd_clean = cmd_normalized.trim();
    if cmd_clean.is_empty() {
        return Classification::Ignored;
    }

    // Exclude cat/head/tail with redirect operators — these are writes, not reads (#315)
    if cmd_clean.starts_with("cat ")
        || cmd_clean.starts_with("head ")
        || cmd_clean.starts_with("tail ")
    {
        let has_redirect = cmd_clean
            .split_whitespace()
            .skip(1)
            .any(|t| t.starts_with('>') || t == "<" || t.starts_with(">>"));
        if has_redirect {
            return Classification::Unsupported {
                base_command: cmd_clean
                    .split_whitespace()
                    .next()
                    .unwrap_or("cat")
                    .to_string(),
            };
        }
    }

    // Fast check with RegexSet — take the last (most specific) match
    let matches: Vec<usize> = REGEX_SET.matches(cmd_clean).into_iter().collect();
    if let Some(&idx) = matches.last() {
        let rule = &RULES[idx];

        // Extract subcommand for savings override and status detection
        let (savings, status) = if let Some(caps) = COMPILED[idx].captures(cmd_clean) {
            if let Some(sub) = caps.get(1) {
                let subcmd = sub.as_str();
                // Check if this subcommand has a special status
                let status = rule
                    .subcmd_status
                    .iter()
                    .find(|(s, _)| *s == subcmd)
                    .map(|(_, st)| *st)
                    .unwrap_or(super::report::CtxcrlStatus::Existing);

                // Check if this subcommand has custom savings
                let savings = rule
                    .subcmd_savings
                    .iter()
                    .find(|(s, _)| *s == subcmd)
                    .map(|(_, pct)| *pct)
                    .unwrap_or(rule.savings_pct);

                (savings, status)
            } else {
                (rule.savings_pct, super::report::CtxcrlStatus::Existing)
            }
        } else {
            (rule.savings_pct, super::report::CtxcrlStatus::Existing)
        };

        Classification::Supported {
            ctxcrl_equivalent: rule.ctxcrl_cmd,
            category: rule.category,
            estimated_savings_pct: savings,
            status,
        }
    } else {
        // Extract base command for unsupported
        let base = extract_base_command(cmd_clean);
        if base.is_empty() {
            Classification::Ignored
        } else {
            Classification::Unsupported {
                base_command: base.to_string(),
            }
        }
    }
}

/// Extract the base command (first word, or first two if it looks like a subcommand pattern).
fn extract_base_command(cmd: &str) -> &str {
    let parts: Vec<&str> = cmd.splitn(3, char::is_whitespace).collect();
    match parts.len() {
        0 => "",
        1 => parts[0],
        _ => {
            let second = parts[1];
            // If the second token looks like a subcommand (no leading -)
            if !second.starts_with('-') && !second.contains('/') && !second.contains('.') {
                // Return "cmd subcmd"
                let end = cmd
                    .find(char::is_whitespace)
                    .and_then(|i| {
                        let rest = &cmd[i..];
                        let trimmed = rest.trim_start();
                        trimmed
                            .find(char::is_whitespace)
                            .map(|j| i + (rest.len() - trimmed.len()) + j)
                    })
                    .unwrap_or(cmd.len());
                &cmd[..end]
            } else {
                parts[0]
            }
        }
    }
}

/// Quote-aware heredoc detection — `<<` inside quotes is not a heredoc.
pub fn has_heredoc(cmd: &str) -> bool {
    tokenize(cmd)
        .iter()
        .any(|t| t.kind == TokenKind::Redirect && t.value.starts_with("<<"))
}

pub fn split_command_chain(cmd: &str) -> Vec<&str> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    // Lexer-based for `<<`; string-based for `$((` (lexer splits it across tokens).
    if has_heredoc(trimmed) || trimmed.contains("$((") {
        return vec![trimmed];
    }

    split_on_operators(trimmed, true)
}

/// Strip git global options before the subcommand (#163).
/// `git -C /tmp status` → `git status`, preserving the rest.
/// Returns the original string unchanged if not a git command.
fn strip_git_global_opts(cmd: &str) -> String {
    // Only applies to commands starting with "git "
    if !cmd.starts_with("git ") {
        return cmd.to_string();
    }
    let after_git = &cmd[4..]; // skip "git "
    let stripped = GIT_GLOBAL_OPT.replace(after_git, "");
    format!("git {}", stripped.trim())
}

/// Strip the rustup `+toolchain` selector after `cargo` (#cargo-toolchain).
/// `cargo +nightly test` → `cargo test`, preserving the rest. Returns the
/// original string unchanged if not a cargo command or no `+toolchain` present.
/// Classification-only: the rewrite path keeps the selector so the spawned
/// command still runs against the requested toolchain.
fn strip_cargo_toolchain(cmd: &str) -> String {
    if !cmd.starts_with("cargo ") {
        return cmd.to_string();
    }
    let after_cargo = &cmd[6..]; // skip "cargo "
    let stripped = CARGO_TOOLCHAIN_OPT.replace(after_cargo, "");
    format!("cargo {}", stripped.trim())
}

/// Normalise a command for classifier/rewriter input so the same form is
/// seen by `classify_command`, `rewrite_segment_inner`, and the
/// `is_excluded` check (#83):
/// 1. Strip env-style prefix (env VAR=val, sudo) — handles `sudo /usr/bin/env`
/// 2. Strip absolute binary path (/usr/bin/env -> env)
/// 3. Re-strip env-style prefix so the surfaced `env <cmd>` is removed
/// 4. Strip git/golangci-lint global opts
fn normalise_command(cmd: &str) -> String {
    let stripped = ENV_PREFIX.replace(cmd.trim(), "").to_string();
    let stripped = strip_absolute_path(&stripped);
    let stripped = ENV_PREFIX.replace(&stripped, "").to_string();
    let stripped = strip_git_global_opts(stripped.trim());
    let stripped = strip_cargo_toolchain(stripped.trim());
    strip_golangci_global_opts(&stripped)
}

/// Strip golangci-lint global options before the `run` subcommand.
/// `golangci-lint --color never run ./...` → `golangci-lint run ./...`
/// Returns the original string unchanged if this is not a supported compact `run` invocation.
fn strip_golangci_global_opts(cmd: &str) -> String {
    match parse_golangci_run_parts(cmd) {
        Some(parts) => format!("golangci-lint {}", parts.run_segment),
        None => cmd.to_string(),
    }
}

/// Parse supported golangci-lint invocations with optional global flags before `run`.
fn parse_golangci_run_parts(cmd: &str) -> Option<GolangciRunParts<'_>> {
    let tokens = split_token_spans(cmd);
    let first = tokens.first()?;
    if first.0 != "golangci-lint" && first.0 != "golangci" {
        return None;
    }

    let mut i = 1;
    while i < tokens.len() {
        let token = tokens[i].0;

        if token == "--" {
            return None;
        }

        if !token.starts_with('-') {
            if token == "run" {
                let global_segment = if i > 1 {
                    cmd[tokens[1].1..tokens[i].1].trim()
                } else {
                    ""
                };
                let run_segment = cmd[tokens[i].1..].trim();
                return Some(GolangciRunParts {
                    global_segment,
                    run_segment,
                });
            }
            return None;
        }

        if let Some(flag) = split_golangci_flag_name(token) {
            if golangci_flag_takes_separate_value(token, flag) {
                i += 1;
            }
        }

        i += 1;
    }

    None
}

fn split_golangci_flag_name(arg: &str) -> Option<&str> {
    if arg.starts_with("--") {
        return Some(arg.split_once('=').map(|(flag, _)| flag).unwrap_or(arg));
    }

    if arg.starts_with('-') {
        return Some(arg);
    }

    None
}

fn golangci_flag_takes_separate_value(arg: &str, flag: &str) -> bool {
    if !GOLANGCI_GLOBAL_OPT_WITH_VALUE.contains(&flag) {
        return false;
    }

    if arg.starts_with("--") && arg.contains('=') {
        return false;
    }

    true
}

fn split_token_spans(cmd: &str) -> Vec<(&str, usize, usize)> {
    let mut tokens = Vec::new();
    let mut start = None;

    for (idx, ch) in cmd.char_indices() {
        if ch.is_whitespace() {
            if let Some(token_start) = start.take() {
                tokens.push((&cmd[token_start..idx], token_start, idx));
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }

    if let Some(token_start) = start {
        tokens.push((&cmd[token_start..], token_start, cmd.len()));
    }

    tokens
}

/// Normalize absolute binary paths: `/usr/bin/grep -rn foo` → `grep -rn foo` (#485)
/// Only strips a TRUE absolute path (first word starts with `/`). Relative
/// invocations like `./git` or `repo/bin/git` are NOT the system binary and
/// must not be normalised to `git` and rewritten (G7/#100).
fn strip_absolute_path(cmd: &str) -> String {
    let first_space = cmd.find(' ');
    let first_word = match first_space {
        Some(pos) => &cmd[..pos],
        None => cmd,
    };
    if first_word.starts_with('/') {
        // Extract basename
        let basename = first_word.rsplit('/').next().unwrap_or(first_word);
        if basename.is_empty() {
            return cmd.to_string();
        }
        match first_space {
            Some(pos) => format!("{}{}", basename, &cmd[pos..]),
            None => basename.to_string(),
        }
    } else {
        cmd.to_string()
    }
}

/// True only when the env-prefix contains an assignment whose key is EXACTLY
/// the canonical `CTXCRL_DISABLED` or the legacy `RTK_DISABLED` (deprecated,
/// still honoured). A naive `prefix.contains("RTK_DISABLED=")` is unsafe: a
/// crafted prefix like `FOO=RTK_DISABLED=1 git status` parses as a single
/// assignment `FOO` = `RTK_DISABLED=1`, so the substring is present even
/// though `RTK_DISABLED` was never genuinely set. Parse into individual
/// `KEY=VALUE` tokens and match the key name precisely.
pub fn prefix_contains_ctxcrl_disabled(prefix_part: &str) -> bool {
    env_prefix_assignments(prefix_part)
        .iter()
        .any(|(key, _)| key == "CTXCRL_DISABLED" || key == "RTK_DISABLED")
}

/// Split an env-prefix chunk into individual `(KEY, VALUE)` assignments.
///
/// The prefix is the portion matched by `ENV_PREFIX` — a run of `sudo `,
/// `env ` words and `KEY=VALUE` assignments. Splits with SHELL-WORD semantics
/// (quote-aware) and splits each remaining word at the FIRST `=` only.
///
/// #229: a naive whitespace split let a QUOTED value with an embedded space
/// (`FOO="bar RTK_DISABLED=1"`) break into two words, so `RTK_DISABLED=1`
/// surfaced as a standalone assignment and spoofed the disable. `shlex`
/// keeps the quoted value as one word (`FOO=bar RTK_DISABLED=1` → key `FOO`).
/// Returns owned strings since shlex un-quotes into new allocations.
fn env_prefix_assignments(prefix_part: &str) -> Vec<(String, String)> {
    let Some(words) = shlex::split(prefix_part) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for tok in words {
        if tok == "sudo" || tok == "env" {
            continue;
        }
        if let Some(eq) = tok.find('=') {
            let key = &tok[..eq];
            // A valid shell env key: [A-Za-z_][A-Za-z0-9_]*.
            if !key.is_empty()
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !key.chars().next().unwrap().is_ascii_digit()
            {
                let value = tok[eq + 1..].to_string();
                out.push((key.to_string(), value));
            }
        }
    }
    out
}

/// Check if a command has RTK_DISABLED= prefix in its env prefix portion.
pub fn cmd_has_ctxcrl_disabled_prefix(cmd: &str) -> bool {
    let (prefix_part, _) = strip_disabled_prefix(cmd);
    prefix_contains_ctxcrl_disabled(prefix_part)
}

/// Strip RTK_DISABLED=X and other env prefixes, returns `(env_prefix, actual_command)`.
pub fn strip_disabled_prefix(cmd: &str) -> (&str, &str) {
    let trimmed = cmd.trim();
    let stripped = ENV_PREFIX.replace(trimmed, "");
    // stripped is a Cow<str> that borrows from trimmed when no replacement happens.
    // We need to return a &str into the original, so compute the offset.
    let prefix_len = trimmed.len() - stripped.len();
    let prefix_part = &trimmed[..prefix_len];
    let rest = trimmed[prefix_len..].trim();
    (prefix_part, rest)
}

fn strip_trailing_redirects(cmd: &str) -> (&str, &str) {
    let tokens = tokenize(cmd);
    if tokens.is_empty() {
        return (cmd, "");
    }

    let mut redir_boundary = tokens.len();
    let mut i = tokens.len();
    while i > 0 {
        i -= 1;
        match tokens[i].kind {
            TokenKind::Redirect => {
                redir_boundary = i;
            }
            TokenKind::Arg => {
                if i > 0 && tokens[i - 1].kind == TokenKind::Redirect {
                    redir_boundary = i - 1;
                    i -= 1;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    if redir_boundary >= tokens.len() {
        return (cmd, "");
    }

    let cut = tokens[redir_boundary].offset;
    let cmd_part = cmd[..cut].trim_end();
    let redir_part = &cmd[cmd_part.len()..];
    (cmd_part, redir_part)
}

/// #166: classify a single Redirect token's effect on the producing
/// command's stdout. Returns `true` when the redirect diverts stdout
/// away from where it would otherwise go (model/terminal). Returns
/// `false` when stdout is unaffected (stderr-only redirect, stdin
/// redirect, heredoc).
///
/// Examples:
/// - `">"`, `">>"`, `"1>"`, `"1>>"`, `"&>"`, `"&>>"` — stdout to file
/// - `">&2"`, `"1>&2"`, `"1>&-"` — stdout duped or closed
/// - `"2>"`, `"2>>"`, `"2>&1"`, `"2>&-"` — stderr-only, stdout safe
/// - `"<"`, `"<<"`, `"<<<"` — stdin, stdout safe
///
/// Fail-closed: an unrecognised redirect token returns `true` (treat as
/// stdout-affecting) so we never rewrite an unknown construct.
fn redirect_affects_stdout(redirect_token: &str) -> bool {
    let t = redirect_token.trim();
    // Stdin / heredoc — never affects stdout.
    if t.starts_with('<') {
        return false;
    }
    // Stderr-source forms: `2>`, `2>>`, `2>&1`, `2>&-`, etc.
    // These divert stderr, not stdout.
    if let Some(rest) = t.strip_prefix("2>") {
        // `2>&N` where N is `1` or `-` is stderr-source. `2>&0` would be
        // unusual but still stderr-source.
        let _ = rest;
        return false;
    }
    // Everything else is stdout-affecting:
    //   `>`, `>>`, `1>`, `1>>`, `&>`, `&>>`, `>&2`, `1>&2`, `>&-`, etc.
    true
}

/// #166: true if any trailing-redirect token on this segment diverts
/// stdout away from the model. Inspects `tokenize(cmd)` once.
fn segment_stdout_is_redirected(cmd: &str) -> bool {
    tokenize(cmd)
        .iter()
        .any(|t| t.kind == TokenKind::Redirect && redirect_affects_stdout(&t.value))
}

/// Collapse bash line continuations (`\<newline>`, incl. CRLF/CR) to a single
/// space so a continuation-broken command still matches a rewrite rule (upstream
/// rtk-ai/rtk 2543be5 / #1564). Claude Code emits these for long invocations,
/// e.g. `git diff \<NL>HEAD~1`. Mirrors the same normalisation the supply-chain
/// gate already applies on its own path. `Cow::Borrowed` fast-path: no alloc
/// when the command has no continuation.
///
/// Quote-aware: a `\<newline>` INSIDE a single- or double-quoted span is left
/// untouched. This matters for shell wrappers — `bash -c 'cargo \<LF>test'`:
/// bash treats `\<LF>` literally inside single quotes (NOT a continuation), so
/// collapsing it would mutate the inner script that `unwrap_shell_wrapper` later
/// extracts, producing a DIFFERENT executed command. Only genuine unquoted
/// continuations are collapsed, preserving the original 2543be5 behaviour for
/// `git diff \<LF>HEAD~1`. (Conservative: we leave double-quoted spans alone too,
/// rather than emulating bash's exact in-double-quote removal — an unchanged
/// quoted body is always safe downstream.)
///
/// Gate safety: the security gates run on the raw, pre-rewrite string in
/// `hook_cmd::run_gates`, so this normalisation never affects what Tirith /
/// supply-chain sees — it only changes filter selection.
fn collapse_line_continuations(s: &str) -> Cow<'_, str> {
    // Fast path: no backslash at all → cannot contain a continuation.
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }

    // Determine whether any UNQUOTED continuation exists; if not, borrow.
    if !has_unquoted_continuation(s) {
        return Cow::Borrowed(s);
    }

    // Accumulate raw bytes — the quote/continuation logic below is byte-safe,
    // but the EMIT step must preserve multibyte UTF-8 exactly. Pushing
    // `c as char` would Latin-1-reinterpret any byte >= 0x80 and corrupt
    // non-ASCII chars in the rewritten command, so we collect bytes and decode
    // once at the end.
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let c = bytes[i];
        // Outside any quote, a backslash directly before a newline (LF/CRLF/CR)
        // is a continuation: drop the surrounding horizontal whitespace already
        // emitted, emit a single space, and skip the continuation bytes.
        if !in_single && !in_double && c == b'\\' {
            if let Some(skip) = continuation_len(&bytes[i..]) {
                // Trim trailing spaces/tabs we just pushed, then emit one space.
                while matches!(out.last(), Some(b' ') | Some(b'\t')) {
                    out.pop();
                }
                out.push(b' ');
                i += skip;
                // Skip leading horizontal whitespace after the newline.
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
                    i += 1;
                }
                continue;
            }
        }
        match c {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            _ => {}
        }
        out.push(c);
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Length in bytes of a continuation sequence (`\` + `\r\n` | `\n` | `\r`)
/// starting at `b[0] == b'\\'`, or `None` if `b` does not start with one.
fn continuation_len(b: &[u8]) -> Option<usize> {
    if b.first() != Some(&b'\\') {
        return None;
    }
    match b.get(1) {
        Some(b'\r') if b.get(2) == Some(&b'\n') => Some(3), // \ CR LF
        Some(b'\n') | Some(b'\r') => Some(2),               // \ LF | \ CR
        _ => None,
    }
}

/// Whether `s` contains a line continuation OUTSIDE single/double quotes.
fn has_unquoted_continuation(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let c = bytes[i];
        if !in_single && !in_double && continuation_len(&bytes[i..]).is_some() {
            return true;
        }
        match c {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Returns `None` if the command is unsupported or ignored (hook should pass through).
///
/// Handles compound commands (`&&`, `||`, `;`) by rewriting each segment independently.
/// For pipes (`|`), only rewrites the left-hand command (pipe targets stay raw),
/// but continues rewriting segments after subsequent `&&`/`||`/`;` operators.
fn strip_ctxcrl_shell_builtin_prefix(cmd: &str) -> Option<&str> {
    let rest = cmd
        .strip_prefix("contextcrawler ")
        .or_else(|| cmd.strip_prefix("rtk "))?;
    let builtin = rest.split_whitespace().next().unwrap_or("");
    const SHELL_SIDE_EFFECT_BUILTINS: &[&str] = &[
        "cd", "pushd", "popd", "export", "source", ".", "alias", "unalias", "unset", "ulimit",
        "umask", "set", "shift", "typeset", "declare",
    ];
    SHELL_SIDE_EFFECT_BUILTINS
        .contains(&builtin)
        .then_some(rest)
}

/// Also strips user-configured transparent wrapper prefixes
/// (`[hooks].transparent_prefixes` in `config.toml`) before routing.
///
/// A transparent prefix is a wrapper command that doesn't change *what* is
/// being run, only *how* it's run — e.g. `docker exec mycontainer`,
/// `direnv exec .`, `poetry run`, or `bundle exec`. Stripping it lets the inner
/// command match a filter; the prefix is then re-prepended to the rewrite. The
/// built-in [`SHELL_PREFIX_BUILTINS`] (`noglob`, `command`, `builtin`, `exec`,
/// `nocorrect`) are always applied in addition to user-configured prefixes.
///
/// Matching is strict: a configured prefix `"foo bar"` matches a command that
/// starts with `"foo bar "` (or strictly equals `"foo bar"`), not anything
/// else. Matching is literal, not pattern-based: configure the exact concrete
/// prefix you use.
pub fn rewrite_command(
    cmd: &str,
    excluded: &[String],
    transparent_prefixes: &[String],
) -> Option<String> {
    // Normalise line continuations BEFORE matching (upstream 2543be5): a
    // `\<NL>`-broken command would otherwise fall through to raw passthrough.
    let normalized = collapse_line_continuations(cmd);
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return None;
    }

    if has_heredoc(trimmed) || trimmed.contains("$((") {
        return None;
    }

    let compiled = compile_exclude_patterns(excluded);
    let normalized_prefixes = normalize_transparent_prefixes(transparent_prefixes);

    // Simple (non-compound) already-CTXCRL command — return as-is, except
    // shell builtins. `contextcrawler cd /x` / `rtk export FOO=bar` run in a
    // subprocess, so their side effect is lost when the subprocess exits.
    // Strip the redundant prefix so the shell executes the builtin in the
    // current process instead (#2508).
    // For compound commands that start with "rtk" (e.g. "contextcrawler git add . && cargo test"),
    // fall through to rewrite_compound so the remaining segments get rewritten.
    let has_compound = trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains(';')
        || trimmed.contains('|')
        || trimmed.contains(" & ");
    if !has_compound
        && (trimmed.starts_with("contextcrawler ")
            || trimmed.starts_with("rtk ")
            || trimmed == "contextcrawler"
            || trimmed == "rtk")
    {
        if let Some(stripped) = strip_ctxcrl_shell_builtin_prefix(trimmed) {
            return Some(stripped.to_string());
        }
        return Some(trimmed.to_string());
    }

    rewrite_compound(trimmed, &compiled, &normalized_prefixes)
}

/// Rewrite a compound command (with `&&`, `||`, `;`, `|`) by rewriting each segment.
fn rewrite_compound(
    cmd: &str,
    excluded: &[ExcludePattern],
    transparent_prefixes: &[String],
) -> Option<String> {
    let tokens = tokenize(cmd);
    let mut result = String::with_capacity(cmd.len() + 32);
    let mut any_changed = false;
    let mut seg_start: usize = 0;

    for tok in &tokens {
        if tok.offset < seg_start {
            continue;
        }
        match tok.kind {
            TokenKind::Operator => {
                let seg = cmd[seg_start..tok.offset].trim();
                let rewritten = rewrite_segment(seg, excluded, transparent_prefixes)
                    .unwrap_or_else(|| seg.to_string());
                if rewritten != seg {
                    any_changed = true;
                }
                result.push_str(&rewritten);
                if tok.value == ";" {
                    result.push(';');
                    let after = tok.offset + tok.value.len();
                    if after < cmd.len() {
                        result.push(' ');
                    }
                } else {
                    result.push(' ');
                    result.push_str(&tok.value);
                    result.push(' ');
                }
                seg_start = tok.offset + tok.value.len();
                while seg_start < cmd.len() && cmd.as_bytes().get(seg_start) == Some(&b' ') {
                    seg_start += 1;
                }
            }
            TokenKind::Pipe => {
                // #166: a command whose stdout is piped MUST NOT be
                // rewritten. The pipeline consumer depends on the
                // producer's exact bytes; substituting `contextcrawler
                // <cmd>` changes those bytes and silently changes the
                // consumer's answer (e.g. `grep ... | wc -l` counts the
                // filtered lines, not the raw matches).
                //
                // Keep the producer segment AND the rest of the pipe
                // chain (everything up to the next `&&`/`||`/`;`/`&`)
                // exactly as the user typed it.
                let seg = cmd[seg_start..tok.offset].trim();
                result.push_str(seg);

                let pipe_group_end = tokens.iter().find(|t| {
                    t.offset > tok.offset
                        && (t.kind == TokenKind::Operator
                            || (t.kind == TokenKind::Shellism && t.value == "&"))
                });

                match pipe_group_end {
                    Some(next_op) => {
                        result.push(' ');
                        result.push_str(cmd[tok.offset..next_op.offset].trim());
                        seg_start = next_op.offset;
                    }
                    None => {
                        result.push(' ');
                        result.push_str(cmd[tok.offset..].trim_start());
                        return if any_changed { Some(result) } else { None };
                    }
                }
            }
            TokenKind::Shellism if tok.value == "&" => {
                let seg = cmd[seg_start..tok.offset].trim();
                let rewritten = rewrite_segment(seg, excluded, transparent_prefixes)
                    .unwrap_or_else(|| seg.to_string());
                if rewritten != seg {
                    any_changed = true;
                }
                result.push_str(&rewritten);
                result.push_str(" & ");
                seg_start = tok.offset + tok.value.len();
                while seg_start < cmd.len() && cmd.as_bytes().get(seg_start) == Some(&b' ') {
                    seg_start += 1;
                }
            }
            _ => {}
        }
    }

    let seg = cmd[seg_start..].trim();
    let rewritten =
        rewrite_segment(seg, excluded, transparent_prefixes).unwrap_or_else(|| seg.to_string());
    if rewritten != seg {
        any_changed = true;
    }
    result.push_str(&rewritten);

    if any_changed {
        Some(result)
    } else {
        None
    }
}

fn rewrite_line_range(cmd: &str) -> Option<String> {
    for re in [&*HEAD_N, &*HEAD_N_SPACE, &*HEAD_LINES, &*HEAD_LINES_SPACE] {
        if let Some(caps) = re.captures(cmd) {
            let n = caps.get(1)?.as_str();
            let file = caps.get(2)?.as_str();
            return Some(format!("contextcrawler read {} --max-lines {}", file, n));
        }
    }
    if cmd.starts_with("head -") {
        return None;
    }
    for re in [
        &*TAIL_N,
        &*TAIL_N_SPACE,
        &*TAIL_LINES_EQ,
        &*TAIL_LINES_SPACE,
    ] {
        if let Some(caps) = re.captures(cmd) {
            let n = caps.get(1)?.as_str();
            let file = caps.get(2)?.as_str();
            return Some(format!("contextcrawler read {} --tail-lines {}", file, n));
        }
    }
    None
}

/// Shell prefix builtins that modify how the shell runs a command
/// but don't change which command runs. Strip before routing, re-prepend after.
const SHELL_PREFIX_BUILTINS: &[&str] = &["noglob", "command", "builtin", "exec", "nocorrect"];

const MAX_PREFIX_DEPTH: usize = 10;

enum ExcludePattern {
    Regex(Regex),
    Prefix(String),
}

fn compile_exclude_patterns(patterns: &[String]) -> Vec<ExcludePattern> {
    patterns
        .iter()
        .filter_map(|pattern| {
            let trimmed = pattern.trim();
            if trimmed.is_empty() || trimmed == "^" {
                eprintln!(
                    "contextcrawler: warning: ignoring trivial exclude_commands pattern '{}'",
                    pattern
                );
                return None;
            }
            let anchored = if trimmed.starts_with('^') {
                trimmed.to_string()
            } else {
                format!(r"^{}($|\s)", regex::escape(trimmed))
            };
            Some(match Regex::new(&anchored) {
                Ok(re) => ExcludePattern::Regex(re),
                Err(e) => {
                    eprintln!(
                        "contextcrawler: warning: invalid exclude_commands pattern '{}': {}",
                        pattern, e
                    );
                    ExcludePattern::Prefix(trimmed.to_string())
                }
            })
        })
        .collect()
}

fn normalize_transparent_prefixes(prefixes: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = prefixes
        .iter()
        .map(|prefix| prefix.trim())
        .filter(|prefix| !prefix.is_empty())
        .map(str::to_string)
        .collect();

    // Match longer wrappers first so `docker exec mycontainer` wins over `docker`.
    normalized.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    normalized.dedup();
    normalized
}

fn rewrite_segment(
    seg: &str,
    excluded: &[ExcludePattern],
    transparent_prefixes: &[String],
) -> Option<String> {
    rewrite_segment_inner(seg, excluded, transparent_prefixes, 0)
}

fn is_excluded(cmd: &str, excluded: &[ExcludePattern]) -> bool {
    excluded.iter().any(|pat| match pat {
        ExcludePattern::Regex(re) => re.is_match(cmd),
        ExcludePattern::Prefix(prefix) => cmd.starts_with(prefix.as_str()),
    })
}

fn rewrite_segment_inner(
    seg: &str,
    excluded: &[ExcludePattern],
    transparent_prefixes: &[String],
    depth: usize,
) -> Option<String> {
    let trimmed = seg.trim();
    if trimmed.is_empty() {
        return None;
    }

    if depth >= MAX_PREFIX_DEPTH {
        return None;
    }

    // #2508 (compound): an already-CTXCRL shell-builtin segment
    // (`contextcrawler cd /x`, `rtk export FOO=bar`) inside a compound command
    // loses its side effect when run in a subprocess. Strip the redundant
    // prefix so the builtin executes in the current shell, mirroring the
    // simple-command path in `rewrite_command`. Only pure side-effect builtins
    // match, so real CTXCRL commands (`contextcrawler read …`) are untouched.
    if let Some(stripped) = strip_ctxcrl_shell_builtin_prefix(trimmed) {
        return Some(stripped.to_string());
    }

    // #195: `sudo` with flags (`sudo -u user <cmd>`). Strip the `sudo …`
    // prefix for classification but RE-PREPEND it so the spawned command still
    // runs with the requested privileges. This MUST run before the ENV_PREFIX
    // block below: ENV_PREFIX matches a bare leading `sudo ` only, so it would
    // otherwise strip `sudo ` and leave the orphan flags (`-u user <cmd>`)
    // which never classify. Bare `sudo <cmd>` (no flags) still falls through to
    // the ENV_PREFIX handling.
    if let Some(m) = SUDO_FLAGS_PREFIX.find(trimmed) {
        let prefix = trimmed[..m.end()].trim_end();
        let rest = trimmed[m.end()..].trim_start();
        if rest.is_empty() {
            return None;
        }
        return rewrite_segment_inner(rest, excluded, transparent_prefixes, depth + 1)
            .map(|rewritten| format!("{} {}", prefix, rewritten));
    }

    let (env_prefix, rest_after_env) = strip_disabled_prefix(trimmed);
    if !env_prefix.is_empty() {
        // #345: RTK_DISABLED=1 in env prefix → skip rewrite entirely
        // #508: warn on stderr so agents learn to stop overusing it
        // G7/#100: match the EXACT key, not a substring — a crafted prefix
        // like `FOO=RTK_DISABLED=1 cmd` must NOT disable rewriting.
        if prefix_contains_ctxcrl_disabled(env_prefix) {
            eprintln!(
                "[contextcrawler] RTK_DISABLED=1 detected — skipping filter for this command. \
                 Remove RTK_DISABLED=1 to restore token savings."
            );
            return None;
        }
        let rewritten =
            rewrite_segment_inner(rest_after_env, excluded, transparent_prefixes, depth + 1)?;
        return Some(format!("{}{}", env_prefix, rewritten));
    }

    for &prefix in SHELL_PREFIX_BUILTINS {
        if let Some(rest) = strip_word_prefix(trimmed, prefix) {
            if rest.is_empty() {
                return None;
            }
            return rewrite_segment_inner(rest, excluded, transparent_prefixes, depth + 1)
                .map(|rewritten| format!("{} {}", prefix, rewritten));
        }
    }

    // User-configured wrapper prefixes (e.g. `docker exec mycontainer`). Same
    // strip-recurse-reprepend contract as the builtin list above.
    for prefix in transparent_prefixes {
        if let Some(rest) = strip_word_prefix(trimmed, prefix) {
            if rest.is_empty() {
                return None;
            }
            return rewrite_segment_inner(rest, excluded, transparent_prefixes, depth + 1)
                .map(|rewritten| format!("{} {}", prefix, rewritten));
        }
    }

    // #195: shell-wrapper unwrap. `sh -c 'git log'` / `bash -lc 'cargo test'`
    // with a SINGLE simple inner command — rewrite the inner and re-wrap so
    // its output gets filtered. Compound inner scripts (pipes, &&, subst,
    // redirects, globs, nested quotes) return None from `unwrap_shell_wrapper`
    // and fall through to raw passthrough. The gates already saw the full raw
    // wrapper string in `hook_cmd::run_gates` before this rewrite runs, so this
    // is filter-selection only and never bypasses Tirith / supply-chain.
    if let Some((prefix, quote, inner)) = unwrap_shell_wrapper(trimmed) {
        // Recurse on the inner command. Only re-wrap if it actually rewrote to
        // something different — otherwise leave the wrapper raw (None).
        if let Some(rewritten_inner) =
            rewrite_segment_inner(inner, excluded, transparent_prefixes, depth + 1)
        {
            if rewritten_inner != inner {
                // `unwrap_shell_wrapper` guarantees the inner had no quote of
                // either kind, and the rewrite only prepends `contextcrawler `
                // / re-uses the inner's own (quote-free) args, so the rewritten
                // inner cannot contain `quote`. Safe to re-wrap verbatim.
                return Some(format!("{}{}{}", prefix, rewritten_inner, quote));
            }
        }
        return None;
    }

    // #166: if ANY redirect on this segment diverts stdout away from the
    // model (e.g. `>file`, `&>file`, `>&2`), skip rewrite entirely. The
    // user asked for the raw bytes to land at the redirect target;
    // replacing the command with `contextcrawler <cmd>` would land
    // filtered bytes instead and silently produce wrong output. Only
    // stderr-source redirects (`2>file`, `2>&1`, `2>&-`) and stdin
    // redirects (`<file`) leave stdout intact and are safe to rewrite.
    if segment_stdout_is_redirected(trimmed) {
        return None;
    }

    // #166: command substitution `$(...)`, backticks, and process
    // substitution `<(...)` / `>(...)` all execute a subshell whose
    // output is interpolated into the surrounding command. Rewriting
    // the OUTER command can silently change what the substitution
    // feeds in (process subst), and we cannot rewrite the INNER without
    // re-parsing it as a fresh command — out of scope for the simple
    // rewrite engine. Fail closed: leave the whole segment raw.
    //
    // `extract_substitutions` returns one entry per `$(...)`, backtick
    // and `<(...)`/`>(...)` construct found at any quoting depth, so a
    // non-empty list means at least one is present.
    if !extract_substitutions(trimmed).is_empty() {
        return None;
    }

    // Strip trailing stderr/stdout redirects before matching (#530)
    // e.g. "git status 2>&1" → match "git status", re-append " 2>&1"
    let (cmd_part, redirect_suffix) = strip_trailing_redirects(trimmed);

    // Already CTXCRL — pass through unchanged
    if cmd_part.starts_with("contextcrawler ")
        || cmd_part.starts_with("rtk ")
        || cmd_part == "contextcrawler"
        || cmd_part == "rtk"
    {
        return Some(trimmed.to_string());
    }

    if cmd_part.starts_with("head -") || cmd_part.starts_with("tail ") {
        return rewrite_line_range(cmd_part).map(|r| format!("{}{}", r, redirect_suffix));
    }

    // Most cat flags (-v, -A, -e, -t, -s, -b, --show-all, etc.) have different
    // semantics than ctxcrl read or no equivalent at all. Only `-n` (line numbers)
    // maps correctly to `ctxcrl read -n`. Skip rewrite for any other flag.
    if let Some(cmd_args) = cmd_part.strip_prefix("cat ") {
        let args = cmd_args.trim_start();
        if args.starts_with('-') && !args.starts_with("-n ") && !args.starts_with("-n\t") {
            return None;
        }
    }

    // Use classify_command for correct ignore/prefix handling.
    // is_excluded must see the same fully-normalised form as classify (#83
    // follow-up) so user-configured exclude_commands rules apply to
    // `/usr/bin/env git ...` and `sudo /usr/bin/env git ...`.
    let ctxcrl_equivalent = match classify_command(cmd_part) {
        Classification::Supported {
            ctxcrl_equivalent, ..
        } => {
            let normalised_for_exclude = normalise_command(cmd_part);
            if is_excluded(normalised_for_exclude.trim(), excluded) {
                return None;
            }
            ctxcrl_equivalent
        }
        _ => return None,
    };

    // Lighter normalisation for downstream rule processing: strip absolute
    // path and env-style prefix only. Global git/golangci opts must be
    // preserved here because the rewrite logic below re-uses them. (#83)
    let cmd_part_norm = strip_absolute_path(cmd_part);
    let cmd_part_norm = ENV_PREFIX.replace(&cmd_part_norm, "").to_string();
    let cmd_part_norm = cmd_part_norm.trim();

    // Find the matching rule (ctxcrl_cmd values are unique across all rules)
    let rule = RULES.iter().find(|r| r.ctxcrl_cmd == ctxcrl_equivalent)?;

    if let Some(parts) = parse_golangci_run_parts(cmd_part_norm) {
        let rewritten = if parts.global_segment.is_empty() {
            format!("contextcrawler golangci-lint {}", parts.run_segment)
        } else {
            format!(
                "contextcrawler golangci-lint {} {}",
                parts.global_segment, parts.run_segment
            )
        };
        return Some(rewritten);
    }

    // #196: gh with --json/--jq/--template produces structured output that
    // ctxcrl gh would corrupt — skip rewrite so the caller gets raw JSON.
    if rule.ctxcrl_cmd == "contextcrawler gh" {
        let args_lower = cmd_part_norm.to_lowercase();
        if args_lower.contains("--json")
            || args_lower.contains("--jq")
            || args_lower.contains("--template")
        {
            return None;
        }
    }

    // Try each rewrite prefix (longest first) with word-boundary check
    for &prefix in rule.rewrite_prefixes {
        if let Some(rest) = strip_word_prefix(cmd_part_norm, prefix) {
            let rewritten = if rest.is_empty() {
                format!("{}{}", rule.ctxcrl_cmd, redirect_suffix)
            } else {
                format!("{} {}{}", rule.ctxcrl_cmd, rest, redirect_suffix)
            };
            return Some(rewritten);
        }
    }

    None
}

/// #195: A `sh -c '<inner>'` / `bash -lc "<inner>"` wrapper whose inner
/// script is a SINGLE simple command. Returns `(prefix, quote, inner)` so the
/// caller can rewrite `inner` and re-wrap as `<prefix><quote><rewritten><quote>`.
///
/// Conservative by design — returns `None` (raw passthrough) for anything that
/// isn't trivially safe to rewrite:
/// - flags we don't model (`-o pipefail`, `-s`, separate `-l -c`)
/// - any shell metacharacter in the inner script: `&`, `|`, `;`, `$`,
///   backtick, `<`, `>`, `(`, `)`, `{`, `}`, newline, backslash, glob `*?[`,
///   or a quote of either kind. The presence of ANY of these means the inner
///   is a compound script / substitution / redirect, NOT a single command —
///   rewriting it would change semantics, so we leave the whole thing raw.
///
/// This is a FILTER-SELECTION decision only. The security gates have already
/// run on the full raw `sh -c '...'` string in `hook_cmd::run_gates` before
/// any rewrite is attempted (#195), so unwrapping never bypasses Tirith /
/// supply-chain.
fn unwrap_shell_wrapper(cmd: &str) -> Option<(&str, char, &str)> {
    let caps = SHELL_WRAPPER_PREFIX.captures(cmd)?;
    let m = caps.get(0)?;
    let quote = caps.get(1)?.as_str().chars().next()?;

    // The opening quote is the last byte of the prefix match. The inner span
    // runs from there to the matching closing quote, which must be the final
    // non-whitespace char of the command (a single quoted argument, nothing
    // after it).
    let prefix = &cmd[..m.end()];
    let after_quote = &cmd[m.end()..];

    // Everything after the inner script must be exactly the closing quote
    // (optionally followed by trailing whitespace). Find the closing quote.
    let close_rel = after_quote.find(quote)?;
    let inner = &after_quote[..close_rel];
    let tail = after_quote[close_rel + quote.len_utf8()..].trim();
    if !tail.is_empty() {
        return None;
    }

    let inner = inner.trim();
    if inner.is_empty() {
        return None;
    }

    // Reject anything that isn't a single simple command. Any of these means
    // the inner is compound / has substitutions / redirects / globs / nested
    // quotes — too risky to rewrite, leave raw.
    const UNSAFE: &[char] = &[
        '&', '|', ';', '$', '`', '<', '>', '(', ')', '{', '}', '\n', '\\', '*', '?', '[', '\'', '"',
    ];
    if inner.chars().any(|c| UNSAFE.contains(&c)) {
        return None;
    }

    Some((prefix, quote, inner))
}

/// Strip a command prefix with word-boundary check.
/// Returns the remainder of the command after the prefix, or `None` if no match.
fn strip_word_prefix<'a>(cmd: &'a str, prefix: &str) -> Option<&'a str> {
    if cmd == prefix {
        Some("")
    } else if cmd.len() > prefix.len()
        && cmd.starts_with(prefix)
        && cmd.as_bytes()[prefix.len()] == b' '
    {
        Some(cmd[prefix.len() + 1..].trim_start())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::report::CtxcrlStatus;
    use super::*;

    fn rewrite_command_no_prefixes(cmd: &str, excluded: &[String]) -> Option<String> {
        super::rewrite_command(cmd, excluded, &[])
    }

    #[test]
    fn test_classify_git_status() {
        assert_eq!(
            classify_command("git status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_env_prefix_absolute_path() {
        // /usr/bin/env <cmd> must classify the same as the bare command (#83)
        assert_eq!(
            classify_command("/usr/bin/env git status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_env_prefix_relative() {
        // Regression guard: bare `env <cmd>` already worked, keep it that way (#83)
        assert_eq!(
            classify_command("env git status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_rewrite_env_prefix_absolute_path() {
        // /usr/bin/env <cmd> must rewrite to the contextcrawler equivalent (#83)
        assert_eq!(
            rewrite_command("/usr/bin/env git status", &[], &[]),
            Some("contextcrawler git status".to_string())
        );
    }

    #[test]
    fn test_rewrite_env_prefix_respects_exclude() {
        // is_excluded must see the normalised form so exclude_commands works
        // even when the user runs `/usr/bin/env git ...` (#83 follow-up).
        assert_eq!(
            rewrite_command("/usr/bin/env git status", &["git".into()], &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_sudo_env_prefix_respects_exclude() {
        assert_eq!(
            rewrite_command("sudo /usr/bin/env git status", &["git".into()], &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_env_prefix_not_excluded() {
        // Regression guard: env-prefixed git still rewrites when the
        // exclude list does not cover it.
        assert_eq!(
            rewrite_command("/usr/bin/env git status", &["docker".into()], &[]),
            Some("contextcrawler git status".to_string())
        );
    }

    #[test]
    fn test_classify_yadm_status() {
        assert_eq!(
            classify_command("yadm status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_yadm_diff() {
        assert_eq!(
            classify_command("yadm diff"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_rewrite_yadm_status() {
        assert_eq!(
            rewrite_command_no_prefixes("yadm status", &[]),
            Some("contextcrawler git status".to_string())
        );
    }

    #[test]
    fn test_classify_git_diff_cached() {
        assert_eq!(
            classify_command("git diff --cached"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_test_filter() {
        assert_eq!(
            classify_command("cargo test filter::"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                category: "Cargo",
                estimated_savings_pct: 90.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_npx_tsc() {
        assert_eq!(
            classify_command("npx tsc --noEmit"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler tsc",
                category: "Build",
                estimated_savings_pct: 83.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cat_file() {
        assert_eq!(
            classify_command("cat src/main.rs"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler read",
                category: "Files",
                estimated_savings_pct: 60.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cat_redirect_not_supported() {
        // cat > file and cat >> file are writes, not reads — should not be classified as supported
        let write_commands = [
            "cat > /tmp/output.txt",
            "cat >> /tmp/output.txt",
            "cat file.txt > output.txt",
            "cat -n file.txt >> log.txt",
            "head -10 README.md > output.txt",
            "tail -f app.log > /dev/null",
        ];
        for cmd in &write_commands {
            if let Classification::Supported { .. } = classify_command(cmd) {
                panic!("{} should NOT be classified as Supported", cmd)
            }
            // Unsupported or Ignored is fine
        }
    }

    #[test]
    fn test_classify_cd_ignored() {
        assert_eq!(classify_command("cd /tmp"), Classification::Ignored);
    }

    #[test]
    fn test_classify_ctxcrl_already() {
        assert_eq!(
            classify_command("contextcrawler git status"),
            Classification::Ignored
        );
    }

    #[test]
    fn test_classify_tirith_ignored() {
        // #86: tirith is our own defense-in-depth gate, not an unsupported command.
        assert_eq!(
            classify_command("tirith scan ./src"),
            Classification::Ignored
        );
    }

    #[test]
    fn test_classify_shell_variable_ignored() {
        // #87: $VAR-prefixed commands are shell expansions; can't classify.
        assert_eq!(classify_command("$EDITOR foo.txt"), Classification::Ignored);
        assert_eq!(
            classify_command("$(which git) status"),
            Classification::Ignored
        );
    }

    #[test]
    fn test_classify_echo_ignored() {
        assert_eq!(
            classify_command("echo hello world"),
            Classification::Ignored
        );
    }

    #[test]
    fn test_classify_htop_unsupported() {
        match classify_command("htop -d 10") {
            Classification::Unsupported { base_command } => {
                assert_eq!(base_command, "htop");
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_env_prefix_stripped() {
        assert_eq!(
            classify_command("GIT_SSH_COMMAND=ssh git push"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_sudo_stripped() {
        assert_eq!(
            classify_command("sudo docker ps"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler docker",
                category: "Infra",
                estimated_savings_pct: 85.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_check() {
        assert_eq!(
            classify_command("cargo check"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_check_all_targets() {
        assert_eq!(
            classify_command("cargo check --all-targets"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_fmt_passthrough() {
        assert_eq!(
            classify_command("cargo fmt"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Passthrough,
            }
        );
    }

    #[test]
    fn test_classify_cargo_clippy_savings() {
        assert_eq!(
            classify_command("cargo clippy --all-targets"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_registry_covers_all_cargo_subcommands() {
        // Verify that every CargoCommand variant (Build, Test, Clippy, Check, Fmt)
        // except Other has a matching pattern in the registry
        for subcmd in ["build", "test", "clippy", "check", "fmt"] {
            let cmd = format!("cargo {subcmd}");
            match classify_command(&cmd) {
                Classification::Supported { .. } => {}
                other => panic!("cargo {subcmd} should be Supported, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_registry_covers_all_git_subcommands() {
        // Verify that every GitCommand subcommand has a matching pattern,
        // including the post-#84 expanded set routed through the passthrough.
        for subcmd in [
            "status",
            "log",
            "diff",
            "show",
            "add",
            "commit",
            "push",
            "pull",
            "branch",
            "fetch",
            "stash",
            "worktree",
            "checkout",
            "switch",
            "restore",
            "merge",
            "rebase",
            "reset",
            "tag",
            "remote",
            "cherry-pick",
        ] {
            let cmd = format!("git {subcmd}");
            match classify_command(&cmd) {
                Classification::Supported { .. } => {}
                other => panic!("git {subcmd} should be Supported, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_classify_git_checkout() {
        // #84: checkout must classify as Supported (routed via passthrough).
        assert_eq!(
            classify_command("git checkout -b foo develop"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 30.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_git_merge_with_c_flag() {
        // #84: `-c key=val` global flags before the subcommand should not
        // defeat classification. cherry-pick also has to survive its hyphen.
        match classify_command("git -c commit.gpgsign=false merge --no-ff foo") {
            Classification::Supported {
                category: "Git", ..
            } => {}
            other => panic!("git -c ... merge should be Supported, got {other:?}"),
        }
        match classify_command("git cherry-pick abc123") {
            Classification::Supported {
                category: "Git", ..
            } => {}
            other => panic!("git cherry-pick should be Supported, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_git_checkout_tag_helper_not_matched() {
        // Codex review: without a word-boundary anchor after the subcommand
        // capture, `git checkout-tag-helper foo` would falsely match the
        // `checkout` alternation. The `(?:\s|$)` anchor in rules.rs prevents that.
        match classify_command("git checkout-tag-helper foo") {
            Classification::Supported {
                category: "Git", ..
            } => {
                panic!("git checkout-tag-helper should NOT classify as Supported Git");
            }
            _ => {}
        }
    }

    #[test]
    fn test_classify_git_c_quoted_value() {
        // Codex review: GIT_GLOBAL_OPT must handle quoted `-c` values with
        // embedded whitespace, e.g. `-c "core.editor=vim -w"`.
        let cls = classify_command(r#"git -c "core.editor=vim -w" merge --no-ff foo"#);
        assert!(
            matches!(
                cls,
                Classification::Supported {
                    category: "Git",
                    ..
                }
            ),
            "expected Supported Git, got {cls:?}"
        );
    }

    #[test]
    fn test_classify_find_not_blocked_by_fi() {
        // Regression: "fi" in IGNORED_PREFIXES used to shadow "find" commands
        // because "find".starts_with("fi") is true. "fi" should only match exactly.
        assert_eq!(
            classify_command("find . -name foo"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler find",
                category: "Files",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_fi_still_ignored_exact() {
        // Bare "fi" (shell keyword) should still be ignored
        assert_eq!(classify_command("fi"), Classification::Ignored);
    }

    #[test]
    fn test_done_still_ignored_exact() {
        // Bare "done" (shell keyword) should still be ignored
        assert_eq!(classify_command("done"), Classification::Ignored);
    }

    #[test]
    fn test_split_chain_and() {
        assert_eq!(split_command_chain("a && b"), vec!["a", "b"]);
    }

    #[test]
    fn test_split_chain_semicolon() {
        assert_eq!(split_command_chain("a ; b"), vec!["a", "b"]);
    }

    #[test]
    fn test_split_pipe_first_only() {
        assert_eq!(split_command_chain("a | b"), vec!["a"]);
    }

    #[test]
    fn test_split_single() {
        assert_eq!(split_command_chain("git status"), vec!["git status"]);
    }

    #[test]
    fn test_split_quoted_and() {
        assert_eq!(
            split_command_chain(r#"echo "a && b""#),
            vec![r#"echo "a && b""#]
        );
    }

    #[test]
    fn test_split_heredoc_no_split() {
        let cmd = "cat <<'EOF'\nhello && world\nEOF";
        assert_eq!(split_command_chain(cmd), vec![cmd]);
    }

    #[test]
    fn test_classify_mypy() {
        assert_eq!(
            classify_command("mypy src/"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler mypy",
                category: "Build",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_python_m_mypy() {
        assert_eq!(
            classify_command("python3 -m mypy --strict"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler mypy",
                category: "Build",
                estimated_savings_pct: 80.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    // --- rewrite_command tests ---

    #[test]
    fn test_rewrite_git_status() {
        assert_eq!(
            rewrite_command_no_prefixes("git status", &[]),
            Some("contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_git_log() {
        assert_eq!(
            rewrite_command_no_prefixes("git log -10", &[]),
            Some("contextcrawler git log -10".into())
        );
    }

    // --- git -C <path> support (#555) ---

    #[test]
    fn test_rewrite_git_dash_c_status() {
        assert_eq!(
            rewrite_command_no_prefixes("git -C /path/to/repo status", &[]),
            Some("contextcrawler git -C /path/to/repo status".into())
        );
    }

    #[test]
    fn test_rewrite_git_dash_c_log() {
        assert_eq!(
            rewrite_command_no_prefixes("git -C /tmp/myrepo log --oneline -5", &[]),
            Some("contextcrawler git -C /tmp/myrepo log --oneline -5".into())
        );
    }

    #[test]
    fn test_rewrite_git_dash_c_diff() {
        assert_eq!(
            rewrite_command_no_prefixes("git -C /home/user/project diff --name-only", &[]),
            Some("contextcrawler git -C /home/user/project diff --name-only".into())
        );
    }

    #[test]
    fn test_classify_git_dash_c() {
        let result = classify_command("git -C /tmp status");
        assert!(
            matches!(
                result,
                Classification::Supported {
                    ctxcrl_equivalent: "contextcrawler git",
                    ..
                }
            ),
            "git -C should be classified as supported, got: {:?}",
            result
        );
    }

    #[test]
    fn test_rewrite_cargo_test() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test", &[]),
            Some("contextcrawler cargo test".into())
        );
    }

    // --- cargo +toolchain (rustup selector) ---

    #[test]
    fn test_classify_cargo_toolchain() {
        // `cargo +nightly test` classifies the SAME as `cargo test`: the
        // selector is stripped for classification (capture 1 = "test").
        assert_eq!(
            classify_command("cargo +nightly test"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                category: "Cargo",
                estimated_savings_pct: 90.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_rewrite_cargo_toolchain_preserved() {
        // `cargo +nightly test` rewrites like `cargo test` but KEEPS `+nightly`
        // so the spawned command runs against the requested toolchain.
        assert_eq!(
            rewrite_command_no_prefixes("cargo +nightly test", &[]),
            Some("contextcrawler cargo +nightly test".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("cargo +stable build --release", &[]),
            Some("contextcrawler cargo +stable build --release".into())
        );
    }

    #[test]
    fn test_strip_cargo_toolchain_helper() {
        assert_eq!(strip_cargo_toolchain("cargo +nightly test"), "cargo test");
        assert_eq!(
            strip_cargo_toolchain("cargo +1.75.0 build --release"),
            "cargo build --release"
        );
        // Non-regression: a plain cargo command is untouched.
        assert_eq!(strip_cargo_toolchain("cargo test"), "cargo test");
        // Non-regression: not a cargo command — left alone.
        assert_eq!(strip_cargo_toolchain("git status"), "git status");
    }

    #[test]
    fn test_rewrite_cargo_no_toolchain_unchanged() {
        // Non-regression: plain `cargo test` still rewrites as before.
        assert_eq!(
            rewrite_command_no_prefixes("cargo test", &[]),
            Some("contextcrawler cargo test".into())
        );
    }

    #[test]
    fn test_rewrite_compound_and() {
        assert_eq!(
            rewrite_command_no_prefixes("git add . && cargo test", &[]),
            Some("contextcrawler git add . && contextcrawler cargo test".into())
        );
    }

    #[test]
    fn test_rewrite_compound_three_segments() {
        assert_eq!(
            rewrite_command_no_prefixes(
                "cargo fmt --all && cargo clippy --all-targets && cargo test",
                &[]
            ),
            Some("contextcrawler cargo fmt --all && contextcrawler cargo clippy --all-targets && contextcrawler cargo test".into())
        );
    }

    #[test]
    fn test_rewrite_already_ctxcrl() {
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler git status", &[]),
            Some("contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_already_ctxcrl_shell_builtin_strips_prefix() {
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler cd /tmp", &[]),
            Some("cd /tmp".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("rtk export FOO=bar", &[]),
            Some("export FOO=bar".into())
        );
        // `contextcrawler read` is a real ContextCrawler command, not the shell builtin.
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler read README.md", &[]),
            Some("contextcrawler read README.md".into())
        );
    }

    #[test]
    fn test_rewrite_compound_ctxcrl_shell_builtin_strips_prefix() {
        // #2508 (compound): a builtin segment must lose its redundant
        // CTXCRL prefix so it runs in the current shell, while sibling
        // segments still get rewritten.
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler cd /tmp && git status", &[]),
            Some("cd /tmp && contextcrawler git status".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("rtk export FOO=bar && ls", &[]),
            Some("export FOO=bar && contextcrawler ls".into())
        );
        // `contextcrawler read` is a real CTXCRL command, not the `read`
        // builtin — it must survive untouched inside a compound.
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler read README.md && git status", &[]),
            Some("contextcrawler read README.md && contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_background_single_amp() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test & git status", &[]),
            Some("contextcrawler cargo test & contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_background_unsupported_right() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test & htop", &[]),
            Some("contextcrawler cargo test & htop".into())
        );
    }

    #[test]
    fn test_rewrite_background_does_not_affect_double_amp() {
        // `&&` must still work after adding `&` support
        assert_eq!(
            rewrite_command_no_prefixes("cargo test && git status", &[]),
            Some("contextcrawler cargo test && contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_unsupported_returns_none() {
        assert_eq!(rewrite_command_no_prefixes("htop", &[]), None);
    }

    #[test]
    fn test_rewrite_ignored_cd() {
        assert_eq!(rewrite_command_no_prefixes("cd /tmp", &[]), None);
    }

    #[test]
    fn test_rewrite_with_env_prefix() {
        assert_eq!(
            rewrite_command_no_prefixes("GIT_SSH_COMMAND=ssh git push", &[]),
            Some("GIT_SSH_COMMAND=ssh contextcrawler git push".into())
        );
    }

    #[test]
    fn test_rewrite_tsc() {
        let commands = vec![
            "npm exec tsc",
            "npm rum tsc",
            "npm run tsc",
            "npm run-script tsc",
            "npm urn tsc",
            "npm x tsc",
            "pnpm dlx tsc",
            "pnpm exec tsc",
            "pnpm run tsc",
            "pnpm run-script tsc",
            "npm tsc",
            "npx tsc",
            "pnpm tsc",
            "pnpx tsc",
            "tsc",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(&format!("{command} --noEmit"), &[]),
                Some("contextcrawler tsc --noEmit".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_cat_file() {
        assert_eq!(
            rewrite_command_no_prefixes("cat src/main.rs", &[]),
            Some("contextcrawler read src/main.rs".into())
        );
    }

    #[test]
    fn test_rewrite_cat_with_incompatible_flags_skipped() {
        // cat flags with different semantics than contextcrawler read — skip rewrite
        assert_eq!(rewrite_command_no_prefixes("cat -A file.cpp", &[]), None);
        assert_eq!(rewrite_command_no_prefixes("cat -v file.txt", &[]), None);
        assert_eq!(rewrite_command_no_prefixes("cat -e file.txt", &[]), None);
        assert_eq!(rewrite_command_no_prefixes("cat -t file.txt", &[]), None);
        assert_eq!(rewrite_command_no_prefixes("cat -s file.txt", &[]), None);
        assert_eq!(
            rewrite_command_no_prefixes("cat --show-all file.txt", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_cat_with_compatible_flags() {
        // cat -n (line numbers) maps to contextcrawler read -n — allow rewrite
        assert_eq!(
            rewrite_command_no_prefixes("cat -n file.txt", &[]),
            Some("contextcrawler read -n file.txt".into())
        );
    }

    #[test]
    fn test_rewrite_rg_pattern() {
        assert_eq!(
            rewrite_command_no_prefixes("rg \"fn main\"", &[]),
            Some("contextcrawler rg \"fn main\"".into())
        );
    }

    #[test]
    fn test_rewrite_playwright() {
        let commands = vec![
            "npm exec playwright",
            "npm rum playwright",
            "npm run playwright",
            "npm run-script playwright",
            "npm urn playwright",
            "npm x playwright",
            "pnpm dlx playwright",
            "pnpm exec playwright",
            "pnpm run playwright",
            "pnpm run-script playwright",
            "npm playwright",
            "npx playwright",
            "pnpm playwright",
            "pnpx playwright",
            "playwright",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(&format!("{command} test"), &[]),
                Some("contextcrawler playwright test".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_next_build() {
        let commands = vec![
            "npm exec next build",
            "npm rum next build",
            "npm run next build",
            "npm run-script next build",
            "npm urn next build",
            "npm x next build",
            "pnpm dlx next build",
            "pnpm exec next build",
            "pnpm run next build",
            "pnpm run-script next build",
            "npm next build",
            "npx next build",
            "pnpm next build",
            "pnpx next build",
            "next build",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(&format!("{command} --turbo"), &[]),
                Some("contextcrawler next --turbo".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_pipe_first_only() {
        // #166: a command whose stdout is piped MUST NOT be rewritten.
        // The pipeline consumer (here, `grep feat`) depends on the producer's
        // exact output format; replacing `git log -10` with `contextcrawler
        // git log -10` would change the producer's bytes and silently change
        // the consumer's answer. Leave the whole pipeline raw.
        assert_eq!(
            rewrite_command_no_prefixes("git log -10 | grep feat", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_find_pipe_skipped() {
        // find in a pipe should NOT be rewritten — contextcrawler find output format
        // is incompatible with pipe consumers like xargs (#439)
        assert_eq!(
            rewrite_command_no_prefixes("find . -name '*.rs' | xargs grep 'fn run'", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_find_pipe_xargs_wc() {
        assert_eq!(
            rewrite_command_no_prefixes("find src -type f | wc -l", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_find_no_pipe_still_rewritten() {
        // find WITHOUT a pipe should still be rewritten
        assert_eq!(
            rewrite_command_no_prefixes("find . -name '*.rs'", &[]),
            Some("contextcrawler find . -name '*.rs'".into())
        );
    }

    #[test]
    fn test_rewrite_heredoc_returns_none() {
        assert_eq!(
            rewrite_command_no_prefixes("cat <<'EOF'\nfoo\nEOF", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_empty_returns_none() {
        assert_eq!(rewrite_command_no_prefixes("", &[]), None);
        assert_eq!(rewrite_command_no_prefixes("   ", &[]), None);
    }

    #[test]
    fn test_rewrite_mixed_compound_partial() {
        // First segment already CTXCRL, second gets rewritten
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler git add . && cargo test", &[]),
            Some("contextcrawler git add . && contextcrawler cargo test".into())
        );
    }

    // --- #345: RTK_DISABLED ---

    #[test]
    fn test_rewrite_ctxcrl_disabled_curl() {
        assert_eq!(
            rewrite_command_no_prefixes("RTK_DISABLED=1 curl https://example.com", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_ctxcrl_disabled_git_status() {
        assert_eq!(
            rewrite_command_no_prefixes("RTK_DISABLED=1 git status", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_ctxcrl_disabled_multi_env() {
        assert_eq!(
            rewrite_command_no_prefixes("FOO=1 RTK_DISABLED=1 git status", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_ctxcrl_disabled_warns_on_stderr() {
        assert_eq!(
            rewrite_command_no_prefixes("RTK_DISABLED=1 git status", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_ctxcrl_disabled_subprocess_warns() {
        let ctxcrl_bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join("rtk");
        if !ctxcrl_bin.exists() {
            return;
        }
        let ctxcrl_mtime = std::fs::metadata(&ctxcrl_bin)
            .ok()
            .and_then(|m| m.modified().ok());
        let test_mtime = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());
        if let (Some(ctxcrl_t), Some(test_t)) = (ctxcrl_mtime, test_mtime) {
            if ctxcrl_t < test_t {
                return;
            }
        }

        let output = std::process::Command::new(&ctxcrl_bin)
            .args(["rewrite", "RTK_DISABLED=1 git status"])
            .output()
            .expect("Failed to run rtk");

        assert!(
            !output.status.success(),
            "Should exit non-zero (no rewrite)"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("RTK_DISABLED=1 detected"),
            "Should warn on stderr, got: {}",
            stderr
        );
    }

    #[test]
    fn test_rewrite_non_ctxcrl_disabled_env_still_rewrites() {
        assert_eq!(
            rewrite_command_no_prefixes("SOME_VAR=1 git status", &[]),
            Some("SOME_VAR=1 contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_env_quoted_value_with_spaces() {
        assert_eq!(
            rewrite_command_no_prefixes(
                r#"GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git push"#,
                &[]
            ),
            Some(
                r#"GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" contextcrawler git push"#
                    .into()
            )
        );
    }

    #[test]
    fn test_rewrite_env_single_quoted_value_with_spaces() {
        assert_eq!(
            rewrite_command_no_prefixes("EDITOR='vim -u NONE' git commit", &[]),
            Some("EDITOR='vim -u NONE' contextcrawler git commit".into())
        );
    }

    #[test]
    fn test_rewrite_env_quoted_plus_unquoted() {
        assert_eq!(
            rewrite_command_no_prefixes(r#"FOO="bar baz" BAR=1 git status"#, &[]),
            Some(r#"FOO="bar baz" BAR=1 contextcrawler git status"#.into())
        );
    }

    #[test]
    fn test_rewrite_env_escaped_quotes_in_value() {
        assert_eq!(
            rewrite_command_no_prefixes(r#"FOO="he said \"hello\"" git status"#, &[]),
            Some(r#"FOO="he said \"hello\"" contextcrawler git status"#.into())
        );
    }

    #[test]
    fn test_classify_env_quoted_value_stripped() {
        assert_eq!(
            classify_command(r#"GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git push"#),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    // --- #346: 2>&1 and &> redirect detection ---

    #[test]
    fn test_rewrite_redirect_2_gt_amp_1_with_pipe() {
        // #166: stdout (including the merged stderr) is piped to `head`
        // — the producer must stay raw.
        assert_eq!(
            rewrite_command_no_prefixes("cargo test 2>&1 | head", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_redirect_2_gt_amp_1_trailing() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test 2>&1", &[]),
            Some("contextcrawler cargo test 2>&1".into())
        );
    }

    #[test]
    fn test_rewrite_redirect_plain_2_devnull() {
        // 2>/dev/null has no `&`, never broken — non-regression
        assert_eq!(
            rewrite_command_no_prefixes("git status 2>/dev/null", &[]),
            Some("contextcrawler git status 2>/dev/null".into())
        );
    }

    #[test]
    fn test_rewrite_redirect_2_gt_amp_1_with_and() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test 2>&1 && echo done", &[]),
            Some("contextcrawler cargo test 2>&1 && echo done".into())
        );
    }

    #[test]
    fn test_rewrite_redirect_amp_gt_devnull() {
        // #166: `&>` redirects BOTH stdout and stderr to a file. The user
        // asked for the raw bytes in the file — must not rewrite.
        assert_eq!(
            rewrite_command_no_prefixes("cargo test &>/dev/null", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_redirect_double() {
        // #166: `2>&1 >/dev/null` — the trailing `>/dev/null` redirects
        // stdout to a file, so the user wanted raw bytes in /dev/null
        // (or wherever). Must not rewrite.
        assert_eq!(
            rewrite_command_no_prefixes("git status 2>&1 >/dev/null", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_redirect_fd_close() {
        // 2>&- (close stderr fd)
        assert_eq!(
            rewrite_command_no_prefixes("git status 2>&-", &[]),
            Some("contextcrawler git status 2>&-".into())
        );
    }

    #[test]
    fn test_rewrite_redirect_quotes_not_stripped() {
        // Redirect-like chars inside quotes should NOT be stripped
        // Known limitation: apostrophes cause conservative no-strip (safe fallback)
        let result = rewrite_command_no_prefixes("git commit -m \"it's fixed\" 2>&1", &[]);
        assert!(
            result.is_some(),
            "Should still rewrite even with apostrophe"
        );
    }

    #[test]
    fn test_rewrite_background_amp_non_regression() {
        // background `&` must still work after redirect fix
        assert_eq!(
            rewrite_command_no_prefixes("cargo test & git status", &[]),
            Some("contextcrawler cargo test & contextcrawler git status".into())
        );
    }

    // --- P0.2: head -N rewrite ---

    #[test]
    fn test_rewrite_head_numeric_flag() {
        // head -20 file → contextcrawler read file --max-lines 20 (not contextcrawler read -20 file)
        assert_eq!(
            rewrite_command_no_prefixes("head -20 src/main.rs", &[]),
            Some("contextcrawler read src/main.rs --max-lines 20".into())
        );
    }

    #[test]
    fn test_rewrite_head_lines_long_flag() {
        assert_eq!(
            rewrite_command_no_prefixes("head --lines=50 src/lib.rs", &[]),
            Some("contextcrawler read src/lib.rs --max-lines 50".into())
        );
    }

    #[test]
    fn test_rewrite_head_n_space_flag() {
        // `head -n 5 file` — space form, parity with `tail -n 5 file`.
        assert_eq!(
            rewrite_command_no_prefixes("head -n 5 src/main.rs", &[]),
            Some("contextcrawler read src/main.rs --max-lines 5".into())
        );
    }

    #[test]
    fn test_rewrite_head_lines_space_flag() {
        // `head --lines 7 file` — space form, parity with `tail --lines 7 file`.
        assert_eq!(
            rewrite_command_no_prefixes("head --lines 7 src/lib.rs", &[]),
            Some("contextcrawler read src/lib.rs --max-lines 7".into())
        );
    }

    #[test]
    fn test_rewrite_head_n_space_multi_file_skipped() {
        // Non-regression: multi-file `head -n N a b` still skips (single-file only).
        assert_eq!(
            rewrite_command_no_prefixes("head -n 5 /tmp/a /tmp/b", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_head_no_flag_still_rewrites() {
        // plain `head file` → `contextcrawler read file` (no numeric flag)
        assert_eq!(
            rewrite_command_no_prefixes("head src/main.rs", &[]),
            Some("contextcrawler read src/main.rs".into())
        );
    }

    #[test]
    fn test_rewrite_head_other_flag_skipped() {
        // head -c 100 file: unsupported flag, skip rewriting
        assert_eq!(
            rewrite_command_no_prefixes("head -c 100 src/main.rs", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_tail_numeric_flag() {
        assert_eq!(
            rewrite_command_no_prefixes("tail -20 src/main.rs", &[]),
            Some("contextcrawler read src/main.rs --tail-lines 20".into())
        );
    }

    #[test]
    fn test_rewrite_tail_n_space_flag() {
        assert_eq!(
            rewrite_command_no_prefixes("tail -n 12 src/lib.rs", &[]),
            Some("contextcrawler read src/lib.rs --tail-lines 12".into())
        );
    }

    #[test]
    fn test_rewrite_tail_lines_long_flag() {
        assert_eq!(
            rewrite_command_no_prefixes("tail --lines=7 src/lib.rs", &[]),
            Some("contextcrawler read src/lib.rs --tail-lines 7".into())
        );
    }

    #[test]
    fn test_rewrite_tail_lines_space_flag() {
        assert_eq!(
            rewrite_command_no_prefixes("tail --lines 7 src/lib.rs", &[]),
            Some("contextcrawler read src/lib.rs --tail-lines 7".into())
        );
    }

    #[test]
    fn test_rewrite_tail_other_flag_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("tail -c 100 src/main.rs", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_tail_plain_file_skipped() {
        assert_eq!(rewrite_command_no_prefixes("tail src/main.rs", &[]), None);
    }

    // --- Issue #1362: head/tail with multiple files falls back to native command ---
    //
    // `contextcrawler read <file> --max-lines N` only accepts a single positional file path in
    // a shape that maps cleanly to `head -N`. Rewriting `head -N a b c` to
    // `contextcrawler read a b c --max-lines N` previously produced a command where `contextcrawler read`
    // would concatenate the files without the `==> name <==` banners that native
    // `head` emits, so the fix is to skip the rewrite and let the shell run the
    // real `head`/`tail` binary.

    #[test]
    fn test_rewrite_head_numeric_flag_multi_file_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("head -3 /tmp/a /tmp/b /tmp/c", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_head_lines_long_flag_multi_file_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("head --lines=50 src/main.rs src/lib.rs", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_tail_numeric_flag_multi_file_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("tail -20 a.log b.log", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_tail_n_space_flag_multi_file_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("tail -n 12 a.log b.log c.log", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_tail_lines_eq_multi_file_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("tail --lines=7 a.log b.log", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_tail_lines_space_multi_file_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("tail --lines 7 a.log b.log", &[]),
            None
        );
    }

    // --- New registry entries ---

    #[test]
    fn test_classify_gh_release() {
        assert!(matches!(
            classify_command("gh release list"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler gh",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_glab_mr() {
        assert!(matches!(
            classify_command("glab mr list"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler glab",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_glab_ci() {
        assert!(matches!(
            classify_command("glab ci list"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler glab",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_glab_release() {
        assert!(matches!(
            classify_command("glab release list"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler glab",
                ..
            }
        ));
    }

    #[test]
    fn test_rewrite_glab_mr_list() {
        assert_eq!(
            rewrite_command_no_prefixes("glab mr list", &[]),
            Some("contextcrawler glab mr list".into())
        );
    }

    #[test]
    fn test_rewrite_glab_ci_status() {
        assert_eq!(
            rewrite_command_no_prefixes("glab ci status", &[]),
            Some("contextcrawler glab ci status".into())
        );
    }

    #[test]
    fn test_classify_cargo_install() {
        assert!(matches!(
            classify_command("cargo install rtk"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler cargo",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_docker_run() {
        assert!(matches!(
            classify_command("docker run --rm ubuntu bash"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler docker",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_docker_exec() {
        assert!(matches!(
            classify_command("docker exec -it mycontainer bash"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler docker",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_docker_build() {
        assert!(matches!(
            classify_command("docker build -t myimage ."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler docker",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_kubectl_describe() {
        assert!(matches!(
            classify_command("kubectl describe pod mypod"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler kubectl",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_kubectl_apply() {
        assert!(matches!(
            classify_command("kubectl apply -f deploy.yaml"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler kubectl",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_tree() {
        assert!(matches!(
            classify_command("tree src/"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler tree",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_diff() {
        assert!(matches!(
            classify_command("diff file1.txt file2.txt"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler diff",
                ..
            }
        ));
    }

    #[test]
    fn test_rewrite_tree() {
        assert_eq!(
            rewrite_command_no_prefixes("tree src/", &[]),
            Some("contextcrawler tree src/".into())
        );
    }

    #[test]
    fn test_rewrite_diff() {
        assert_eq!(
            rewrite_command_no_prefixes("diff file1.txt file2.txt", &[]),
            Some("contextcrawler diff file1.txt file2.txt".into())
        );
    }

    #[test]
    fn test_rewrite_gh_release() {
        assert_eq!(
            rewrite_command_no_prefixes("gh release list", &[]),
            Some("contextcrawler gh release list".into())
        );
    }

    #[test]
    fn test_rewrite_cargo_install() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo install rtk", &[]),
            Some("contextcrawler cargo install rtk".into())
        );
    }

    #[test]
    fn test_rewrite_kubectl_describe() {
        assert_eq!(
            rewrite_command_no_prefixes("kubectl describe pod mypod", &[]),
            Some("contextcrawler kubectl describe pod mypod".into())
        );
    }

    #[test]
    fn test_rewrite_docker_run() {
        assert_eq!(
            rewrite_command_no_prefixes("docker run --rm ubuntu bash", &[]),
            Some("contextcrawler docker run --rm ubuntu bash".into())
        );
    }

    #[test]
    fn test_classify_swift_test() {
        assert!(matches!(
            classify_command("swift test"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler swift",
                category: "Build",
                estimated_savings_pct: 90.0,
                status: CtxcrlStatus::Existing,
            }
        ));
    }

    #[test]
    fn test_rewrite_swift_test() {
        assert_eq!(
            rewrite_command_no_prefixes("swift test --parallel", &[]),
            Some("contextcrawler swift test --parallel".into())
        );
    }

    // --- #336: docker compose supported subcommands rewritten, unsupported skipped ---

    #[test]
    fn test_rewrite_docker_compose_ps() {
        assert_eq!(
            rewrite_command_no_prefixes("docker compose ps", &[]),
            Some("contextcrawler docker compose ps".into())
        );
    }

    #[test]
    fn test_rewrite_docker_compose_logs() {
        assert_eq!(
            rewrite_command_no_prefixes("docker compose logs web", &[]),
            Some("contextcrawler docker compose logs web".into())
        );
    }

    #[test]
    fn test_rewrite_docker_compose_build() {
        assert_eq!(
            rewrite_command_no_prefixes("docker compose build", &[]),
            Some("contextcrawler docker compose build".into())
        );
    }

    #[test]
    fn test_rewrite_docker_compose_up_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("docker compose up -d", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_docker_compose_down_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("docker compose down", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_docker_compose_config_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("docker compose -f foo.yaml config --services", &[]),
            None
        );
    }

    // --- AWS / psql (PR #216) ---

    #[test]
    fn test_classify_aws() {
        assert!(matches!(
            classify_command("aws s3 ls"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler aws",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_aws_ec2() {
        assert!(matches!(
            classify_command("aws ec2 describe-instances"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler aws",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_psql() {
        assert!(matches!(
            classify_command("psql -U postgres"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler psql",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_psql_url() {
        assert!(matches!(
            classify_command("psql postgres://localhost/mydb"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler psql",
                ..
            }
        ));
    }

    #[test]
    fn test_rewrite_aws() {
        assert_eq!(
            rewrite_command_no_prefixes("aws s3 ls", &[]),
            Some("contextcrawler aws s3 ls".into())
        );
    }

    #[test]
    fn test_rewrite_aws_ec2() {
        assert_eq!(
            rewrite_command_no_prefixes("aws ec2 describe-instances --region us-east-1", &[]),
            Some("contextcrawler aws ec2 describe-instances --region us-east-1".into())
        );
    }

    #[test]
    fn test_rewrite_psql() {
        assert_eq!(
            rewrite_command_no_prefixes("psql -U postgres -d mydb", &[]),
            Some("contextcrawler psql -U postgres -d mydb".into())
        );
    }

    // --- Python tooling ---

    #[test]
    fn test_classify_ruff_check() {
        assert!(matches!(
            classify_command("ruff check ."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler ruff",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_ruff_format() {
        assert!(matches!(
            classify_command("ruff format src/"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler ruff",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_pytest() {
        assert!(matches!(
            classify_command("pytest tests/"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler pytest",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_python_m_pytest() {
        assert!(matches!(
            classify_command("python -m pytest tests/"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler pytest",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_pip_list() {
        assert!(matches!(
            classify_command("pip list"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler pip",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_uv_pip_list() {
        assert!(matches!(
            classify_command("uv pip list"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler pip",
                ..
            }
        ));
    }

    #[test]
    fn test_rewrite_ruff_check() {
        assert_eq!(
            rewrite_command_no_prefixes("ruff check .", &[]),
            Some("contextcrawler ruff check .".into())
        );
    }

    #[test]
    fn test_rewrite_ruff_format() {
        assert_eq!(
            rewrite_command_no_prefixes("ruff format src/", &[]),
            Some("contextcrawler ruff format src/".into())
        );
    }

    #[test]
    fn test_rewrite_pytest() {
        assert_eq!(
            rewrite_command_no_prefixes("pytest tests/", &[]),
            Some("contextcrawler pytest tests/".into())
        );
    }

    #[test]
    fn test_rewrite_python_m_pytest() {
        assert_eq!(
            rewrite_command_no_prefixes("python -m pytest -x tests/", &[]),
            Some("contextcrawler pytest -x tests/".into())
        );
    }

    #[test]
    fn test_rewrite_pip_list() {
        assert_eq!(
            rewrite_command_no_prefixes("pip list", &[]),
            Some("contextcrawler pip list".into())
        );
    }

    #[test]
    fn test_rewrite_pip_outdated() {
        assert_eq!(
            rewrite_command_no_prefixes("pip outdated", &[]),
            Some("contextcrawler pip outdated".into())
        );
    }

    #[test]
    fn test_rewrite_uv_pip_list() {
        assert_eq!(
            rewrite_command_no_prefixes("uv pip list", &[]),
            Some("contextcrawler pip list".into())
        );
    }

    // --- Go tooling ---

    #[test]
    fn test_classify_go_test() {
        assert!(matches!(
            classify_command("go test ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler go",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_go_build() {
        assert!(matches!(
            classify_command("go build ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler go",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_go_vet() {
        assert!(matches!(
            classify_command("go vet ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler go",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint() {
        assert!(matches!(
            classify_command("golangci-lint run"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint -v run ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_value_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint --color never run ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_inline_value_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint --color=never run ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_inline_config_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint --config=foo.yml run ./..."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_bare_is_not_compact_wrapper() {
        assert!(!matches!(
            classify_command("golangci-lint"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_other_subcommand_is_not_compact_wrapper() {
        assert!(!matches!(
            classify_command("golangci-lint version"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_rewrite_go_test() {
        assert_eq!(
            rewrite_command_no_prefixes("go test ./...", &[]),
            Some("contextcrawler go test ./...".into())
        );
    }

    #[test]
    fn test_rewrite_go_build() {
        assert_eq!(
            rewrite_command_no_prefixes("go build ./...", &[]),
            Some("contextcrawler go build ./...".into())
        );
    }

    #[test]
    fn test_rewrite_go_vet() {
        assert_eq!(
            rewrite_command_no_prefixes("go vet ./...", &[]),
            Some("contextcrawler go vet ./...".into())
        );
    }

    #[test]
    fn test_rewrite_golangci_lint() {
        assert_eq!(
            rewrite_command_no_prefixes("golangci-lint run ./...", &[]),
            Some("contextcrawler golangci-lint run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_golangci_lint_with_flag_before_run() {
        assert_eq!(
            rewrite_command_no_prefixes("golangci-lint -v run ./...", &[]),
            Some("contextcrawler golangci-lint -v run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_golangci_lint_with_value_flag_before_run() {
        assert_eq!(
            rewrite_command_no_prefixes("golangci-lint --color never run ./...", &[]),
            Some("contextcrawler golangci-lint --color never run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_golangci_lint_with_inline_value_flag_before_run() {
        assert_eq!(
            rewrite_command_no_prefixes("golangci-lint --color=never run ./...", &[]),
            Some("contextcrawler golangci-lint --color=never run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_golangci_lint_with_inline_config_flag_before_run() {
        assert_eq!(
            rewrite_command_no_prefixes("golangci-lint --config=foo.yml run ./...", &[]),
            Some("contextcrawler golangci-lint --config=foo.yml run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_env_prefixed_golangci_lint_with_value_flag_before_run() {
        assert_eq!(
            rewrite_command_no_prefixes("FOO=1 golangci-lint --color never run ./...", &[]),
            Some("FOO=1 contextcrawler golangci-lint --color never run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_env_prefixed_golangci_lint_with_inline_value_flag_before_run() {
        assert_eq!(
            rewrite_command_no_prefixes("FOO=1 golangci-lint --color=never run ./...", &[]),
            Some("FOO=1 contextcrawler golangci-lint --color=never run ./...".into())
        );
    }

    #[test]
    fn test_rewrite_bare_golangci_lint_skips_compact_wrapper() {
        assert_eq!(rewrite_command_no_prefixes("golangci-lint", &[]), None);
    }

    #[test]
    fn test_rewrite_other_golangci_lint_subcommand_skips_compact_wrapper() {
        assert_eq!(
            rewrite_command_no_prefixes("golangci-lint version", &[]),
            None
        );
    }

    // --- JS/TS tooling ---

    #[test]
    fn test_classify_lint() {
        let commands = vec![
            "npm exec biome",
            "npm exec eslint",
            "npm rum biome",
            "npm rum eslint",
            "npm rum lint",
            "npm run biome",
            "npm run eslint",
            "npm run lint",
            "npm run-script biome",
            "npm run-script eslint",
            "npm run-script lint",
            "npm urn biome",
            "npm urn eslint",
            "npm urn lint",
            "npm x biome",
            "npm x eslint",
            "pnpm dlx biome",
            "pnpm dlx eslint",
            "pnpm exec biome",
            "pnpm exec eslint",
            "pnpm run biome",
            "pnpm run eslint",
            "pnpm run lint",
            "pnpm run-script biome",
            "pnpm run-script eslint",
            "pnpm run-script lint",
            "npm biome",
            "npm eslint",
            "npm lint",
            "npx biome",
            "npx eslint",
            "npx lint",
            "pnpm biome",
            "pnpm eslint",
            "pnpm lint",
            "pnpx biome",
            "pnpx eslint",
            "pnpx lint",
            "biome",
            "eslint",
            "lint",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(command),
                    Classification::Supported {
                        ctxcrl_equivalent: "contextcrawler lint",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_lint() {
        let commands = vec![
            "npm exec biome",
            "npm exec eslint",
            "npm rum biome",
            "npm rum eslint",
            "npm rum lint",
            "npm run biome",
            "npm run eslint",
            "npm run lint",
            "npm run-script biome",
            "npm run-script eslint",
            "npm run-script lint",
            "npm urn biome",
            "npm urn eslint",
            "npm urn lint",
            "npm x biome",
            "npm x eslint",
            "pnpm dlx biome",
            "pnpm dlx eslint",
            "pnpm exec biome",
            "pnpm exec eslint",
            "pnpm run biome",
            "pnpm run eslint",
            "pnpm run lint",
            "pnpm run-script biome",
            "pnpm run-script eslint",
            "pnpm run-script lint",
            "npm biome",
            "npm eslint",
            "npm lint",
            "npx biome",
            "npx eslint",
            "npx lint",
            "pnpm biome",
            "pnpm eslint",
            "pnpm lint",
            "pnpx biome",
            "pnpx eslint",
            "pnpx lint",
            "biome",
            "eslint",
            "lint",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(command, &[]),
                Some("contextcrawler lint".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_classify_jest() {
        let commands = vec![
            "jest run",
            "jest",
            "npm exec jest run",
            "npm exec jest",
            "npm jest run",
            "npm jest",
            "npm rum jest run",
            "npm rum jest",
            "npm run jest run",
            "npm run jest",
            "npm run-script jest run",
            "npm run-script jest",
            "npm urn jest run",
            "npm urn jest",
            "npm x jest run",
            "npm x jest",
            "npx jest run",
            "npx jest",
            "pnpm dlx jest run",
            "pnpm dlx jest",
            "pnpm exec jest run",
            "pnpm exec jest",
            "pnpm jest run",
            "pnpm jest",
            "pnpm run jest run",
            "pnpm run jest",
            "pnpm run-script jest run",
            "pnpm run-script jest",
            "pnpx jest run",
            "pnpx jest",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(command),
                    Classification::Supported {
                        ctxcrl_equivalent: "contextcrawler jest",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_jest() {
        let commands = vec![
            "jest run",
            "jest",
            "npm exec jest run",
            "npm exec jest",
            "npm jest run",
            "npm jest",
            "npm rum jest run",
            "npm rum jest",
            "npm run jest run",
            "npm run jest",
            "npm run-script jest run",
            "npm run-script jest",
            "npm urn jest run",
            "npm urn jest",
            "npm x jest run",
            "npm x jest",
            "npx jest run",
            "npx jest",
            "pnpm dlx jest run",
            "pnpm dlx jest",
            "pnpm exec jest run",
            "pnpm exec jest",
            "pnpm jest run",
            "pnpm jest",
            "pnpm run jest run",
            "pnpm run jest",
            "pnpm run-script jest run",
            "pnpm run-script jest",
            "pnpx jest run",
            "pnpx jest",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(command, &[]),
                Some("contextcrawler jest".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_classify_vitest() {
        let commands = vec![
            "npm exec vitest run",
            "npm exec vitest",
            "npm rum vitest run",
            "npm rum vitest",
            "npm run vitest run",
            "npm run vitest",
            "npm run-script vitest run",
            "npm run-script vitest",
            "npm urn vitest run",
            "npm urn vitest",
            "npm vitest run",
            "npm vitest",
            "npm x vitest run",
            "npm x vitest",
            "npx vitest run",
            "npx vitest",
            "pnpm dlx vitest run",
            "pnpm dlx vitest",
            "pnpm exec vitest run",
            "pnpm exec vitest",
            "pnpm run vitest run",
            "pnpm run vitest",
            "pnpm run-script vitest run",
            "pnpm run-script vitest",
            "pnpm vitest run",
            "pnpm vitest",
            "pnpx vitest run",
            "pnpx vitest",
            "vitest run",
            "vitest",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(command),
                    Classification::Supported {
                        ctxcrl_equivalent: "contextcrawler vitest",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_vitest() {
        let commands = vec![
            "npm exec vitest run",
            "npm exec vitest",
            "npm rum vitest run",
            "npm rum vitest",
            "npm run vitest run",
            "npm run vitest",
            "npm run-script vitest run",
            "npm run-script vitest",
            "npm urn vitest run",
            "npm urn vitest",
            "npm vitest run",
            "npm vitest",
            "npm x vitest run",
            "npm x vitest",
            "npx vitest run",
            "npx vitest",
            "pnpm dlx vitest run",
            "pnpm dlx vitest",
            "pnpm exec vitest run",
            "pnpm exec vitest",
            "pnpm run vitest run",
            "pnpm run vitest",
            "pnpm run-script vitest run",
            "pnpm run-script vitest",
            "pnpm vitest run",
            "pnpm vitest",
            "pnpx vitest run",
            "pnpx vitest",
            "vitest run",
            "vitest",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(command, &[]),
                Some("contextcrawler vitest".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_classify_prisma() {
        let commands = vec![
            "npm exec prisma",
            "npm rum prisma",
            "npm run prisma",
            "npm run-script prisma",
            "npm urn prisma",
            "npm x prisma",
            "pnpm dlx prisma",
            "pnpm exec prisma",
            "pnpm run prisma",
            "pnpm run-script prisma",
            "npm prisma",
            "npx prisma",
            "pnpm prisma",
            "pnpx prisma",
            "prisma",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(format!("{command} migrate dev").as_str()),
                    Classification::Supported {
                        ctxcrl_equivalent: "contextcrawler prisma",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_prisma() {
        let commands = vec![
            "npm exec prisma",
            "npm rum prisma",
            "npm run prisma",
            "npm run-script prisma",
            "npm urn prisma",
            "npm x prisma",
            "pnpm dlx prisma",
            "pnpm exec prisma",
            "pnpm run prisma",
            "pnpm run-script prisma",
            "npm prisma",
            "npx prisma",
            "pnpm prisma",
            "pnpx prisma",
            "prisma",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(format!("{command} migrate dev").as_str(), &[]),
                Some("contextcrawler prisma migrate dev".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_prettier() {
        let commands = vec![
            "npm exec prettier",
            "npm rum prettier",
            "npm run prettier",
            "npm run-script prettier",
            "npm urn prettier",
            "npm x prettier",
            "pnpm dlx prettier",
            "pnpm exec prettier",
            "pnpm run prettier",
            "pnpm run-script prettier",
            "npm prettier",
            "npx prettier",
            "pnpm prettier",
            "pnpx prettier",
            "prettier",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(format!("{command} --check src/").as_str(), &[]),
                Some("contextcrawler prettier --check src/".into()),
                "Failed for command: {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_pnpm_command() {
        let commands = vec![
            "exec",
            "i",
            "install",
            "list",
            "ls",
            "outdated",
            "run",
            "run-script",
        ];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(format!("pnpm {command}").as_str(), &[]),
                Some(format!("contextcrawler pnpm {command}")),
                "Failed for command: pnpm {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_npm_bare_subcommand() {
        let commands = vec!["exec", "run", "run-script", "x"];
        for command in commands {
            assert_eq!(
                rewrite_command_no_prefixes(format!("npm {command}").as_str(), &[]),
                Some(format!("contextcrawler npm {command}")),
                "Failed for bare command: npm {}",
                command
            );
        }
    }

    #[test]
    fn test_rewrite_npm_with_args() {
        assert_eq!(
            rewrite_command_no_prefixes("npm run test", &[]),
            Some("contextcrawler npm run test".to_string()),
        );
        assert_eq!(
            rewrite_command_no_prefixes("npm exec vitest", &[]),
            Some("contextcrawler vitest".to_string()),
        );
    }

    #[test]
    fn test_rewrite_npx() {
        assert_eq!(
            rewrite_command_no_prefixes("npx svgo", &[]),
            Some("contextcrawler npx svgo".to_string()),
        );
    }

    // --- Gradle ---

    #[test]
    fn test_classify_gradlew() {
        assert!(matches!(
            classify_command("./gradlew assembleDebug"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_gradlew_no_dot_slash() {
        assert!(matches!(
            classify_command("gradlew build"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_gradlew_bat() {
        assert!(matches!(
            classify_command("gradlew.bat clean"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_gradle() {
        assert!(matches!(
            classify_command("gradle build"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_rewrite_gradlew() {
        assert_eq!(
            rewrite_command_no_prefixes("./gradlew assembleDebug", &[]),
            Some("contextcrawler gradlew assembleDebug".into())
        );
    }

    #[test]
    fn test_rewrite_gradlew_no_dot_slash() {
        assert_eq!(
            rewrite_command_no_prefixes("gradlew build", &[]),
            Some("contextcrawler gradlew build".into())
        );
    }

    #[test]
    fn test_rewrite_gradlew_bat() {
        assert_eq!(
            rewrite_command_no_prefixes("gradlew.bat clean", &[]),
            Some("contextcrawler gradlew clean".into())
        );
    }

    #[test]
    fn test_rewrite_gradle() {
        assert_eq!(
            rewrite_command_no_prefixes("gradle build", &[]),
            Some("contextcrawler gradlew build".into())
        );
    }

    #[test]
    fn test_rewrite_gradlew_test_savings() {
        assert_eq!(
            classify_command("./gradlew test"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler gradlew",
                category: "Build",
                estimated_savings_pct: 90.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    // --- Compound operator edge cases ---

    #[test]
    fn test_rewrite_compound_or() {
        // `||` fallback: left rewritten, right rewritten
        assert_eq!(
            rewrite_command_no_prefixes("cargo test || cargo build", &[]),
            Some("contextcrawler cargo test || contextcrawler cargo build".into())
        );
    }

    #[test]
    fn test_rewrite_compound_semicolon() {
        assert_eq!(
            rewrite_command_no_prefixes("git status; cargo test", &[]),
            Some("contextcrawler git status; contextcrawler cargo test".into())
        );
    }

    #[test]
    fn test_rewrite_compound_pipe_raw_filter() {
        // #166: pipeline producer must stay raw, otherwise the consumer
        // sees filtered bytes and silently produces a wrong answer.
        assert_eq!(
            rewrite_command_no_prefixes("cargo test | grep FAILED", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_compound_pipe_git_grep() {
        // #166: same — the producer stays raw inside a pipeline.
        assert_eq!(
            rewrite_command_no_prefixes("git log -10 | grep feat", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_compound_four_segments() {
        assert_eq!(
            rewrite_command_no_prefixes(
                "cargo fmt --all && cargo clippy && cargo test && git status",
                &[]
            ),
            Some(
                "contextcrawler cargo fmt --all && contextcrawler cargo clippy && contextcrawler cargo test && contextcrawler git status"
                    .into()
            )
        );
    }

    #[test]
    fn test_rewrite_compound_mixed_supported_unsupported() {
        // unsupported segments stay raw
        assert_eq!(
            rewrite_command_no_prefixes("cargo test && htop", &[]),
            Some("contextcrawler cargo test && htop".into())
        );
    }

    #[test]
    fn test_rewrite_compound_all_unsupported_returns_none() {
        // No rewrite at all: returns None
        assert_eq!(rewrite_command_no_prefixes("htop && top", &[]), None);
    }

    // --- sudo / env prefix + rewrite ---

    #[test]
    fn test_rewrite_sudo_docker() {
        assert_eq!(
            rewrite_command_no_prefixes("sudo docker ps", &[]),
            Some("sudo contextcrawler docker ps".into())
        );
    }

    #[test]
    fn test_rewrite_env_var_prefix() {
        assert_eq!(
            rewrite_command_no_prefixes("GIT_SSH_COMMAND=ssh git push origin main", &[]),
            Some("GIT_SSH_COMMAND=ssh contextcrawler git push origin main".into())
        );
    }

    // --- find with native flags ---

    #[test]
    fn test_rewrite_find_with_flags() {
        assert_eq!(
            rewrite_command_no_prefixes("find . -name '*.rs' -type f", &[]),
            Some("contextcrawler find . -name '*.rs' -type f".into())
        );
    }

    #[test]
    fn test_all_rules_are_complete() {
        for rule in RULES {
            assert!(
                !rule.pattern.is_empty(),
                "Rule '{}' has empty pattern",
                rule.ctxcrl_cmd
            );
            assert!(
                !rule.ctxcrl_cmd.is_empty(),
                "Rule with empty ctxcrl_cmd found"
            );
            assert!(
                rule.ctxcrl_cmd.starts_with("contextcrawler "),
                "ctxcrl_cmd '{}' must start with 'contextcrawler ' (#62)",
                rule.ctxcrl_cmd
            );
            assert!(
                !rule.rewrite_prefixes.is_empty(),
                "Rule '{}' has no rewrite_prefixes",
                rule.ctxcrl_cmd
            );
        }
    }

    // --- exclude_commands (#243) ---

    #[test]
    fn test_rewrite_excludes_curl() {
        let excluded = vec!["curl".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("curl https://api.example.com/health", &excluded),
            None
        );
    }

    #[test]
    fn test_rewrite_exclude_does_not_affect_other_commands() {
        let excluded = vec!["curl".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("git status", &excluded),
            Some("contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_empty_excludes_rewrites_curl() {
        let excluded: Vec<String> = vec![];
        assert!(rewrite_command_no_prefixes("curl https://api.example.com", &excluded).is_some());
    }

    #[test]
    fn test_rewrite_compound_partial_exclude() {
        // curl excluded but git still rewrites
        let excluded = vec!["curl".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("git status && curl https://api.example.com", &excluded),
            Some("contextcrawler git status && curl https://api.example.com".into())
        );
    }

    #[test]
    fn test_exclude_env_prefixed_command() {
        let excluded = vec!["psql".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("PGPASSWORD=postgres psql -h localhost", &excluded),
            None
        );
    }

    #[test]
    fn test_exclude_subcommand_pattern() {
        let excluded = vec!["git push".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("git push origin main", &excluded),
            None
        );
    }

    #[test]
    fn test_exclude_regex_pattern() {
        let excluded = vec!["^curl".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("curl http://example.com", &excluded),
            None
        );
    }

    #[test]
    fn test_exclude_invalid_regex_fallback() {
        let excluded = vec!["curl[".to_string()];
        assert!(rewrite_command_no_prefixes("curl http://example.com", &excluded).is_some());
    }

    #[test]
    fn test_exclude_does_not_substring_match() {
        let excluded = vec!["go".to_string()];
        assert!(rewrite_command_no_prefixes("golangci-lint run ./...", &excluded).is_some());
    }

    #[test]
    fn test_exclude_does_not_match_hyphenated_command() {
        let excluded = vec!["golangci".to_string()];
        assert!(rewrite_command_no_prefixes("golangci-lint run ./...", &excluded).is_some());
    }

    #[test]
    fn test_exclude_empty_pattern_ignored() {
        let excluded = vec!["".to_string()];
        assert!(rewrite_command_no_prefixes("git status", &excluded).is_some());
    }

    #[test]
    fn test_exclude_bare_anchor_ignored() {
        let excluded = vec!["^".to_string()];
        assert!(rewrite_command_no_prefixes("git status", &excluded).is_some());
    }

    #[test]
    fn test_all_patterns_are_valid_regex() {
        use regex::Regex;
        for (i, rule) in RULES.iter().enumerate() {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "RULES[{i}] ({}) has invalid pattern '{}'",
                rule.ctxcrl_cmd,
                rule.pattern
            );
        }
    }

    // --- #196: gh --json/--jq/--template passthrough ---

    #[test]
    fn test_rewrite_gh_json_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("gh pr list --json number,title", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_gh_jq_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("gh pr list --json number --jq '.[].number'", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_gh_template_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("gh pr view 42 --template '{{.title}}'", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_gh_api_json_skipped() {
        assert_eq!(
            rewrite_command_no_prefixes("gh api repos/owner/repo --jq '.name'", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_gh_without_json_still_works() {
        assert_eq!(
            rewrite_command_no_prefixes("gh pr list", &[]),
            Some("contextcrawler gh pr list".into())
        );
    }

    // --- #508: RTK_DISABLED detection helpers ---

    #[test]
    fn test_cmd_has_ctxcrl_disabled_prefix() {
        assert!(cmd_has_ctxcrl_disabled_prefix("RTK_DISABLED=1 git status"));
        assert!(cmd_has_ctxcrl_disabled_prefix(
            "FOO=1 RTK_DISABLED=1 cargo test"
        ));
        assert!(cmd_has_ctxcrl_disabled_prefix(
            "RTK_DISABLED=true git log --oneline"
        ));
        assert!(!cmd_has_ctxcrl_disabled_prefix("git status"));
        assert!(!cmd_has_ctxcrl_disabled_prefix("contextcrawler git status"));
        assert!(!cmd_has_ctxcrl_disabled_prefix("SOME_VAR=1 git status"));
    }

    // --- G7/#100: RTK_DISABLED key must be matched exactly, not as a substring ---

    #[test]
    fn test_ctxcrl_disabled_substring_does_not_bypass() {
        // A crafted prefix where RTK_DISABLED= appears inside another var's
        // VALUE must NOT count as setting RTK_DISABLED.
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            "FOO=RTK_DISABLED=1 git status"
        ));
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            "X=a RTK_DISABLED_NOT=1 git status"
        ));
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            "MY_RTK_DISABLED=1 git status"
        ));
        // ...and rewriting must still happen for the crafted prefix.
        assert_eq!(
            rewrite_command_no_prefixes("FOO=RTK_DISABLED=1 git status", &[]),
            Some("FOO=RTK_DISABLED=1 contextcrawler git status".into())
        );
    }

    #[test]
    fn test_quoted_env_value_cannot_inject_disable() {
        // #229 (council): a quoted env value containing spaces must not be
        // whitespace-split into a standalone RTK_DISABLED/CTXCRL_DISABLED token.
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            r#"FOO="bar RTK_DISABLED=1" git status"#
        ));
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            r#"FOO='x CTXCRL_DISABLED=1' git status"#
        ));
        // ...and the command must still be rewritten (proxy not disabled).
        assert!(
            rewrite_command_no_prefixes(r#"FOO="bar RTK_DISABLED=1" git status"#, &[]).is_some()
        );
    }

    #[test]
    fn test_real_ctxcrl_disabled_still_bypasses() {
        // A genuine RTK_DISABLED=1 assignment must still disable rewriting.
        assert!(cmd_has_ctxcrl_disabled_prefix("RTK_DISABLED=1 git status"));
        assert_eq!(
            rewrite_command_no_prefixes("RTK_DISABLED=1 git status", &[]),
            None
        );
        // ...even when preceded by other (innocuous) assignments.
        assert!(cmd_has_ctxcrl_disabled_prefix(
            "FOO=bar RTK_DISABLED=1 git status"
        ));
        assert_eq!(
            rewrite_command_no_prefixes("FOO=bar RTK_DISABLED=1 git status", &[]),
            None
        );
    }

    // --- Branding migration: BOTH the canonical CTXCRL_DISABLED and the legacy
    // RTK_DISABLED prefixes must disable rewriting (back-compat shim). ---

    #[test]
    fn test_both_disable_prefixes_bypass() {
        // Canonical name (new).
        assert!(cmd_has_ctxcrl_disabled_prefix(
            "CTXCRL_DISABLED=1 git status"
        ));
        assert_eq!(
            rewrite_command_no_prefixes("CTXCRL_DISABLED=1 git status", &[]),
            None
        );
        // Legacy name (deprecated, still honoured).
        assert!(cmd_has_ctxcrl_disabled_prefix("RTK_DISABLED=1 git status"));
        assert_eq!(
            rewrite_command_no_prefixes("RTK_DISABLED=1 git status", &[]),
            None
        );
        // Crafted substring of the canonical key must NOT bypass.
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            "FOO=CTXCRL_DISABLED=1 git status"
        ));
        assert!(!cmd_has_ctxcrl_disabled_prefix(
            "CTXCRL_DISABLED_NOT=1 git status"
        ));
    }

    // --- G7/#100: only TRUE absolute paths are normalised to a bare binary ---

    #[test]
    fn test_relative_path_not_normalised() {
        // `./git` and `repo/bin/git` are not the system binary — they must
        // NOT be normalised to `git` and rewritten.
        assert_eq!(strip_absolute_path("./git status"), "./git status");
        assert_eq!(
            strip_absolute_path("repo/bin/git status"),
            "repo/bin/git status"
        );
        assert_eq!(rewrite_command_no_prefixes("./git status", &[]), None);
        assert_eq!(
            rewrite_command_no_prefixes("repo/bin/git status", &[]),
            None
        );
    }

    #[test]
    fn test_absolute_path_still_normalised() {
        // Regression guard: a real absolute path still strips to the binary.
        assert_eq!(strip_absolute_path("/usr/bin/git status"), "git status");
    }

    #[test]
    fn test_strip_disabled_prefix() {
        assert_eq!(
            strip_disabled_prefix("RTK_DISABLED=1 git status"),
            ("RTK_DISABLED=1 ", "git status")
        );
        assert_eq!(
            strip_disabled_prefix("FOO=1 RTK_DISABLED=1 cargo test"),
            ("FOO=1 RTK_DISABLED=1 ", "cargo test")
        );
        assert_eq!(strip_disabled_prefix("git status"), ("", "git status"));
    }

    // --- #485: absolute path normalization ---

    #[test]
    fn test_classify_absolute_path_grep() {
        assert_eq!(
            classify_command("/usr/bin/grep -rni pattern"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler grep",
                category: "Files",
                estimated_savings_pct: 75.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_absolute_path_ls() {
        assert_eq!(
            classify_command("/bin/ls -la"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler ls",
                category: "Files",
                estimated_savings_pct: 65.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_absolute_path_git() {
        assert_eq!(
            classify_command("/usr/local/bin/git status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_absolute_path_no_args() {
        // /usr/bin/find alone → still classified
        assert_eq!(
            classify_command("/usr/bin/find ."),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler find",
                category: "Files",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_strip_absolute_path_helper() {
        assert_eq!(strip_absolute_path("/usr/bin/grep -rn foo"), "grep -rn foo");
        assert_eq!(strip_absolute_path("/bin/ls -la"), "ls -la");
        assert_eq!(strip_absolute_path("grep -rn foo"), "grep -rn foo");
        assert_eq!(strip_absolute_path("/usr/local/bin/git"), "git");
    }

    // --- #163: git global options ---

    #[test]
    fn test_classify_git_with_dash_c_path() {
        assert_eq!(
            classify_command("git -C /tmp status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_git_no_pager_log() {
        assert_eq!(
            classify_command("git --no-pager log -5"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_git_git_dir() {
        assert_eq!(
            classify_command("git --git-dir /tmp/.git status"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_rewrite_git_dash_c() {
        assert_eq!(
            rewrite_command_no_prefixes("git -C /tmp status", &[]),
            Some("contextcrawler git -C /tmp status".to_string())
        );
    }

    #[test]
    fn test_rewrite_git_no_pager() {
        assert_eq!(
            rewrite_command_no_prefixes("git --no-pager log -5", &[]),
            Some("contextcrawler git --no-pager log -5".to_string())
        );
    }

    #[test]
    fn test_strip_git_global_opts_helper() {
        assert_eq!(strip_git_global_opts("git -C /tmp status"), "git status");
        assert_eq!(strip_git_global_opts("git --no-pager log"), "git log");
        assert_eq!(strip_git_global_opts("git status"), "git status");
        assert_eq!(strip_git_global_opts("cargo test"), "cargo test");
    }

    #[test]
    fn test_strip_golangci_global_opts_helper() {
        assert_eq!(
            strip_golangci_global_opts("golangci-lint -v run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint --color never run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint --color=never run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint --config=foo.yml run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint version"),
            "golangci-lint version"
        );
        assert_eq!(strip_golangci_global_opts("cargo test"), "cargo test");
    }

    // --- #wc: wc filter was silently ignored by the hook ---

    #[test]
    fn test_classify_wc_supported() {
        // BUG: "wc " was in IGNORED_PREFIXES despite wc_cmd.rs having a full filter.
        // This test documents the bug: it must FAIL before the fix and PASS after.
        assert_eq!(
            classify_command("wc -l src/main.rs"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler wc",
                category: "Files",
                estimated_savings_pct: 60.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_wc_multi_file() {
        assert_eq!(
            classify_command("wc src/*.rs"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler wc",
                category: "Files",
                estimated_savings_pct: 60.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_rewrite_wc() {
        assert_eq!(
            rewrite_command_no_prefixes("wc -l src/main.rs", &[]),
            Some("contextcrawler wc -l src/main.rs".into())
        );
    }

    #[test]
    fn test_rewrite_wc_multi_file() {
        assert_eq!(
            rewrite_command_no_prefixes("wc src/*.rs", &[]),
            Some("contextcrawler wc src/*.rs".into())
        );
    }

    #[test]
    fn test_classify_command_substitution_passthrough() {
        assert_eq!(
            classify_command("git log $(git rev-parse HEAD~1)"),
            Classification::Supported {
                ctxcrl_equivalent: "contextcrawler git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: CtxcrlStatus::Existing,
            }
        );
    }

    #[test]
    fn test_rewrite_command_substitution_passthrough() {
        // #166: a command containing $(...) executes the inner in a
        // subshell whose output is interpolated as an arg. Rewriting
        // the outer to `contextcrawler git log $(...)` would route the
        // inner result through the contextcrawler filter, which may
        // mangle the resolved arg (e.g. a commit hash with surrounding
        // commit metadata). Fail closed: leave the whole thing raw.
        assert_eq!(
            rewrite_command_no_prefixes("git log $(git rev-parse HEAD~1)", &[]),
            None
        );
    }

    #[test]
    fn test_split_command_substitution_no_split() {
        assert_eq!(
            split_command_chain("git log $(git rev-parse HEAD~1)"),
            vec!["git log $(git rev-parse HEAD~1)"]
        );
    }

    #[test]
    fn test_shell_prefix_noglob() {
        assert_eq!(
            rewrite_command_no_prefixes("noglob git status", &[]),
            Some("noglob contextcrawler git status".into())
        );
    }

    #[test]
    fn test_shell_prefix_command() {
        assert_eq!(
            rewrite_command_no_prefixes("command git status", &[]),
            Some("command contextcrawler git status".into())
        );
    }

    #[test]
    fn test_shell_prefix_builtin_exec_nocorrect() {
        assert_eq!(
            rewrite_command_no_prefixes("builtin git status", &[]),
            Some("builtin contextcrawler git status".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("exec git status", &[]),
            Some("exec contextcrawler git status".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("nocorrect git status", &[]),
            Some("nocorrect contextcrawler git status".into())
        );
    }

    #[test]
    fn test_shell_prefix_unknown_inner() {
        assert_eq!(
            rewrite_command_no_prefixes("noglob unknown_cmd --flag", &[]),
            None
        );
    }

    // --- transparent_prefixes tests ---

    #[test]
    fn test_transparent_prefix_strips_and_reprepends() {
        let prefixes = vec!["shadowenv exec --".to_string()];
        assert_eq!(
            super::rewrite_command("shadowenv exec -- git status", &[], &prefixes),
            Some("shadowenv exec -- contextcrawler git status".into())
        );
    }

    #[test]
    fn test_transparent_prefix_with_test_runner() {
        let prefixes = vec!["shadowenv exec --".to_string()];
        assert_eq!(
            super::rewrite_command("shadowenv exec -- cargo test", &[], &prefixes),
            Some("shadowenv exec -- contextcrawler cargo test".into())
        );
    }

    #[test]
    fn test_transparent_prefix_unknown_inner_returns_none() {
        let prefixes = vec!["shadowenv exec --".to_string()];
        assert_eq!(
            super::rewrite_command("shadowenv exec -- htop", &[], &prefixes),
            None
        );
    }

    #[test]
    fn test_transparent_prefix_not_matched_is_passthrough() {
        // Without the prefix configured, the wrapper breaks routing.
        assert_eq!(
            super::rewrite_command("shadowenv exec -- git status", &[], &[]),
            None
        );
    }

    #[test]
    fn test_transparent_prefix_composed_with_builtin() {
        // `noglob shadowenv exec -- git status` — builtin layer strips noglob,
        // user layer strips shadowenv exec --, inner `git status` routes.
        let prefixes = vec!["shadowenv exec --".to_string()];
        assert_eq!(
            super::rewrite_command("noglob shadowenv exec -- git status", &[], &prefixes),
            Some("noglob shadowenv exec -- contextcrawler git status".into())
        );
    }

    #[test]
    fn test_transparent_prefix_composed_with_env_prefix() {
        let prefixes = vec!["bundle exec".to_string()];
        assert_eq!(
            super::rewrite_command("RAILS_ENV=test bundle exec git status", &[], &prefixes),
            Some("RAILS_ENV=test bundle exec contextcrawler git status".into())
        );
    }

    #[test]
    fn test_env_prefix_composed_with_builtin() {
        assert_eq!(
            rewrite_command_no_prefixes("sudo noglob git status", &[]),
            Some("sudo noglob contextcrawler git status".into())
        );
    }

    #[test]
    fn test_transparent_prefix_multiple_configured() {
        let prefixes = vec!["shadowenv exec --".to_string(), "direnv exec .".to_string()];
        assert_eq!(
            super::rewrite_command("direnv exec . git status", &[], &prefixes),
            Some("direnv exec . contextcrawler git status".into())
        );
    }

    #[test]
    fn test_transparent_prefixes_normalize_once() {
        let prefixes = vec![
            "  docker exec mycontainer  ".to_string(),
            "".to_string(),
            "docker".to_string(),
            "docker exec mycontainer".to_string(),
        ];
        assert_eq!(
            normalize_transparent_prefixes(&prefixes),
            vec!["docker exec mycontainer".to_string(), "docker".to_string()]
        );
    }

    #[test]
    fn test_transparent_prefix_overlapping_entries_use_longest_match() {
        let prefixes = vec!["docker".to_string(), "docker exec app".to_string()];
        assert_eq!(
            super::rewrite_command("docker exec app git status", &[], &prefixes),
            Some("docker exec app contextcrawler git status".into())
        );
    }

    #[test]
    fn test_transparent_prefix_whole_word_matching() {
        // A prefix `"foo"` must NOT match `"foobar git status"`.
        let prefixes = vec!["foo".to_string()];
        assert_eq!(
            super::rewrite_command("foobar git status", &[], &prefixes),
            None
        );
    }

    #[test]
    fn test_transparent_prefix_empty_rest_returns_none() {
        let prefixes = vec!["shadowenv exec --".to_string()];
        assert_eq!(
            super::rewrite_command("shadowenv exec --", &[], &prefixes),
            None
        );
    }

    #[test]
    fn test_transparent_prefix_empty_entry_is_skipped() {
        // A blank entry in the config should not cause spurious matches or panics.
        let prefixes = vec!["".to_string(), "   ".to_string()];
        assert_eq!(
            super::rewrite_command("git status", &[], &prefixes),
            Some("contextcrawler git status".into())
        );
    }

    #[test]
    fn test_transparent_prefix_inside_compound() {
        // Each segment of `&&` / `;` should independently get prefix-stripped.
        let prefixes = vec!["shadowenv exec --".to_string()];
        assert_eq!(
            super::rewrite_command(
                "shadowenv exec -- git status && shadowenv exec -- cargo test",
                &[],
                &prefixes
            ),
            Some("shadowenv exec -- contextcrawler git status && shadowenv exec -- contextcrawler cargo test".into())
        );
    }

    #[test]
    fn test_transparent_prefix_respects_excluded() {
        // An excluded inner command should still produce no rewrite even behind
        // a transparent prefix.
        let prefixes = vec!["shadowenv exec --".to_string()];
        let excluded = vec!["git".to_string()];
        assert_eq!(
            super::rewrite_command("shadowenv exec -- git status", &excluded, &prefixes),
            None
        );
    }

    #[test]
    fn test_transparent_prefix_recursion_bounded() {
        // A prefix that could recurse forever (e.g. one that maps to itself)
        // must terminate once MAX_PREFIX_DEPTH is reached.
        let prefixes = vec!["wrap".to_string()];
        let mut cmd = String::new();
        for _ in 0..(MAX_PREFIX_DEPTH + 2) {
            cmd.push_str("wrap ");
        }
        cmd.push_str("git status");
        // Doesn't matter exactly what it returns — just that it doesn't stack-
        // overflow or loop forever. Exercise the code path.
        let _ = super::rewrite_command(&cmd, &[], &prefixes);
    }

    #[test]
    fn test_python3_m_pytest() {
        assert_eq!(
            rewrite_command_no_prefixes("python3 -m pytest tests/", &[]),
            Some("contextcrawler pytest tests/".into())
        );
    }

    #[test]
    fn test_pip_show() {
        assert_eq!(
            rewrite_command_no_prefixes("pip show flask", &[]),
            Some("contextcrawler pip show flask".into())
        );
    }

    #[test]
    fn test_gt_graphite() {
        assert_eq!(
            rewrite_command_no_prefixes("gt log", &[]),
            Some("contextcrawler gt log".into())
        );
    }

    #[test]
    fn test_command_no_longer_ignored() {
        assert_ne!(
            classify_command("command git status"),
            Classification::Ignored
        );
    }

    // --- Pipe + operator rewrite ---

    #[test]
    fn test_rewrite_pipe_then_and() {
        // #166: the pipe branch (`git log | head -5`) stays raw; the `&&`
        // branch (`git stash`) is a separate simple command whose stdout
        // goes to the model — rewrite it normally.
        assert_eq!(
            rewrite_command_no_prefixes("git log | head -5 && git stash", &[]),
            Some("git log | head -5 && contextcrawler git stash".into())
        );
    }

    #[test]
    fn test_rewrite_pipe_then_semicolon() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test | head; git status", &[]),
            Some("cargo test | head; contextcrawler git status".into())
        );
    }

    #[test]
    fn test_rewrite_pipe_then_or() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test | grep FAIL || git stash", &[]),
            Some("cargo test | grep FAIL || contextcrawler git stash".into())
        );
    }

    #[test]
    fn test_rewrite_env_pipe_then_and() {
        // #166: env-prefixed pipeline producer also stays raw.
        assert_eq!(
            rewrite_command_no_prefixes(
                "RUST_BACKTRACE=1 cargo test 2>&1 | grep FAILED && git stash",
                &[]
            ),
            Some(
                "RUST_BACKTRACE=1 cargo test 2>&1 | grep FAILED && contextcrawler git stash".into()
            )
        );
    }

    #[test]
    fn test_rewrite_and_then_pipe() {
        // #166: left branch is a simple command with terminal stdout
        // (rewrite). Right branch is a pipeline producer (stay raw).
        assert_eq!(
            rewrite_command_no_prefixes("git status && cargo test | grep FAIL", &[]),
            Some("contextcrawler git status && cargo test | grep FAIL".into())
        );
    }

    #[test]
    fn test_rewrite_multi_pipe_then_and() {
        assert_eq!(
            rewrite_command_no_prefixes("git log | head | tail && git status", &[]),
            Some("git log | head | tail && contextcrawler git status".into())
        );
    }

    // --- #166: pipeline-safe + redirection-safe rewrite ---

    /// The original bug report. `grep ... | wc -l` MUST count the raw grep
    /// output, not the filtered output. Skip rewriting the pipeline
    /// producer entirely.
    #[test]
    fn issue_166_grep_into_wc_is_not_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes(r#"grep -R "fn " src/analytics | wc -l"#, &[]),
            None
        );
    }

    /// Stdout redirected to a file. The user explicitly asked for the raw
    /// bytes to land in the file, not the filtered ones.
    #[test]
    fn issue_166_stdout_redirect_is_not_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo check >/tmp/build.log", &[]),
            None
        );
    }

    #[test]
    fn issue_166_stdout_redirect_with_space_is_not_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("ls -la src > /tmp/f.txt", &[]),
            None
        );
    }

    #[test]
    fn issue_166_stdout_append_redirect_is_not_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("git status >> /tmp/log.txt", &[]),
            None
        );
    }

    #[test]
    fn issue_166_amp_gt_redirect_is_not_rewritten() {
        // `&>file` redirects BOTH stdout and stderr — must not rewrite.
        assert_eq!(
            rewrite_command_no_prefixes("cargo test &>/dev/null", &[]),
            None
        );
    }

    #[test]
    fn issue_166_amp_gt_gt_redirect_is_not_rewritten() {
        // `&>>file` is the append form of `&>` — both streams redirected.
        assert_eq!(
            rewrite_command_no_prefixes("cargo test &>>/tmp/log", &[]),
            None
        );
    }

    #[test]
    fn issue_166_explicit_fd1_redirect_is_not_rewritten() {
        // `1>file` is the same as `>file` — stdout to a file.
        assert_eq!(
            rewrite_command_no_prefixes("git status 1>/tmp/out", &[]),
            None
        );
    }

    #[test]
    fn issue_166_2_then_1_swap_then_devnull_not_rewritten() {
        // `2>&1 >/dev/null` — stdout to /dev/null, stderr to original
        // stdout (which is terminal). The `>` redirects stdout, so skip.
        assert_eq!(
            rewrite_command_no_prefixes("git status 2>&1 >/dev/null", &[]),
            None
        );
    }

    /// `2>file` redirects ONLY stderr. Stdout still goes to the model, so
    /// rewriting is safe. The filter is applied to stdout; stderr is
    /// untouched in either case.
    #[test]
    fn issue_166_stderr_only_redirect_is_still_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo check 2>/tmp/err.log", &[]),
            Some("contextcrawler cargo check 2>/tmp/err.log".into())
        );
    }

    /// `2>&1` alone (no other redirect) merges stderr INTO stdout. Stdout
    /// still goes to the model, so rewriting is safe.
    #[test]
    fn issue_166_stderr_to_stdout_merge_only_is_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("cargo test 2>&1", &[]),
            Some("contextcrawler cargo test 2>&1".into())
        );
    }

    /// `2>&-` closes stderr — stdout still goes to the model.
    #[test]
    fn issue_166_close_stderr_is_still_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("git status 2>&-", &[]),
            Some("contextcrawler git status 2>&-".into())
        );
    }

    /// Command substitution payload must not be rewritten — the outer
    /// `echo` already passes through `classify_command` as Unsupported
    /// (not in the rules table), but assert the outer result for any
    /// command shape we DO recognise.
    #[test]
    fn issue_166_command_substitution_is_not_rewritten() {
        // The outer `git status` is wrapped in $(...) for substitution.
        // Substitution payloads execute in a subshell that captures
        // stdout into the surrounding command — rewriting the inner
        // would silently change what `echo` prints.
        // Today this entire shape (echo $(...)) is Unsupported at the
        // outer level (echo is not in rules), so the rewrite returns
        // None. Guard that until/unless echo gets a filter; the inner
        // payload must not leak a rewrite either.
        assert_eq!(rewrite_command_no_prefixes("echo $(git status)", &[]), None);
    }

    #[test]
    fn issue_166_backtick_substitution_is_not_rewritten() {
        assert_eq!(rewrite_command_no_prefixes("echo `git status`", &[]), None);
    }

    #[test]
    fn issue_166_heredoc_is_not_rewritten() {
        // Pre-existing behaviour but assert it explicitly under #166.
        assert_eq!(
            rewrite_command_no_prefixes("cat <<EOF\nhello\nEOF", &[]),
            None
        );
    }

    /// Baseline that the fix does NOT regress: a simple `git status`
    /// with stdout going to the model still rewrites.
    #[test]
    fn issue_166_simple_command_still_rewrites() {
        assert_eq!(
            rewrite_command_no_prefixes("git status", &[]),
            Some("contextcrawler git status".into())
        );
    }

    /// `cmd1 && cmd2` where both branches are simple terminal-stdout
    /// commands — both rewrite.
    #[test]
    fn issue_166_and_chain_both_branches_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("git status && cargo check", &[]),
            Some("contextcrawler git status && contextcrawler cargo check".into())
        );
    }

    /// #195 supersedes the original #166 stance for the SIMPLE single-command
    /// case: `sh -lc 'git status'` now unwraps and rewrites the inner command
    /// (re-wrapped in the shell) so its output is filtered. The conservative
    /// "bypass" behaviour is retained for compound inner scripts — see
    /// `issue_195_rewrite_sh_c_compound_passthrough`.
    #[test]
    fn issue_166_195_nested_shell_simple_command_is_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("sh -lc 'git status'", &[]),
            Some("sh -lc 'contextcrawler git status'".into())
        );
    }

    /// Process substitution (`<(...)`, `>(...)`) — the outer command
    /// connects to the substitution via a pipe-like file descriptor.
    /// Rewriting the outer would change what the substitution reads.
    /// At minimum the inner payload must not leak a rewrite; today the
    /// outer command is whatever the user typed (often `diff` or `cat`
    /// — not in the rules table). Assert that a recognised outer with
    /// process substitution is not rewritten.
    #[test]
    fn issue_166_process_substitution_outer_not_rewritten() {
        // `diff <(git status) <(git status)` — `diff` is not in the
        // rules table, returns None. The behaviour we lock in here is
        // that a process substitution token does not cause the inner
        // `git status` to leak out as a rewrite of the whole command.
        let out = rewrite_command_no_prefixes("diff <(git status) <(git status)", &[]);
        assert!(
            out.is_none() || !out.as_deref().unwrap_or("").starts_with("contextcrawler "),
            "process substitution must not produce a rewrite of the outer command: {:?}",
            out
        );
    }

    // --- Security-review lockdown tests (codex + agy round, #166) ---
    //
    // The peer review verified the bug class is closed but flagged four edge
    // cases worth pinning in tests so a future lexer or rewrite-engine refactor
    // can't silently regress the guarantee.

    /// No-space chained redirect: `2>&1>file`. Agy hypothesised the lexer
    /// could emit a single `2>&1>file` token whose `strip_prefix("2>")`
    /// succeeds and trips fail-open. Verified in lexer.rs — the trailing `>`
    /// after `2>&1` starts a separate Redirect token, so
    /// `segment_stdout_is_redirected` sees the bare `>` and skips. Lock it in.
    #[test]
    fn issue_166_no_space_2to1_to_file_is_not_rewritten() {
        assert_eq!(
            rewrite_command_no_prefixes("git status 2>&1>/tmp/x", &[]),
            None
        );
    }

    /// `|&` is bash 4+ shorthand for `2>&1 |`. The lexer tokenises this as
    /// Pipe + Shellism rather than a single token, so the producer is not
    /// rewritten. Importantly, assert no corrupted `contextcrawler` token
    /// leaks into the right-hand side of the chain even when the producer
    /// would otherwise be a rewrite candidate.
    #[test]
    fn issue_166_amp_pipe_does_not_corrupt_rhs() {
        let out = rewrite_command_no_prefixes("cargo test |& head", &[]);
        // Must not produce a rewrite (producer is in a pipe), and must not
        // emit `contextcrawler` anywhere in the chain — that would mean the
        // engine spliced output halfway through a corrupted shell line.
        assert!(
            out.is_none() || !out.as_deref().unwrap_or("").contains("contextcrawler"),
            "|& shorthand must not corrupt the chain with a rewrite: {:?}",
            out
        );
    }

    /// Process substitution combined with a pipe consumer. The outer command
    /// (`cat`) is not in the rules table, but pinning the combined shape
    /// guards against a future change that adds `cat` to the rules table —
    /// the process-substitution + pipe combination must still skip rewrite.
    #[test]
    fn issue_166_process_subst_into_pipe_is_not_rewritten() {
        let out = rewrite_command_no_prefixes("cat <(git log) | head", &[]);
        assert!(
            out.is_none() || !out.as_deref().unwrap_or("").starts_with("contextcrawler "),
            "process subst piped into another command must not rewrite the outer: {:?}",
            out
        );
    }

    /// Pipe consumer carries a trailing stdout redirect: `git log | tee f > /dev/null`.
    /// The producer (`git log`) feeds `tee`, whose stdout goes to /dev/null.
    /// If the engine ever started inspecting only the last segment's redirect
    /// it could erroneously decide the chain is "safe to rewrite the producer".
    /// Producer in any pipeline must stay raw.
    #[test]
    fn issue_166_pipe_with_consumer_redirect_producer_stays_raw() {
        assert_eq!(
            rewrite_command_no_prefixes("git log | tee f > /dev/null", &[]),
            None
        );
    }

    // --- #195: wrapper-command unwrap (sh -c / bash -lc / sudo flags) ---

    #[test]
    fn issue_195_unwrap_sh_c_single_quote() {
        assert_eq!(
            unwrap_shell_wrapper("sh -c 'git status'"),
            Some(("sh -c '", '\'', "git status"))
        );
    }

    #[test]
    fn issue_195_unwrap_bash_lc_double_quote() {
        assert_eq!(
            unwrap_shell_wrapper(r#"bash -lc "cargo test""#),
            Some((r#"bash -lc ""#, '"', "cargo test"))
        );
    }

    #[test]
    fn issue_195_unwrap_zsh_ic() {
        assert_eq!(
            unwrap_shell_wrapper("zsh -ic 'git log'"),
            Some(("zsh -ic '", '\'', "git log"))
        );
    }

    #[test]
    fn issue_195_unwrap_compound_and_returns_none() {
        // `a && b` is a compound script — must NOT unwrap.
        assert_eq!(
            unwrap_shell_wrapper("sh -c 'git add . && cargo test'"),
            None
        );
    }

    #[test]
    fn issue_195_unwrap_pipe_returns_none() {
        assert_eq!(unwrap_shell_wrapper("sh -c 'git log | head'"), None);
    }

    #[test]
    fn issue_195_unwrap_semicolon_returns_none() {
        assert_eq!(unwrap_shell_wrapper("bash -c 'cd /tmp; ls'"), None);
    }

    #[test]
    fn issue_195_unwrap_subst_returns_none() {
        assert_eq!(unwrap_shell_wrapper("sh -c 'echo $(date)'"), None);
        assert_eq!(unwrap_shell_wrapper("sh -c 'git log `whoami`'"), None);
    }

    #[test]
    fn issue_195_unwrap_redirect_returns_none() {
        assert_eq!(unwrap_shell_wrapper("sh -c 'git log > out.txt'"), None);
    }

    #[test]
    fn issue_195_unwrap_glob_returns_none() {
        assert_eq!(unwrap_shell_wrapper("sh -c 'ls *.rs'"), None);
    }

    #[test]
    fn issue_195_unwrap_trailing_token_returns_none() {
        // A bare positional arg after the quoted script ($0/extra args) — the
        // inner isn't the whole command; refuse to unwrap.
        assert_eq!(unwrap_shell_wrapper("sh -c 'git status' extra"), None);
    }

    #[test]
    fn issue_195_unwrap_unmodelled_flag_returns_none() {
        // `-o pipefail` is not a flag we model — leave raw.
        assert_eq!(unwrap_shell_wrapper("bash -o pipefail -c 'git log'"), None);
        // Separate `-l -c` (not combined) — not modelled.
        assert_eq!(unwrap_shell_wrapper("bash -l -c 'git log'"), None);
        // `-s` reads from stdin, not an arg — not a wrapper we unwrap.
        assert_eq!(unwrap_shell_wrapper("sh -s 'git log'"), None);
    }

    #[test]
    fn issue_195_unwrap_empty_inner_returns_none() {
        assert_eq!(unwrap_shell_wrapper("sh -c ''"), None);
    }

    #[test]
    fn issue_195_rewrite_sh_c_git_log() {
        assert_eq!(
            rewrite_command_no_prefixes("sh -c 'git log'", &[]),
            Some("sh -c 'contextcrawler git log'".into())
        );
    }

    #[test]
    fn issue_195_rewrite_bash_lc_cargo_test() {
        assert_eq!(
            rewrite_command_no_prefixes(r#"bash -lc "cargo test""#, &[]),
            Some(r#"bash -lc "contextcrawler cargo test""#.into())
        );
    }

    #[test]
    fn issue_195_rewrite_sh_c_compound_passthrough() {
        // Compound inner must NOT rewrite — stays raw (None).
        assert_eq!(
            rewrite_command_no_prefixes("sh -c 'git add . && cargo test'", &[]),
            None
        );
    }

    #[test]
    fn issue_195_rewrite_sh_c_unsupported_inner_passthrough() {
        // Single but unsupported inner (`htop`) — nothing to rewrite, raw.
        assert_eq!(rewrite_command_no_prefixes("sh -c 'htop'", &[]), None);
    }

    #[test]
    fn issue_195_rewrite_sudo_flag_user_ls() {
        // `sudo -u x ls` — strip sudo+flags for classification, KEEP sudo on
        // the spawned command (privileges preserved).
        assert_eq!(
            rewrite_command_no_prefixes("sudo -u x ls", &[]),
            Some("sudo -u x contextcrawler ls".into())
        );
    }

    #[test]
    fn issue_195_rewrite_sudo_bare_still_works() {
        // Regression: bare `sudo <cmd>` (handled by ENV_PREFIX) unaffected.
        assert_eq!(
            rewrite_command_no_prefixes("sudo docker ps", &[]),
            Some("sudo contextcrawler docker ps".into())
        );
    }

    #[test]
    fn issue_195_rewrite_sudo_value_less_flags() {
        assert_eq!(
            rewrite_command_no_prefixes("sudo -E -H -u root cargo test", &[]),
            Some("sudo -E -H -u root contextcrawler cargo test".into())
        );
    }

    #[test]
    fn issue_195_rewrite_sudo_sh_c_combo() {
        // `sudo sh -c 'git log'` — sudo (bare, via ENV_PREFIX) then the shell
        // wrapper unwrap. sudo + wrapper both preserved.
        assert_eq!(
            rewrite_command_no_prefixes("sudo sh -c 'git log'", &[]),
            Some("sudo sh -c 'contextcrawler git log'".into())
        );
    }

    #[test]
    fn issue_195_rewrite_bare_sh_not_wrapper_unaffected() {
        // `sh script.sh` is not a `-c` wrapper — must stay raw (ignored prefix).
        assert_eq!(rewrite_command_no_prefixes("sh script.sh", &[]), None);
    }

    // --- line-continuation handling (upstream 2543be5 / #1564) ----------

    #[test]
    fn test_rewrite_internal_backslash_newline_matches_single_line() {
        // Claude Code emits long commands with a `\<NL>` between the subcommand
        // and its args; must rewrite to the same thing as the single-line form.
        let multiline = rewrite_command_no_prefixes("git diff \\\nHEAD~1 --stat", &[]);
        let single = rewrite_command_no_prefixes("git diff HEAD~1 --stat", &[]);
        assert_eq!(
            multiline,
            Some("contextcrawler git diff HEAD~1 --stat".into())
        );
        assert_eq!(multiline, single);
    }

    #[test]
    fn test_rewrite_leading_backslash_newline() {
        assert_eq!(
            rewrite_command_no_prefixes("\\\ngit diff HEAD~1", &[]),
            Some("contextcrawler git diff HEAD~1".into())
        );
    }

    #[test]
    fn test_rewrite_leading_backslash_crlf() {
        assert_eq!(
            rewrite_command_no_prefixes("\\\r\ngit diff HEAD~1", &[]),
            Some("contextcrawler git diff HEAD~1".into())
        );
    }

    #[test]
    fn test_rewrite_backslash_newline_with_indent() {
        assert_eq!(
            rewrite_command_no_prefixes("git \\\n    diff HEAD~1", &[]),
            Some("contextcrawler git diff HEAD~1".into())
        );
    }

    #[test]
    fn test_rewrite_no_line_continuation_unchanged() {
        assert_eq!(
            rewrite_command_no_prefixes("git diff HEAD~1", &[]),
            Some("contextcrawler git diff HEAD~1".into())
        );
    }

    #[test]
    fn test_collapse_line_continuations_borrows_when_no_match() {
        // Zero-alloc fast path: no continuation → borrowed, not owned.
        match collapse_line_continuations("git diff HEAD~1") {
            Cow::Borrowed(_) => {}
            Cow::Owned(_) => panic!("expected Cow::Borrowed for input without continuations"),
        }
    }

    #[test]
    fn test_collapse_line_continuations_collapses_to_single_space() {
        assert_eq!(
            collapse_line_continuations("git diff \\\nHEAD~1"),
            "git diff HEAD~1"
        );
    }

    // --- quote-aware continuation collapse (FIX 3) ----------------------

    #[test]
    fn test_collapse_preserves_single_quoted_backslash_newline() {
        // bash treats `\<LF>` literally inside single quotes — it is NOT a
        // continuation. The body must be left byte-for-byte intact so
        // `unwrap_shell_wrapper` extracts the script the user actually wrote.
        let input = "bash -c 'cargo \\\ntest'";
        let out = collapse_line_continuations(input);
        assert_eq!(out, input);
        // No allocation needed when the only continuation is quoted.
        match out {
            Cow::Borrowed(_) => {}
            Cow::Owned(_) => panic!("quoted-only continuation should borrow, not mutate"),
        }
    }

    #[test]
    fn test_collapse_preserves_double_quoted_backslash_newline() {
        // Conservative: double-quoted spans are left untouched too.
        let input = "echo \"a \\\nb\"";
        assert_eq!(collapse_line_continuations(input), input);
    }

    #[test]
    fn test_collapse_unquoted_still_collapses_with_quotes_present() {
        // An UNQUOTED continuation collapses even when quoted text is also
        // present elsewhere (quote state correctly closed before the `\<LF>`).
        assert_eq!(
            collapse_line_continuations("echo 'hi' \\\nthere"),
            "echo 'hi' there"
        );
    }

    #[test]
    fn test_rewrite_bash_c_single_quoted_continuation_not_mutated() {
        // End-to-end: a single-quoted wrapper body with a literal `\<LF>` is a
        // compound/odd inner script → unwrap_shell_wrapper bails → raw
        // passthrough (None). The key property is that the inner body is NOT
        // silently rewritten into a different command.
        assert_eq!(
            rewrite_command_no_prefixes("bash -c 'cargo \\\ntest'", &[]),
            None
        );
    }

    #[test]
    fn test_rewrite_unquoted_continuation_still_collapses_regression() {
        // #2543be5 non-regression: an UNQUOTED `\<LF>` continuation still
        // collapses so the command matches a rewrite rule.
        assert_eq!(
            rewrite_command_no_prefixes("git diff \\\nHEAD~1", &[]),
            Some("contextcrawler git diff HEAD~1".into())
        );
    }

    #[test]
    fn test_collapse_line_continuations_preserves_non_ascii() {
        // MEDIUM UTF-8 fix: the emit step must preserve multibyte UTF-8 exactly.
        // The old `out.push(c as char)` Latin-1-reinterpreted bytes >= 0x80,
        // mangling "café" → "cafÃ©" in the rewritten command. Round-trip an
        // unquoted continuation alongside non-ASCII text and a unicode path.
        assert_eq!(
            collapse_line_continuations("git commit -m café \\\n--author=x"),
            "git commit -m café --author=x"
        );
        assert_eq!(
            collapse_line_continuations("ls ./café/日本語 \\\n--all"),
            "ls ./café/日本語 --all"
        );
        // Emoji (4-byte sequence) survives too.
        assert_eq!(
            collapse_line_continuations("echo 🚀 \\\nthere"),
            "echo 🚀 there"
        );
    }
}
