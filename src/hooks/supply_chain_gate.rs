// SPDX-License-Identifier: MIT
// Part of the ContextCrawler downstream of rtk-ai/rtk.
// Copyright (c) 2026 ContextCrawler contributors.
//
//! Supply-chain pre-install gate.
//!
//! Detects npm/pnpm/yarn/pip/uv/poetry/pipx install commands in a bash
//! command string, queries the relevant registry (npm or PyPI) for the
//! latest version's publish time, and OSV.dev for known vulnerabilities.
//! Returns a Verdict the caller (hook_cmd / rewrite_cmd) uses to downgrade
//! the auto-allow decision when packages fail an age cooldown or carry
//! HIGH-severity CVEs.
//!
//! Empirical justification for defaults: see
//!   notes/research/supply-chain-audit-report.md
//! in the umbrella repo.
//!
//! Subprocess-free internal HTTP via `ureq` (already an rtk dep).

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration as StdDuration, Instant};

// ---------------------------------------------------------------------------
// SEC-I2: aggregate budget + package cap
// ---------------------------------------------------------------------------

/// Aggregate wall-clock budget for an entire `check()` call. Each registry /
/// OSV request carries its own 8s timeout; without an aggregate cap a command
/// installing many packages against a slow/hostile registry could stall the
/// hook for minutes. Once this budget is exceeded `check()` stops vetting and
/// fails closed to `Ask`/`Unavailable`.
const CHECK_WALL_BUDGET: StdDuration = StdDuration::from_secs(25);

/// Maximum number of distinct packages `check()` will vet in one command.
/// Beyond this the install is too large to vet within budget — fail closed to
/// `Ask` ("too many packages to vet") rather than issuing dozens of requests.
const MAX_PACKAGES_PER_CHECK: usize = 20;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Verdict {
    /// Gate disabled, or command contains no install actions. Caller proceeds normally.
    Skip,
    /// All checks passed.
    Allow,
    /// One or more packages failed the gate. Caller should refuse the auto-allow.
    Block(Vec<Finding>),
    /// The install verb was detected but its package set cannot be vetted
    /// (lockfile / requirements / constraints install — no nameable package).
    /// Not a hard failure: callers fail CLOSED by downgrading the auto-allow
    /// to Ask so the user confirms the unvetted set, rather than waving it
    /// through (Skip) or hard-refusing it (Block).
    Ask(Vec<Finding>),
    /// Network or other transient failure (TOML parse, registry timeout,
    /// OSV lookup error). Callers fail CLOSED: the auto-allow is downgraded
    /// to Ask so the user is prompted rather than the install waved through.
    Unavailable(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub package: String,
    pub ecosystem: String,
    pub reason: FindingReason,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum FindingReason {
    RecentRelease {
        age_days: f64,
        cooldown_days: u32,
        version: String,
    },
    KnownVulnerability {
        id: String,
        summary: String,
    },
    /// The install command contained an editable / path / URL token (e.g.
    /// `-e .`, `git+...`, `https://...`) and the ecosystem config does not
    /// allow these to bypass review.
    UnvettableSource {
        token_kind: String,
    },
    /// An install verb was detected but no package name is resolvable: the
    /// install pulls its package set from a lockfile / requirements file /
    /// constraints file the gate cannot enumerate or query. Examples:
    /// `npm install` / `npm ci` with no args, `pip install -r requirements.txt`.
    /// Fails closed to Ask so the unvetted set is surfaced to the user.
    UnvettableInstall {
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "LOW" => Some(Severity::Low),
            "MEDIUM" | "MED" | "MODERATE" => Some(Severity::Medium),
            "HIGH" => Some(Severity::High),
            "CRITICAL" => Some(Severity::Critical),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    supply_chain: GlobalConfig,
    #[serde(default = "default_npm")]
    npm: EcosystemConfig,
    #[serde(default = "default_pypi")]
    pypi: EcosystemConfig,
    #[serde(default)]
    overrides: Overrides,
}

#[derive(Debug, Deserialize, Default)]
struct GlobalConfig {
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct EcosystemConfig {
    #[serde(default = "default_cooldown")]
    cooldown_days: u32,
    #[serde(default = "default_severity")]
    block_severity: String,
    #[serde(default)]
    allow_editable: bool,
}

#[derive(Debug, Deserialize, Default)]
struct Overrides {
    #[serde(default)]
    always_allow: Vec<String>,
    #[serde(default)]
    always_deny: Vec<String>,
}

fn default_cooldown() -> u32 {
    3
}

fn default_severity() -> String {
    "HIGH".into()
}

fn default_npm() -> EcosystemConfig {
    EcosystemConfig {
        cooldown_days: 3,
        block_severity: "HIGH".into(),
        allow_editable: false,
    }
}

fn default_pypi() -> EcosystemConfig {
    EcosystemConfig {
        cooldown_days: 3,
        block_severity: "HIGH".into(),
        allow_editable: true,
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            supply_chain: GlobalConfig { enabled: false },
            npm: default_npm(),
            pypi: default_pypi(),
            overrides: Overrides::default(),
        }
    }
}

/// Where to look for the supply-chain config.
/// Search order (first hit wins):
///   1. `$XDG_CONFIG_HOME/contextcrawler/supply-chain.toml`
///   2. `~/.config/contextcrawler/supply-chain.toml` (developer-friendly on macOS)
///   3. `dirs::config_dir()/contextcrawler/supply-chain.toml`
///      (= ~/Library/Application Support on macOS, ~/.config on Linux, AppData on Windows)
fn config_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        out.push(PathBuf::from(xdg).join("contextcrawler").join("supply-chain.toml"));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".config/contextcrawler/supply-chain.toml"));
    }
    if let Some(cfg) = dirs::config_dir() {
        out.push(cfg.join("contextcrawler").join("supply-chain.toml"));
    }
    out
}

/// Read the supply-chain config from disk (first candidate that exists wins).
fn read_config_from_disk() -> Config {
    for path in config_candidates() {
        if let Ok(content) = fs::read_to_string(&path) {
            return toml::from_str(&content).unwrap_or_default();
        }
    }
    Config::default()
}

/// Process-lifetime cache for the supply-chain config.
///
/// The gate now runs on EVERY hook-routed Bash command (the hottest path in
/// the tool), so an uncached `load_config()` would hit disk on every agent
/// command even when the gate is disabled. The hook process is short-lived
/// (one invocation per agent command) so a process-lifetime cache is correct;
/// even if the hook ran long-lived, config doesn't change mid-process so the
/// cache stays valid. Codex-review follow-up for #100.
static CONFIG_CACHE: OnceLock<Config> = OnceLock::new();

/// Returns the supply-chain config, reading disk at most once per process.
fn load_config() -> &'static Config {
    CONFIG_CACHE.get_or_init(read_config_from_disk)
}

// ---------------------------------------------------------------------------
// Command parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedInstall {
    ecosystem: Ecosystem,
    /// (package_name, optional_pinned_version)
    packages: Vec<(String, Option<String>)>,
    has_editable: bool,
    /// Set when the install resolves its package set from a file the gate
    /// cannot enumerate or query: pip `-r`/`--requirement`/`-c`/`--constraint`,
    /// or a bare lockfile install (`npm install`/`npm ci` with no package
    /// args). The string is a short human-readable description of the source.
    unvettable: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
        }
    }
}

// Combined regex contract — both #143 (develop) and #140 layered:
//
// Prefix anchor `(?:^|[\s;/\\'"]|&&|\|\|)` treats whitespace, `;`, `&&`,
// `||`, `/`, `\`, `'`, and `"` as command-start delimiters:
//   - `/` and `\` close the absolute / relative path bypass (#139).
//   - `'` and `"` close the quoted-head bypass (#140) — `'npm' install x`
//     / `"pip" install x` are detected via the quote-as-anchor + an
//     optional closing quote after the verb (`['"]?` immediately after).
//
// Verb tokens use `(?i:…)` so `NPM`, `Npm` etc. classify alongside `npm`.
// The pip verb also covers versioned launchers — `pip\d*(?:\.\d+)*`
// matches `pip`, `pip3`, `pip3.12`, etc.
//
// After the verb (and optional closing quote) `(?:\.(?i:cmd|exe|bat))*`
// absorbs Windows launchers (`npm.cmd`, `npm.cmd.exe`, `NPM.CMD`) —
// chained extensions collapse for free.
//
// The capture group excludes `\r\n` so a multi-line script does not
// chain-swallow the next line. Line-continuation backslashes are
// collapsed BEFORE matching by `LINE_CONT_RE` in `detect_installs`. The
// outer command is also pre-masked by `mask_quoted_operators` so a
// literal `&` / `|` / `;` inside a quoted flag value does not truncate
// the package scan.
lazy_static! {
    // Backslash + line-ending + any whitespace = shell line-continuation.
    // Collapsed to a single space before install detection. Covers POSIX
    // (`\n`), Windows (`\r\n`), AND legacy Mac (`\r` alone).
    static ref LINE_CONT_RE: Regex = Regex::new(r"\\(?:\r\n|\n|\r)\s*").unwrap();
    // Verb subcommand wrapped in `['"]?…['"]?` — closes the BLOCKER both
    // reviewers flagged on #146: `npm 'install' lodash` / `pip "install" x`
    // would otherwise bypass (regex doesn't match the quoted subcommand,
    // and the bare-install scan sees `lodash` as a package → silent skip).
    static ref NPM_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:npm)['"]?(?:\.(?i:cmd|exe|bat))*\s+['"]?(?i:i|install|add)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PNPM_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pnpm)['"]?(?:\.(?i:cmd|exe|bat))*\s+['"]?(?i:i|install|add)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref YARN_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:yarn)['"]?(?:\.(?i:cmd|exe|bat))*\s+['"]?(?i:add)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PIP_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pip\d*(?:\.\d+)*)['"]?(?:\.(?i:cmd|exe|bat))*\s+['"]?(?i:install)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref UV_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:uv)['"]?(?:\.(?i:cmd|exe|bat))*\s+(?:['"]?(?i:pip)['"]?\s+)?['"]?(?i:install|add)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref POETRY_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:poetry)['"]?(?:\.(?i:cmd|exe|bat))*\s+['"]?(?i:add)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PIPX_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pipx)['"]?(?:\.(?i:cmd|exe|bat))*\s+['"]?(?i:install)['"]?\s+([^|;&<>\r\n]+)"#
    )
    .unwrap();
}

/// Tokenise a shell command into (offset, token-text) pairs.
///
/// Shell operators `&&`, `||`, `;`, `|`, `>`, `>>`, `<`, `<<` become their
/// own tokens — but only when seen OUTSIDE quotes. Inside `'…'`, `"…"`, or
/// `$'…'` the operator characters are part of the surrounding word.
///
/// The token text is the *literal payload* with surrounding quote characters
/// stripped — `'npm'` becomes `npm`, `"pip"` becomes `pip`. This lets the
/// bare-install scan in [`detect_bare_lockfile_installs`] match a quoted
/// install head against `"npm"` / `"pnpm"` / `"yarn"` without special casing.
///
/// Command-substitution payloads (`$(…)`, backticks) are NOT emitted as
/// tokens here — they are extracted separately by
/// [`extract_recursion_segments`] so [`detect_installs`] can recurse into
/// them. The substitution body still consumes its source span so subsequent
/// tokens align on byte offsets in the *original* command.
///
/// Unmatched quotes are tolerated: the unclosed run is consumed to end-of-input
/// as a single token. The gate's fallback contract is no-panic; an unmatched
/// quote at worst yields a noisy token that the regex pass ignores.
///
/// ANSI-C `$'…'` quotes are treated as single quotes for tokenising — we
/// do not interpret `\n`/`\t` escapes because the gate only needs the verb
/// surface, not the byte-perfect payload.
fn shell_tokens(cmd: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Shell operators become their own tokens — outside quotes only.
        if c == ';' || c == '|' || c == '&' || c == '>' || c == '<' {
            let start = i;
            let mut j = i + 1;
            // Group repeated operator chars (`&&`, `||`, `>>`, `<<`).
            while j < bytes.len() && (bytes[j] as char) == c {
                j += 1;
            }
            out.push((start, cmd[start..j].to_string()));
            i = j;
            continue;
        }
        // Ordinary word: run until whitespace or an *unquoted* operator,
        // accumulating the literal payload (quotes stripped, substitution
        // bodies copied verbatim so the offset arithmetic in callers stays
        // honest).
        let start = i;
        let mut payload = String::new();
        let mut j = i;
        while j < bytes.len() {
            let cj = bytes[j] as char;
            if cj.is_whitespace() || cj == ';' || cj == '|' || cj == '&' || cj == '>' || cj == '<'
            {
                break;
            }
            // Single quote: literal — no expansion, no escape, ends at next `'`.
            if cj == '\'' {
                let q_start = j + 1;
                let mut k = q_start;
                while k < bytes.len() && (bytes[k] as char) != '\'' {
                    k += 1;
                }
                payload.push_str(&cmd[q_start..k.min(bytes.len())]);
                // Step past the closing quote if present; otherwise consume
                // to end-of-input (unmatched quote — best effort, no panic).
                j = if k < bytes.len() { k + 1 } else { k };
                continue;
            }
            // ANSI-C $'…' quote: same shape as single quote for our purposes.
            if cj == '$' && j + 1 < bytes.len() && (bytes[j + 1] as char) == '\'' {
                let q_start = j + 2;
                let mut k = q_start;
                while k < bytes.len() && (bytes[k] as char) != '\'' {
                    // Honour `\'` escape so the inner quote does not terminate.
                    if (bytes[k] as char) == '\\' && k + 1 < bytes.len() {
                        k += 2;
                        continue;
                    }
                    k += 1;
                }
                payload.push_str(&cmd[q_start..k.min(bytes.len())]);
                j = if k < bytes.len() { k + 1 } else { k };
                continue;
            }
            // Double quote: no operator splitting, no expansion. `\"` is the
            // only escape we honour (the only one that matters for finding
            // the closing quote). `$(…)` and backticks INSIDE a double-quoted
            // string still execute, so we copy the body verbatim — the
            // top-level recursion sweep finds substitutions anywhere in the
            // command, including inside double quotes.
            if cj == '"' {
                let q_start = j + 1;
                let mut k = q_start;
                while k < bytes.len() {
                    let cc = bytes[k] as char;
                    if cc == '\\' && k + 1 < bytes.len() {
                        k += 2;
                        continue;
                    }
                    if cc == '"' {
                        break;
                    }
                    k += 1;
                }
                payload.push_str(&cmd[q_start..k.min(bytes.len())]);
                j = if k < bytes.len() { k + 1 } else { k };
                continue;
            }
            // Command substitution `$(…)`: consume balanced. The body is
            // exposed via extract_recursion_segments, not as a token here —
            // but the source span still has to be skipped so word boundaries
            // align with the original command.
            if cj == '$' && j + 1 < bytes.len() && (bytes[j + 1] as char) == '(' {
                let body_start = j + 2;
                let k = scan_balanced_paren(cmd, body_start);
                // Copy body verbatim into the payload so any package-name
                // text that lives at the same shell-word level (e.g. an
                // adversary writing `npm$(echo )install foo`) does not
                // disappear from the regex pass.
                payload.push_str(&cmd[body_start..k.min(bytes.len())]);
                j = if k < bytes.len() { k + 1 } else { k };
                continue;
            }
            // Backtick substitution: same role as `$(…)`, single-level only.
            if cj == '`' {
                let body_start = j + 1;
                let mut k = body_start;
                while k < bytes.len() && (bytes[k] as char) != '`' {
                    if (bytes[k] as char) == '\\' && k + 1 < bytes.len() {
                        k += 2;
                        continue;
                    }
                    k += 1;
                }
                payload.push_str(&cmd[body_start..k.min(bytes.len())]);
                j = if k < bytes.len() { k + 1 } else { k };
                continue;
            }
            // Backslash escape outside quotes: skip one char.
            if cj == '\\' && j + 1 < bytes.len() {
                payload.push(bytes[j + 1] as char);
                j += 2;
                continue;
            }
            payload.push(cj);
            j += 1;
        }
        out.push((start, payload));
        i = j;
    }
    out
}

/// Scan forward from `start` (which should point just past the opening `(`)
/// to the matching closing `)`. Returns the index of that `)`, or
/// `cmd.len()` if no match was found (unmatched — best effort, no panic).
/// Nested `(` increment the depth; quoted regions are honoured so a `)`
/// inside `'…'` or `"…"` does not close the substitution.
fn scan_balanced_paren(cmd: &str, start: usize) -> usize {
    let bytes = cmd.as_bytes();
    let mut k = start;
    let mut depth: i32 = 1;
    while k < bytes.len() {
        let c = bytes[k] as char;
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return k;
                }
            }
            '\'' => {
                k += 1;
                while k < bytes.len() && (bytes[k] as char) != '\'' {
                    k += 1;
                }
            }
            '"' => {
                k += 1;
                while k < bytes.len() {
                    let cc = bytes[k] as char;
                    if cc == '\\' && k + 1 < bytes.len() {
                        k += 2;
                        continue;
                    }
                    if cc == '"' {
                        break;
                    }
                    k += 1;
                }
            }
            '\\' if k + 1 < bytes.len() => {
                k += 1;
            }
            _ => {}
        }
        k += 1;
    }
    bytes.len()
}

/// Extract recursion segments: payloads of `sh -c <arg>` / `bash -c <arg>`,
/// command-substitution bodies `$(…)`, and backtick bodies. Returned strings
/// are the *literal inner command text* — the caller re-runs the full
/// install detector on each one to close the wrapped-install bypass class.
///
/// Representation choice: a flat `Vec<String>` of inner commands rather than
/// in-band tokens. This keeps the offset/dedup contract of `shell_tokens`
/// intact (offsets always refer to the original cmd) and isolates recursion
/// to a single explicit pass in `detect_installs`. Each segment is treated as
/// an independent command — no offset is needed because spans in the inner
/// command would not align with the outer claimed-span dedup anyway.
fn extract_recursion_segments(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        // `$(…)` substitution.
        if c == '$' && i + 1 < bytes.len() && (bytes[i + 1] as char) == '(' {
            let body_start = i + 2;
            let end = scan_balanced_paren(cmd, body_start);
            if end > body_start && end <= bytes.len() {
                out.push(cmd[body_start..end].to_string());
            }
            i = if end < bytes.len() { end + 1 } else { end };
            continue;
        }
        // Backtick substitution.
        if c == '`' {
            let body_start = i + 1;
            let mut k = body_start;
            while k < bytes.len() && (bytes[k] as char) != '`' {
                if (bytes[k] as char) == '\\' && k + 1 < bytes.len() {
                    k += 2;
                    continue;
                }
                k += 1;
            }
            if k > body_start && k <= bytes.len() {
                out.push(cmd[body_start..k.min(bytes.len())].to_string());
            }
            i = if k < bytes.len() { k + 1 } else { k };
            continue;
        }
        // Single-quoted: skip without recursion (no expansion happens inside).
        if c == '\'' {
            let mut k = i + 1;
            while k < bytes.len() && (bytes[k] as char) != '\'' {
                k += 1;
            }
            i = if k < bytes.len() { k + 1 } else { k };
            continue;
        }
        // Double-quoted: recurse for `$(…)` / backticks inside (they DO
        // execute inside `"…"`), but the literal characters between are not
        // word-split — we still scan for substitutions.
        if c == '"' {
            let mut k = i + 1;
            while k < bytes.len() {
                let cc = bytes[k] as char;
                if cc == '\\' && k + 1 < bytes.len() {
                    k += 2;
                    continue;
                }
                if cc == '"' {
                    break;
                }
                // Surface substitutions inside double quotes.
                if cc == '$' && k + 1 < bytes.len() && (bytes[k + 1] as char) == '(' {
                    let body_start = k + 2;
                    let end = scan_balanced_paren(cmd, body_start);
                    if end > body_start && end <= bytes.len() {
                        out.push(cmd[body_start..end].to_string());
                    }
                    k = if end < bytes.len() { end + 1 } else { end };
                    continue;
                }
                if cc == '`' {
                    let body_start = k + 1;
                    let mut m = body_start;
                    while m < bytes.len() && (bytes[m] as char) != '`' {
                        if (bytes[m] as char) == '\\' && m + 1 < bytes.len() {
                            m += 2;
                            continue;
                        }
                        m += 1;
                    }
                    if m > body_start && m <= bytes.len() {
                        out.push(cmd[body_start..m.min(bytes.len())].to_string());
                    }
                    k = if m < bytes.len() { m + 1 } else { m };
                    continue;
                }
                k += 1;
            }
            i = if k < bytes.len() { k + 1 } else { k };
            continue;
        }
        i += 1;
    }

    // `sh -c <arg>` / `bash -c <arg>` (and friends): pull the argument that
    // follows the `-c` option. Combined short-option clusters like `-lc`,
    // `-xc`, `-x -c`, and POSIX-legal orderings like `bash -c -e '<cmd>'`
    // were a confirmed bypass (agy + Codex HIGH on #146): the original
    // exact-`-c` match missed every form except the canonical one.
    //
    // Strategy: locate a shell head (`sh`/`bash`/`zsh`/`dash`/`ksh`), then
    // scan forward through short-option clusters for one whose final
    // character is `c`. The next token after the matching cluster is the
    // command body. A long option (`--`) or non-option token before `-c`
    // ends the scan without recursion.
    let toks = shell_tokens(cmd);
    let mut idx = 0;
    while idx < toks.len() {
        let head = installer_basename(toks[idx].1.as_str()).to_ascii_lowercase();
        if matches!(head.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh") {
            // Scan forward for a short-option cluster containing `c`.
            let mut scan = idx + 1;
            let mut body_idx: Option<usize> = None;
            while scan < toks.len() {
                let t = toks[scan].1.as_str();
                if t.starts_with("--") {
                    // Long option: stop without recursion.
                    break;
                }
                if t.starts_with('-') && t.len() >= 2 && t.contains('c') {
                    body_idx = Some(scan + 1);
                    break;
                }
                if !t.starts_with('-') {
                    // Non-option token before `-c`: this isn't a `-c` form
                    // (e.g. `bash script.sh` — a script-file invocation,
                    // not in scope for body extraction).
                    break;
                }
                scan += 1;
            }
            if let Some(mut b) = body_idx {
                if b < toks.len() && toks[b].1 == "--" {
                    b += 1;
                }
                if b < toks.len() {
                    out.push(toks[b].1.clone());
                }
                idx = b + 1;
                continue;
            }
        }
        idx += 1;
    }

    out
}

/// Return a same-length copy of `cmd` where shell operator characters
/// (`&`, `|`, `;`, `>`, `<`) inside quoted regions are replaced by spaces.
/// The package-list regexes use `[^|;&<>]+` to bound the package arg list;
/// without masking, a literal `&` in `--description="install & test"` cuts
/// the scan short and the package after the flag is lost.
///
/// Lengths are preserved byte-for-byte so any byte offsets produced from
/// the masked string still align with the original `cmd` (no
/// re-tokenisation needed downstream).
fn mask_quoted_operators(cmd: &str) -> String {
    let bytes = cmd.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\'' {
            out.push(b'\'');
            i += 1;
            while i < bytes.len() && (bytes[i] as char) != '\'' {
                let ch = bytes[i];
                out.push(if matches!(ch, b'&' | b'|' | b';' | b'>' | b'<') {
                    b' '
                } else {
                    ch
                });
                i += 1;
            }
            if i < bytes.len() {
                out.push(b'\'');
                i += 1;
            }
            continue;
        }
        if c == '"' {
            out.push(b'"');
            i += 1;
            while i < bytes.len() {
                let cc = bytes[i] as char;
                if cc == '\\' && i + 1 < bytes.len() {
                    out.push(bytes[i]);
                    out.push(bytes[i + 1]);
                    i += 2;
                    continue;
                }
                if cc == '"' {
                    out.push(b'"');
                    i += 1;
                    break;
                }
                let ch = bytes[i];
                out.push(if matches!(ch, b'&' | b'|' | b';' | b'>' | b'<') {
                    b' '
                } else {
                    ch
                });
                i += 1;
            }
            continue;
        }
        // ANSI-C $'…': mask like single quotes.
        if c == '$' && i + 1 < bytes.len() && (bytes[i + 1] as char) == '\'' {
            out.push(b'$');
            out.push(b'\'');
            i += 2;
            while i < bytes.len() && (bytes[i] as char) != '\'' {
                if (bytes[i] as char) == '\\' && i + 1 < bytes.len() {
                    out.push(bytes[i]);
                    out.push(bytes[i + 1]);
                    i += 2;
                    continue;
                }
                let ch = bytes[i];
                out.push(if matches!(ch, b'&' | b'|' | b';' | b'>' | b'<') {
                    b' '
                } else {
                    ch
                });
                i += 1;
            }
            if i < bytes.len() {
                out.push(b'\'');
                i += 1;
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Safety: we only ever copied valid UTF-8 bytes through (the masked
    // chars are ASCII space). `from_utf8` cannot fail here, but we still
    // fall back to `from_utf8_lossy` to honour the no-panic contract.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

/// True if a token is a shell operator delimiter (not a package name).
fn is_shell_operator(tok: &str) -> bool {
    matches!(
        tok,
        ";" | "|" | "||" | "&" | "&&" | ">" | ">>" | "<" | "<<"
    )
}

/// Data-consuming utilities — their argv is data, not a command-of-commands.
/// When the head verb of a command segment is one of these, install-shaped
/// substrings inside that segment are treated as plain data (not real install
/// invocations) and the gate suppresses detection for that segment.
///
/// This is the #141 pragmatic bandaid (approach 1 of three): a head-verb
/// allowlist. Approaches (2) "token-position constraint" and (3) "quote-
/// context exclusion" remain the more principled fixes; this list should
/// shrink (or retire) once they ship.
///
/// Kept deliberately narrow: only utilities whose canonical role is to EMIT
/// or SEARCH their argv as data. Stateful utilities like `cd`, `env`,
/// `xargs`, `sudo`, `nohup` are NOT on the list — they invoke a subsequent
/// command and that command is the real head.
///
/// **EXCLUDED (deliberately) — execution-capable utilities** (agy + Codex
/// BLOCKERs on PR #148): tools that can execute arbitrary shell as a
/// side effect of normal flags do NOT belong on a "data only" allowlist,
/// because masking their segment hides any install verb from the gate
/// while the runtime still spawns it.
///
/// Confirmed execution-capable, NEVER mask:
///   - `awk` / `gawk` / `mawk` — Turing-complete with `system()`:
///     `awk 'BEGIN { system("npm install evil") }'`
///   - GNU `sed` — `s///e` flag runs the replacement as a shell command:
///     `sed 's/.*/npm install .../e'`
///   - `rg` (ripgrep) — `--pre <executable>` runs the preprocessor on
///     each file (Codex BLOCKER): `rg --pre /tmp/script.sh pattern .`
///
/// If you ever want to surface real installs invoked through these
/// utilities, walk the script body via `extract_recursion_segments` — do
/// NOT add them back to the allowlist.
const DATA_CONSUMING_UTILITIES: &[&str] = &[
    // Emit-as-data
    "echo", "printf", "cat", "tac", "tee",
    // Search-as-data (grep family — no `--pre`-style executable flag)
    "grep", "egrep", "fgrep",
    // Slice / trim-as-data
    "head", "tail", "nl",
    // Encode / decode (cannot execute)
    "base64", "xxd", "od", "hexdump",
    // Structured-text parse (jq has no shell-out; `--exec`-style flags do not exist)
    "jq",
];

/// True iff the first non-whitespace token of `segment`, basename-normalised,
/// matches a known data-consuming utility (see [`DATA_CONSUMING_UTILITIES`]).
///
/// Basename normalisation handles `/bin/echo`, `./echo`, `/usr/bin/grep` etc.
/// — the same path-bypass concern that #139 closed for installer heads
/// applies symmetrically here.
///
/// Returns `false` on an empty / whitespace-only segment, on segments that
/// begin with a shell operator, and on any unknown head.
#[allow(dead_code)] // exercised by tests + reserved for principled-path follow-up
fn command_head_is_data_utility(segment: &str) -> bool {
    let tokens = shell_tokens(segment);
    let head = match tokens.first() {
        Some((_, t)) => t.as_str(),
        None => return false,
    };
    // A leading shell operator (e.g. trailing chain fragment with no head)
    // is not a data utility — it's just empty.
    if is_shell_operator(head) {
        return false;
    }
    let basename = installer_basename(head);
    DATA_CONSUMING_UTILITIES.contains(&basename)
}

/// Mask command segments whose head verb is a data-consuming utility (see
/// [`command_head_is_data_utility`]). Returns a string of the same byte
/// length as `cmd` — bytes inside masked segments are replaced with ASCII
/// spaces, chain operators and unmasked segments are preserved verbatim.
///
/// Preserving byte offsets matters: the regex prefix-anchor in NPM_RE /
/// PIP_RE / etc. relies on the boundary char immediately before the install
/// verb (space, `&&`, `||`, `;`, `/`, `\`), and the downstream `claimed`
/// dedup uses absolute indices into the command. Replacing with spaces
/// (not deleting) keeps both invariants intact.
///
/// Segment boundaries are shell operator tokens (`;`, `|`, `||`, `&`, `&&`,
/// `>`, `>>`, `<`, `<<`) as produced by [`shell_tokens`]. Each segment's
/// head is the first non-operator token; the segment span is `[head_off,
/// next_op_off)` — using the next operator's source offset as the segment
/// end avoids the trap that `shell_tokens` strips quote characters from
/// token payloads (so `tok.len()` no longer equals the source-span length
/// for a quoted token).
fn mask_data_utility_segments(cmd: &str) -> String {
    let tokens = shell_tokens(cmd);
    let bytes = cmd.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();

    let mask_range = |buf: &mut Vec<u8>, start: usize, end: usize| {
        for b in buf.iter_mut().take(end).skip(start) {
            // Preserve newlines so any multi-line invariants survive; we
            // are not currently aware of one, but it costs nothing.
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };

    let mut seg_head_off: Option<usize> = None;
    let mut seg_head_is_data_util = false;

    for (off, tok) in &tokens {
        if is_shell_operator(tok) {
            // Close the in-flight segment at the operator's source offset.
            if let (Some(start), true) = (seg_head_off, seg_head_is_data_util) {
                mask_range(&mut out, start, *off);
            }
            seg_head_off = None;
            seg_head_is_data_util = false;
            continue;
        }
        // First word of a fresh segment establishes the head.
        if seg_head_off.is_none() {
            seg_head_off = Some(*off);
            let basename = installer_basename(tok);
            seg_head_is_data_util = DATA_CONSUMING_UTILITIES.contains(&basename);
        }
    }
    // Flush the final segment — it runs to end-of-string.
    if let (Some(start), true) = (seg_head_off, seg_head_is_data_util) {
        mask_range(&mut out, start, bytes.len());
    }

    // Safety: we only overwrite ASCII word bytes with ASCII spaces — ASCII
    // space is never a UTF-8 continuation byte, so multi-byte sequences
    // inside masked spans get replaced byte-by-byte with valid UTF-8. The
    // result is therefore valid UTF-8 and `from_utf8` cannot fail in
    // practice; fall back to the original `cmd` on the impossible case
    // rather than panic, honouring the gate's no-panic contract.
    String::from_utf8(out).unwrap_or_else(|_| cmd.to_string())
}

/// Detect package-manager install invocations in a shell command.
///
/// ## Scope (codified after Codex + agy peer review on #143)
///
/// The gate is intentionally limited to the install-shaped surfaces below.
/// Anything outside this list returns [`Verdict::Skip`] — that is not a
/// silent miss, it is a documented scope boundary. Expansion candidates
/// (bun, pdm, pipenv, conda, mamba, brew, plus `pnpm update`,
/// `poetry update`, etc.) are tracked in
/// [issue #144](https://github.com/thehoff/contextcrawler/issues/144).
///
/// **In scope** (package-bearing, via regex):
/// - `npm install <pkg>` / `npm i <pkg>` / `npm add <pkg>`
/// - `pnpm install <pkg>` / `pnpm i <pkg>` / `pnpm add <pkg>`
/// - `yarn add <pkg>`
/// - `pip install <pkg>` / `pip3 install <pkg>` / `pip3.12.exe install <pkg>` etc.
/// - `uv install <pkg>` / `uv add <pkg>` / `uv pip install <pkg>`
/// - `poetry add <pkg>`
/// - `pipx install <pkg>`
///
/// **In scope** (bare lockfile / always-bare, via token walk):
/// - `npm install` / `npm i` / `npm ci`
/// - `pnpm install` / `pnpm i` / `pnpm ci`
/// - `yarn install`, bare `yarn`, and `yarn <install-flag>` (e.g.
///   `yarn --frozen-lockfile`) — Yarn's shorthand for `yarn install`
/// - `poetry install` (always bare, all args are flags)
/// - `uv sync` / `uv pip sync` (always bare, all args are flags)
///
/// **Deliberately out of scope** (maintenance / lockfile-only / non-install):
/// - `npm rebuild`, `npm dedupe`, `npm update`
/// - `uv lock`, `poetry lock`
/// - `yarn --version`, `yarn -v`, `yarn --help`, `yarn -h` — diagnostic
///   forms; filtered by `is_yarn_help_or_version_flag` in the bare-yarn arm
///
/// All path forms (POSIX abs, POSIX rel, Windows `\` paths, `.cmd`/`.exe`/
/// `.bat` launcher suffixes, chained extensions, all case variants) are
/// normalised by [`installer_basename`] and the regex anchor before the
/// match arms see the token.
fn detect_installs(cmd: &str) -> Vec<ParsedInstall> {
    // Collapse shell line-continuation (`\` + newline + indent) into a single
    // space BEFORE detection (#143 / agy HIGH). Without this, the `\r\n`
    // guard in the regex capture truncates at the trailing `\` and packages
    // on the next line escape detection. The normalised form re-anchors the
    // entire install on one logical line so the regex absorbs every token.
    let normalised_cow = LINE_CONT_RE.replace_all(cmd, " ");
    let cmd: &str = normalised_cow.as_ref();

    let mut out = Vec::new();
    detect_installs_into(cmd, 0, &mut out);
    // Cross-layer dedup. The outer regex pass + recursion into `sh -c`
    // bodies / substitutions will both fire on the same install when the
    // wrapper passes the verb through verbatim (e.g. `sh -c 'npm install
    // foo'` matches NPM_RE via the `'` anchor AND the recursed body
    // matches it again). Two ParsedInstalls with identical content
    // collapse to one — we lose no information, but the gate stops
    // double-vetting the same package set.
    dedup_installs(&mut out);
    out
}

/// Structural dedup: collapse `ParsedInstall`s that carry the same
/// ecosystem + package set + editable + unvettable detail. Order of the
/// first occurrence is preserved (stable).
fn dedup_installs(items: &mut Vec<ParsedInstall>) {
    let mut i = 0;
    while i < items.len() {
        let mut j = i + 1;
        while j < items.len() {
            if installs_equivalent(&items[i], &items[j]) {
                items.remove(j);
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

fn installs_equivalent(a: &ParsedInstall, b: &ParsedInstall) -> bool {
    if a.ecosystem != b.ecosystem
        || a.has_editable != b.has_editable
        || a.unvettable != b.unvettable
        || a.packages.len() != b.packages.len()
    {
        return false;
    }
    // Order-independent package-set compare (agy LOW on #146): two installs
    // listing `[a, b]` and `[b, a]` semantically install the same set and
    // must collapse. We sort cheap clones rather than mutate inputs so the
    // original ordering (which has display value) is preserved for callers.
    let mut a_pkgs = a.packages.clone();
    let mut b_pkgs = b.packages.clone();
    a_pkgs.sort();
    b_pkgs.sort();
    a_pkgs == b_pkgs
}

/// Recursion-bounded core of [`detect_installs`]. `depth` guards against a
/// pathological `$(${...})` nesting (or future bug) that would otherwise
/// recurse without bound. Each `sh -c` / `$(…)` / backtick body recurses
/// once at `depth + 1`, and `MAX_RECURSION_DEPTH` caps the total at a
/// number well above any realistic shell-script shape.
const MAX_RECURSION_DEPTH: u8 = 6;

fn detect_installs_into(cmd: &str, depth: u8, out: &mut Vec<ParsedInstall>) {
    // #141: mask any segment whose head verb is a data-consuming utility
    // (echo, printf, cat, grep, jq, base64, …). The masked string has the
    // SAME byte offsets — bytes inside masked segments are turned into
    // spaces — so all downstream regex anchors, the `claimed` index
    // bookkeeping, AND `mask_quoted_operators` (which also produces a
    // same-length string) compose cleanly.
    //
    // Applied at every recursion depth — wrappers like `sh -c 'echo "npm
    // install foo"'` extract the inner `echo "..."` payload via
    // `extract_recursion_segments` and recurse here; the inner head is also
    // a data utility and must be masked at the inner depth, not just at the
    // top level.
    //
    // Crucially, the recursion sweep below runs against the ORIGINAL
    // `cmd_raw` (NOT the masked copy). Substitution bodies inside a masked
    // data-utility segment still surface for recursion — masking only
    // suppresses the surface-level regex pass for that segment, not the
    // recursion sweep. This is intentional: `echo "$(npm install foo)"`
    // does execute the substitution at runtime, so the gate must still vet
    // its body.
    let cmd_raw = cmd;
    let masked_data = mask_data_utility_segments(cmd_raw);
    let cmd: &str = masked_data.as_str();

    // Run UV before PIP so `uv pip install foo` is claimed by the UV pattern
    // and PIP_RE matching the inner `pip install foo` substring is suppressed
    // for that span.
    let mut claimed: Vec<(usize, usize)> = Vec::new();

    let ordered = [
        (&*UV_RE, Ecosystem::Pypi),
        (&*NPM_RE, Ecosystem::Npm),
        (&*PNPM_RE, Ecosystem::Npm),
        (&*YARN_RE, Ecosystem::Npm),
        (&*PIP_RE, Ecosystem::Pypi),
        (&*POETRY_RE, Ecosystem::Pypi),
        (&*PIPX_RE, Ecosystem::Pypi),
    ];

    // Run the regex pass against a same-length copy of `cmd` where shell
    // operators inside quotes are masked to spaces. This closes the
    // false-negative class where `[^|;&<>]+` truncates at a literal `&`
    // inside `--description="install & test"` and drops the package after
    // the flag. Byte offsets in `masked` map 1:1 to `cmd`, so we slice
    // arg-text from `cmd` itself (preserving the original characters).
    let masked = mask_quoted_operators(cmd);

    for (re, eco) in ordered {
        for m in re.find_iter(&masked) {
            let (start, end) = (m.start(), m.end());
            // Skip if any earlier (higher-priority) pattern already claimed this span.
            if claimed
                .iter()
                .any(|(s, e)| start >= *s && start < *e)
            {
                continue;
            }
            claimed.push((start, end));
            let cap = match re.captures_at(&masked, start) {
                Some(c) => c,
                None => continue,
            };
            // Re-slice the argument span out of the ORIGINAL command so the
            // package names carry their real (unmasked) characters. The
            // masking only ever rewrites bytes inside quoted regions to
            // spaces, so the offsets are identical in both strings.
            let arg_string = cap
                .get(1)
                .map(|m| &cmd[m.start()..m.end()])
                .unwrap_or("");
            let (pkgs, has_editable, lockfile_source) = parse_package_args(arg_string);
            // An install verb was detected. If no package is nameable AND no
            // editable token is present, the install set is unvettable
            // (lockfile / requirements / constraints indirection, or an
            // install verb whose only args were flags). Surface it instead
            // of dropping the whole install silently — see #111 G1.
            let unvettable = if pkgs.is_empty() && !has_editable {
                Some(lockfile_source.unwrap_or_else(|| {
                    "install resolves packages from a lockfile/requirements file the gate cannot vet"
                        .to_string()
                }))
            } else {
                lockfile_source
            };
            out.push(ParsedInstall {
                ecosystem: eco,
                packages: pkgs,
                has_editable,
                unvettable,
            });
        }
    }

    // Bare lockfile installs (`npm install` / `npm ci` / `pnpm install` /
    // `yarn install` / `yarn` with no package args) never match the
    // package-bearing regexes above. They are classified from the parsed
    // token stream rather than a regex that must see end-of-command: a
    // regex anchored on `$`/delimiter is defeated by trailing flags such
    // as `npm ci --ignore-scripts` or `yarn install --immutable`, which
    // would then fall through as a silent Skip (#111 G1 follow-up).
    detect_bare_lockfile_installs(cmd, &mut claimed, out);

    // Recurse into shell-wrapped install shells: `sh -c '<install>'`,
    // `$(<install>)`, backticks. Each inner command is treated as its own
    // top-level command — claimed-span dedup is local to a single string,
    // so duplicates between layers are not a concern.
    //
    // Depth limit (Codex + agy BLOCKER on #146): at `MAX_RECURSION_DEPTH`
    // the recursion stops. The original implementation silently dropped
    // any installs at depths beyond the cap — fail-OPEN. A nested payload
    // (`sh -c "$(sh -c "$(sh -c '...')")"`) that exceeds the cap would
    // then auto-allow at the gate. The fix: at the cap, if there are still
    // unresolved recursion segments, surface a synthetic Unvettable
    // ParsedInstall so the caller fails CLOSED (Verdict::Ask) instead.
    if depth < MAX_RECURSION_DEPTH {
        // Recurse against the original (unmasked) cmd: a substitution body
        // nested inside a data-utility segment still executes at runtime
        // (`echo "$(npm install foo)"`) and must be vetted.
        for inner in extract_recursion_segments(cmd_raw) {
            detect_installs_into(&inner, depth + 1, out);
        }
    } else if !extract_recursion_segments(cmd_raw).is_empty() {
        out.push(ParsedInstall {
            ecosystem: Ecosystem::Npm, // ecosystem-agnostic; pick one
            packages: Vec::new(),
            has_editable: false,
            unvettable: Some(format!(
                "recursion depth limit ({}) reached — nested shell payload exceeds vetting capacity, treat as unvettable",
                MAX_RECURSION_DEPTH
            )),
        });
    }
}

/// Last path component of a token, stripping POSIX (`/`) and Windows (`\`)
/// separators, then dropping trailing Windows launcher extensions
/// (`.cmd` / `.exe` / `.bat`) case-insensitively in a loop so chained
/// extensions like `npm.cmd.exe` collapse to `npm`. Used to normalise an
/// installer command head before matching `"npm"` / `"pnpm"` / `"yarn"` —
/// both `/Users/.../bin/npm` and `C:\Tools\npm.cmd` (and `NPM.CMD`,
/// `npm.cmd.exe`) classify as `npm`. Returns the original-cased subslice
/// so callers can still see the source casing if needed — match arms
/// should compare with `eq_ignore_ascii_case` or lowercase first.
/// Is this token one of the canonical Yarn diagnostic flags that should NOT
/// be classified as a bare-install verb? `yarn --version`, `yarn -v`,
/// `yarn --help`, `yarn -h` are query-style invocations — they read state
/// and exit without touching the dependency tree. Codex peer-review LOW on
/// #143 flagged the bare-yarn rule's over-match for these.
fn is_yarn_help_or_version_flag(tok: &str) -> bool {
    matches!(tok, "--version" | "-v" | "--help" | "-h")
}

fn installer_basename(tok: &str) -> &str {
    let mut base = tok.rsplit(['/', '\\']).next().unwrap_or(tok);
    // Loop: strip the longest matching suffix until none match.
    loop {
        let mut stripped = false;
        for suffix in [".cmd", ".exe", ".bat"] {
            if base.len() >= suffix.len()
                && base[base.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            {
                base = &base[..base.len() - suffix.len()];
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    base
}

/// Scan the shell token stream for package-manager install verbs that
/// resolve their package set from a lockfile (no package-name token
/// follows). Covers npm/pnpm/yarn (via lockfile install) plus
/// `poetry install` and `uv sync` (which resolve from
/// pyproject.toml / uv.lock — Antigravity peer-review HIGH).
///
/// A package name is a bare token that is neither a flag (`-`-prefixed)
/// nor a shell operator; trailing flags and shell operators must NOT
/// defeat the classification. A verb followed by a package token is left
/// for the package-bearing regexes above.
fn detect_bare_lockfile_installs(
    cmd: &str,
    claimed: &mut Vec<(usize, usize)>,
    out: &mut Vec<ParsedInstall>,
) {
    let tokens = shell_tokens(cmd);
    // Look-ahead helper that lowercases the Nth token relative to `idx` so
    // verb sub-commands like `INSTALL`, `Ci`, `Sync` classify the same as
    // their canonical lowercase form (Windows file-systems and shells are
    // case-preserving but case-insensitive on the head; the gate must agree).
    let next_lower = |i: usize| {
        tokens
            .get(i)
            .map(|(_, t)| t.to_ascii_lowercase())
    };

    let mut idx = 0;
    while idx < tokens.len() {
        let (start, raw_tok) = (&tokens[idx].0, tokens[idx].1.as_str());
        // Basename-normalise the head token before matching. `installer_basename`
        // strips POSIX/Windows path separators AND `.cmd`/`.exe`/`.bat`
        // (case-insensitively, looping for `npm.cmd.exe`-style chains).
        // Lowercase the result so `NPM`, `Npm`, `PNPM` etc. all classify
        // alongside their canonical form. Closes the abs/relative-path
        // bypass observed on 2026-05-23 plus Codex/agy peer-review HIGH on #142.
        let tok_norm = installer_basename(raw_tok).to_ascii_lowercase();
        // Identify an install-verb head and what it implies.
        //   `bare_eco`        — ecosystem of this bare lockfile install.
        //   `accepts_packages` — true if the verb may take a positional
        //                       package (so a non-flag token after the verb
        //                       means "not bare"). For verbs that *never*
        //                       take a positional package (poetry install,
        //                       uv sync, uv pip sync, npm ci, yarn install,
        //                       bare yarn) this is false, and the package
        //                       scan is skipped — closes the Codex+agy
        //                       BLOCKER where `poetry install --with dev`
        //                       (and `uv sync --extra dev`) misclassified
        //                       `dev` as a package and silently Skipped.
        let (verb_span_end_idx, bare_eco, accepts_packages) = match tok_norm.as_str() {
            "npm" | "pnpm" => {
                match next_lower(idx + 1).as_deref() {
                    // `npm install` / `pnpm install` / pnpm `i` *can* take a
                    // package. Keep the scan to distinguish bare-vs-named —
                    // though the named case is normally claimed upstream by
                    // NPM_RE / PNPM_RE; this is the fallback.
                    Some("install") | Some("i") => (idx + 1, Some(Ecosystem::Npm), true),
                    // `npm ci` / `pnpm ci` never takes a package — value-
                    // consuming flags don't apply, always bare.
                    Some("ci") => (idx + 1, Some(Ecosystem::Npm), false),
                    _ => {
                        idx += 1;
                        continue;
                    }
                }
            }
            "yarn" => match next_lower(idx + 1).as_deref() {
                // `yarn install` never takes a positional package.
                Some("install") => (idx + 1, Some(Ecosystem::Npm), false),
                // Bare `yarn` or `yarn` followed by a shell operator IS an
                // install (no sub-command = `yarn install` shorthand).
                // BUT `yarn --version`, `yarn -v`, `yarn --help`, `yarn -h`
                // are diagnostic invocations that do NOT install anything.
                // Codex peer review on #143 flagged the bare over-match;
                // exclude the known help/version flags here.
                Some(next) if is_yarn_help_or_version_flag(next) => {
                    idx += 1;
                    continue;
                }
                Some(next) if next.starts_with('-') || is_shell_operator(next) => {
                    (idx, Some(Ecosystem::Npm), false)
                }
                None => (idx, Some(Ecosystem::Npm), false),
                _ => {
                    idx += 1;
                    continue;
                }
            },
            // `poetry install` resolves from pyproject.toml / poetry.lock and
            // takes ONLY flag arguments (`--with <group>`, `--without`,
            // `--only`, `--no-root`, `--sync`, …). Never a positional
            // package — `poetry add foo` is the package-bearing form,
            // claimed by POETRY_RE upstream.
            "poetry" => match next_lower(idx + 1).as_deref() {
                Some("install") => (idx + 1, Some(Ecosystem::Pypi), false),
                _ => {
                    idx += 1;
                    continue;
                }
            },
            // `uv sync` (and `uv pip sync`) resolves from uv.lock. Takes
            // only flag arguments (`--extra <name>`, `--group <name>`,
            // `--no-extra`, `--no-group`, `--inexact`, …). Never a positional
            // package — `uv install foo` / `uv add foo` / `uv pip install foo`
            // are package-bearing and claimed by UV_RE upstream.
            "uv" => match next_lower(idx + 1).as_deref() {
                Some("sync") => (idx + 1, Some(Ecosystem::Pypi), false),
                Some("pip") if next_lower(idx + 2).as_deref() == Some("sync") => {
                    (idx + 2, Some(Ecosystem::Pypi), false)
                }
                _ => {
                    idx += 1;
                    continue;
                }
            },
            _ => {
                idx += 1;
                continue;
            }
        };

        let Some(eco) = bare_eco else {
            idx += 1;
            continue;
        };

        // For verbs that can take a positional package, walk the tokens
        // after the verb: stop at the first shell operator. A non-flag,
        // non-operator token is a package name → NOT a bare install.
        //
        // Verbs that NEVER take a positional skip this scan unconditionally,
        // so value-consuming flag arguments (`--with dev`, `--extra dev`)
        // do not flip `has_package` to true and cause a silent miss.
        let has_package = if accepts_packages {
            let mut found = false;
            let mut scan = verb_span_end_idx + 1;
            while scan < tokens.len() {
                let t = tokens[scan].1.as_str();
                if is_shell_operator(t) {
                    break;
                }
                if !t.starts_with('-') {
                    found = true;
                    break;
                }
                scan += 1;
            }
            found
        } else {
            false
        };

        if !has_package {
            // Skip if a higher-priority pattern already claimed this span.
            if !claimed.iter().any(|(s, e)| *start >= *s && *start < *e) {
                // Claim the full verb span (head token through the verb
                // token), not just the head — the end is read by no later
                // pass today, but a short span would silently break dedup
                // if another detector is added after this one.
                let verb_end = tokens[verb_span_end_idx].0
                    + tokens[verb_span_end_idx].1.len();
                claimed.push((*start, verb_end));
                out.push(ParsedInstall {
                    ecosystem: eco,
                    packages: Vec::new(),
                    has_editable: false,
                    unvettable: Some(match eco {
                        Ecosystem::Npm => "bare lockfile install — pulls the dependency tree \
                                           from package-lock.json/pnpm-lock.yaml/yarn.lock \
                                           the gate cannot vet"
                            .to_string(),
                        Ecosystem::Pypi => "bare lockfile install — pulls the dependency tree \
                                            from poetry.lock/uv.lock/pyproject.toml the gate \
                                            cannot vet"
                            .to_string(),
                    }),
                });
            }
        }

        idx = verb_span_end_idx + 1;
    }
}

/// Split a CLI argument token into `(flag, attached_value)`.
///
/// Returns `None` when the token is not a flag (does not start with `-`).
/// For a flag, the value is `Some` only when an attached `=` form is used:
///   `--requirement=req.txt` -> `("--requirement", Some("req.txt"))`
///   `-r=req.txt`            -> `("-r", Some("req.txt"))`
///   `--requirement`         -> `("--requirement", None)`
///   `-r`                    -> `("-r", None)`
/// This mirrors the established `a == "--config" || a.starts_with("--config=")`
/// attached-form handling used by other arg checkers in the codebase.
fn split_attached_flag(tok: &str) -> Option<(&str, Option<&str>)> {
    if !tok.starts_with('-') {
        return None;
    }
    match tok.split_once('=') {
        Some((flag, value)) => Some((flag, Some(value))),
        None => Some((tok, None)),
    }
}

/// Returns (registry-package-names with optional pinned version,
/// saw_editable_arg, lockfile_source). `lockfile_source` is `Some(detail)`
/// when a `-r`/`--requirement`/`-c`/`--constraint` indirection flag was seen
/// (in either the separate or attached `=` form).
fn parse_package_args(s: &str) -> (Vec<(String, Option<String>)>, bool, Option<String>) {
    let mut pkgs = Vec::new();
    let mut editable = false;
    let mut lockfile_source: Option<String> = None;
    let mut tokens = s.split_whitespace().peekable();

    while let Some(tok) = tokens.next() {
        if tok == "-e" || tok == "--editable" {
            editable = true;
            tokens.next();
            continue;
        }
        // Requirements / constraints indirection. Accept BOTH the separate
        // form (`-r req.txt`, `--requirement req.txt`) and the attached `=`
        // form (`--requirement=req.txt`, `-r=req.txt`). When the file is
        // attached, the value travels in the same token — splitting on `=`
        // recovers it. Either way, set `lockfile_source` so the install is
        // flagged unvettable (#111 G1 follow-up).
        if let Some((flag, attached)) = split_attached_flag(tok) {
            if matches!(flag, "-r" | "--requirement" | "-c" | "--constraint") {
                let target: String = match attached {
                    Some(v) => v.to_string(),
                    None => tokens.next().unwrap_or("(unspecified)").to_string(),
                };
                lockfile_source.get_or_insert_with(|| {
                    format!(
                        "install reads packages from '{}' ({}) — the gate cannot vet a \
                         requirements/constraints file",
                        target, flag
                    )
                });
                continue;
            }
            if matches!(flag, "-t" | "--target" | "--index-url") {
                // Value-bearing flag: consume the value token only when it
                // was NOT attached with `=`.
                if attached.is_none() {
                    tokens.next();
                }
                continue;
            }
        }
        if tok.starts_with('-') {
            continue;
        }
        if tok == "."
            || tok.starts_with(".[")
            || tok.starts_with("./")
            || tok.starts_with("../")
            || tok.starts_with("/")
            || tok.starts_with("file:")
            || tok.starts_with("git+")
            || tok.starts_with("http://")
            || tok.starts_with("https://")
        {
            editable = true;
            continue;
        }

        let (name, version) = split_name_version(tok);
        if !name.is_empty() {
            pkgs.push((name, version));
        }
    }

    (pkgs, editable, lockfile_source)
}

/// Split a token like `requests==2.20.0`, `@types/node@22.10.0`, or `lodash`
/// into (name, optional pinned version). Only exact pins (`==X`, `name@X`)
/// are returned; ranges like `>=2.0` yield None for the version (we don't
/// pin a range to query).
fn split_name_version(s: &str) -> (String, Option<String>) {
    let stripped = s.trim_matches(|c: char| c == '"' || c == '\'');

    // npm scoped: @scope/name[@version]
    if let Some(rest) = stripped.strip_prefix('@') {
        if let Some(slash_idx) = rest.find('/') {
            let after_slash = &rest[slash_idx + 1..];
            if let Some(at_idx) = after_slash.find('@') {
                let name = format!("@{}/{}", &rest[..slash_idx], &after_slash[..at_idx]);
                let ver = after_slash[at_idx + 1..].to_string();
                let ver = if ver.is_empty() { None } else { Some(ver) };
                return (name, ver);
            }
            return (format!("@{}/{}", &rest[..slash_idx], after_slash), None);
        }
        return (format!("@{}", rest), None);
    }
    // pip exact pin
    if let Some(idx) = stripped.find("==") {
        return (
            stripped[..idx].to_string(),
            Some(stripped[idx + 2..].to_string()),
        );
    }
    // pip range specifiers — drop the spec, leave version None
    for sep in [">=", "<=", "~=", "!=", ">", "<"] {
        if let Some(idx) = stripped.find(sep) {
            return (stripped[..idx].to_string(), None);
        }
    }
    // npm: name@version
    if let Some(idx) = stripped.find('@') {
        return (
            stripped[..idx].to_string(),
            Some(stripped[idx + 1..].to_string()),
        );
    }
    (stripped.to_string(), None)
}

// ---------------------------------------------------------------------------
// HTTP queries
// ---------------------------------------------------------------------------

/// 8 MB cap on a single HTTP response body (SEC-I2).
///
/// The previous 64 MB cap was sized for npm's full `/<pkg>` document, but the
/// gate only ever reads `dist-tags` + `time` (npm) or `info`/`releases`/`urls`
/// (PyPI) — a few KB. For npm we also send the abbreviated-metadata `Accept`
/// header (`application/vnd.npm.install-v1+json`), which the registry honours
/// by returning a document ~100x smaller. 8 MB is comfortably above any
/// legitimate abbreviated response while denying a hostile registry the
/// ability to stream 64 MB per package into a short-lived hook process.
const HTTP_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// npm abbreviated-metadata media type. The registry returns a far smaller
/// document (dist-tags + per-version essentials) when this is the `Accept`
/// header. The `time` map and `dist-tags` we rely on are still present.
const NPM_ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";

fn read_body(resp: ureq::Response) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    // `take` caps the read; if the body would exceed the cap we still only
    // pull `HTTP_MAX_BYTES`, so a hostile infinite/huge response cannot
    // exhaust memory. A truncated body then fails JSON parsing -> Err ->
    // the caller fails closed to Ask.
    resp.into_reader()
        .take(HTTP_MAX_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body: {}", e))?;
    Ok(buf)
}

fn http_get_json(url: &str) -> Result<Value, String> {
    let mut req = ureq::get(url)
        .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
        .timeout(StdDuration::from_secs(8));
    // Request npm's abbreviated metadata where applicable — ~100x smaller.
    // PyPI ignores the header, so it is safe to send unconditionally for npm
    // hosts only.
    if url.starts_with("https://registry.npmjs.org/") {
        req = req.set("Accept", NPM_ABBREVIATED_ACCEPT);
    }
    let resp = req
        .call()
        .map_err(|e| format!("HTTP {}: {}", url, e))?;
    let buf = read_body(resp)?;
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let resp = ureq::post(url)
        .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
        .set("Content-Type", "application/json")
        .timeout(StdDuration::from_secs(8))
        .send_string(&body.to_string())
        .map_err(|e| format!("HTTP {}: {}", url, e))?;
    let buf = read_body(resp)?;
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

/// Resolve (version, publish_time) for the package. If `pinned` is Some, use
/// that version; otherwise resolve and use the registry's `latest`.
/// Cache keys include the version so pinned-and-unpinned don't collide.
fn npm_metadata(pkg: &str, pinned: Option<&str>) -> Result<(String, DateTime<Utc>), String> {
    let cache_key = format!("{}@{}", pkg, pinned.unwrap_or("__latest__"));
    if let Some(cached) = cache_get(Ecosystem::Npm, &cache_key) {
        return Ok(cached);
    }
    // Always query the full /<pkg> doc since per-version endpoints don't
    // expose publish times.
    let url = format!("https://registry.npmjs.org/{}", urlencoding(pkg));
    let v = http_get_json(&url)?;
    let resolved = match pinned {
        Some(ver) => ver.to_string(),
        None => v
            .pointer("/dist-tags/latest")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "no dist-tags/latest".to_string())?
            .to_string(),
    };
    let ts = v
        .pointer(&format!("/time/{}", resolved))
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("no publish time for version {}", resolved))?;
    let publish = parse_iso8601(ts)?;
    cache_put(Ecosystem::Npm, &cache_key, &resolved, &publish);
    Ok((resolved, publish))
}

fn pypi_metadata(pkg: &str, pinned: Option<&str>) -> Result<(String, DateTime<Utc>), String> {
    let cache_key = format!("{}@{}", pkg, pinned.unwrap_or("__latest__"));
    if let Some(cached) = cache_get(Ecosystem::Pypi, &cache_key) {
        return Ok(cached);
    }
    // When pinned, use the version-specific endpoint (smaller response).
    // Otherwise hit the package endpoint to discover `info.version` and the
    // release files.
    if let Some(ver) = pinned {
        let url = format!(
            "https://pypi.org/pypi/{}/{}/json",
            urlencoding(pkg),
            urlencoding(ver)
        );
        let v = http_get_json(&url)?;
        let urls = v
            .get("urls")
            .and_then(|x| x.as_array())
            .ok_or_else(|| "no urls in pypi response".to_string())?;
        let first = urls
            .first()
            .ok_or_else(|| "empty urls list".to_string())?;
        let ts = first
            .get("upload_time_iso_8601")
            .or_else(|| first.get("upload_time"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| "no upload_time".to_string())?;
        let publish = parse_iso8601(ts)?;
        cache_put(Ecosystem::Pypi, &cache_key, ver, &publish);
        return Ok((ver.to_string(), publish));
    }
    let url = format!("https://pypi.org/pypi/{}/json", urlencoding(pkg));
    let v = http_get_json(&url)?;
    let latest = v
        .pointer("/info/version")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "no info/version".to_string())?
        .to_string();
    let arr = v
        .pointer(&format!("/releases/{}", latest))
        .and_then(|x| x.as_array())
        .ok_or_else(|| "no releases".to_string())?;
    let first = arr.first().ok_or_else(|| "empty releases".to_string())?;
    let ts = first
        .get("upload_time_iso_8601")
        .or_else(|| first.get("upload_time"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| "no upload_time".to_string())?;
    let publish = parse_iso8601(ts)?;
    cache_put(Ecosystem::Pypi, &cache_key, &latest, &publish);
    Ok((latest, publish))
}

/// Parse an ISO-8601 / RFC-3339 timestamp into a UTC `DateTime`.
///
/// SEC-I3 hardening: the package-age cooldown is the gate's primary control.
/// A misparse that yields a far-past date silently skips the cooldown, and a
/// far-future date used to be clamped to zero age — both wave a package
/// through. So:
///   - A failed parse is an error (`Err`), never a silent fallback. The old
///     `{}Z`-suffix retry could coerce a malformed string into a bogus value;
///     we keep a *conservative* retry only for the bare missing-`Z` case
///     (`2024-01-01T00:00:00` -> append `Z`) and reject everything else.
///   - A parsed timestamp more than ~1 day in the future is rejected as an
///     error rather than clamped — a future publish date is not trustworthy
///     and must not be allowed to satisfy the cooldown.
fn parse_iso8601(s: &str) -> Result<DateTime<Utc>, String> {
    let parsed = DateTime::parse_from_rfc3339(s)
        .or_else(|_| {
            // Conservative retry: only for a timestamp that is well-formed
            // except for a missing trailing `Z`. We do NOT strip an existing
            // `Z` and re-append (that masked malformed input). The string
            // must not already carry a timezone designator.
            let t = s.trim();
            // This guard rejects strings that already carry a `Z` or a `+HH:MM`
            // offset (re-appending `Z` would mask malformed input). It does NOT
            // need to test for `-HH:MM` negative offsets: a well-formed negative
            // offset is parsed by the primary `parse_from_rfc3339` above and
            // never reaches this retry. A malformed string with a `-` that
            // slips through gets `Z` appended, producing invalid RFC3339 (two
            // timezone designators) that `parse_from_rfc3339` rejects — so the
            // gap fails closed. The guard gap is harmless.
            if t.ends_with('Z') || t.contains('+') {
                Err("malformed timestamp".to_string())
            } else {
                DateTime::parse_from_rfc3339(&format!("{}Z", t)).map_err(|e| e.to_string())
            }
        })
        .map_err(|_| format!("unparseable timestamp: {:?}", s))?;

    let dt = parsed.with_timezone(&Utc);

    // Reject implausibly future-dated timestamps. A package cannot have been
    // published more than a day from now; treating such a value as valid
    // would let a hostile registry skip the age cooldown.
    let skew = ChronoDuration::days(1);
    if dt > Utc::now() + skew {
        return Err(format!(
            "timestamp {} is more than {}d in the future — refusing to trust it",
            dt,
            skew.num_days()
        ));
    }

    Ok(dt)
}

fn urlencoding(s: &str) -> String {
    // Minimal percent-encoding for path segments.
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b'@' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Query OSV.dev for any vulns affecting (ecosystem, package, version).
/// Returns (id, summary, severity) per vuln so callers can apply a threshold.
fn osv_query(
    eco: Ecosystem,
    pkg: &str,
    version: &str,
) -> Result<Vec<(String, String, Severity)>, String> {
    let body = serde_json::json!({
        "package": { "name": pkg, "ecosystem": eco.as_str() },
        "version": version
    });
    let v = http_post_json("https://api.osv.dev/v1/query", &body)?;
    let vulns = v
        .get("vulns")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(vulns
        .iter()
        .filter_map(|vuln| {
            let id = vuln.get("id").and_then(|x| x.as_str())?.to_string();
            let summary = vuln
                .get("summary")
                .and_then(|x| x.as_str())
                .unwrap_or("(no summary)")
                .to_string();
            let severity = osv_severity(vuln);
            Some((id, summary, severity))
        })
        .collect())
}

/// Extract a CVSS-style severity from an OSV vuln record. Best-effort.
fn osv_severity(vuln: &Value) -> Severity {
    if let Some(arr) = vuln.get("severity").and_then(|x| x.as_array()) {
        for entry in arr {
            if let Some(score) = entry.get("score").and_then(|x| x.as_str()) {
                if score.contains("CRITICAL") {
                    return Severity::Critical;
                } else if score.contains("HIGH") {
                    return Severity::High;
                } else if score.contains("MEDIUM") || score.contains("MODERATE") {
                    return Severity::Medium;
                } else if score.contains("LOW") {
                    return Severity::Low;
                }
            }
        }
    }
    if let Some(arr) = vuln.get("database_specific").and_then(|x| x.as_object()) {
        if let Some(sev) = arr.get("severity").and_then(|x| x.as_str()) {
            if let Some(parsed) = Severity::parse(sev) {
                return parsed;
            }
        }
    }
    // Default if unknown: assume HIGH so it doesn't silently slip past a HIGH threshold.
    Severity::High
}

// ---------------------------------------------------------------------------
// Cache (24h, file-based)
// ---------------------------------------------------------------------------

fn cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("contextcrawler").join("supply-chain"))
}

fn cache_file(eco: Ecosystem, pkg: &str) -> Option<PathBuf> {
    // Refuse anything that could escape the cache directory or smuggle a
    // path separator the caller didn't anticipate. Real npm/pypi names
    // are an allowlist of [A-Za-z0-9._@/-]; we additionally reject `..`
    // sequences and any backslash. If we can't represent the name
    // safely we skip the cache (worst case: re-query the registry).
    if pkg.is_empty()
        || pkg.contains("..")
        || pkg.contains('\\')
        || pkg
            .chars()
            .any(|c| c.is_control() || c == ':' || c == '*' || c == '?')
    {
        return None;
    }
    let safe = pkg.replace('/', "_").replace('@', "_at_");
    cache_dir().map(|d| d.join(format!("{}-{}.json", eco.as_str(), safe)))
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    version: String,
    publish_time: String,
    fetched_at: String,
}

fn cache_get(eco: Ecosystem, pkg: &str) -> Option<(String, DateTime<Utc>)> {
    let path = cache_file(eco, pkg)?;
    let content = fs::read_to_string(&path).ok()?;
    let entry: CacheEntry = serde_json::from_str(&content).ok()?;
    let fetched = parse_iso8601(&entry.fetched_at).ok()?;
    if (Utc::now() - fetched) > ChronoDuration::hours(24) {
        return None;
    }
    let publish = parse_iso8601(&entry.publish_time).ok()?;
    Some((entry.version, publish))
}

fn cache_put(eco: Ecosystem, pkg: &str, version: &str, publish: &DateTime<Utc>) {
    let Some(path) = cache_file(eco, pkg) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let entry = CacheEntry {
        version: version.to_string(),
        publish_time: publish.to_rfc3339(),
        fetched_at: Utc::now().to_rfc3339(),
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        let _ = fs::write(&path, json);
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Inspect a shell command. Returns Skip if not an install / gate disabled.
pub fn check(cmd: &str) -> Verdict {
    let config = load_config();
    if !config.supply_chain.enabled {
        return Verdict::Skip;
    }
    if std::env::var("CONTEXTCRAWLER_SUPPLY_CHAIN").as_deref() == Ok("off") {
        return Verdict::Skip;
    }

    let installs = detect_installs(cmd);
    if installs.is_empty() {
        return Verdict::Skip;
    }

    // SEC-I2: package-count cap. A command installing more distinct packages
    // than we can vet within budget is failed closed to Ask rather than
    // issuing dozens of serial registry/OSV requests.
    let total_packages: usize = installs.iter().map(|i| i.packages.len()).sum();
    if total_packages > MAX_PACKAGES_PER_CHECK {
        return Verdict::Ask(vec![Finding {
            package: format!("<{} packages>", total_packages),
            ecosystem: "multiple".to_string(),
            reason: FindingReason::UnvettableInstall {
                detail: format!(
                    "install lists {} packages — more than the {} the gate will vet \
                     in one command. Confirm to proceed, or split the install.",
                    total_packages, MAX_PACKAGES_PER_CHECK
                ),
            },
            severity: Severity::Medium,
        }]);
    }

    // SEC-I2: aggregate wall-clock budget. Each registry/OSV call has its own
    // 8s timeout; this deadline bounds the whole `check()` so a slow/hostile
    // registry cannot stall the hook for minutes.
    let started = Instant::now();
    let budget_exceeded = || started.elapsed() >= CHECK_WALL_BUDGET;

    let mut findings = Vec::new();
    // Findings that should downgrade to Ask (fail-closed-to-confirm) rather
    // than a hard Block. An unvettable install (lockfile / requirements file)
    // is not a known-bad package — we just can't enumerate what it pulls.
    let mut ask_findings = Vec::new();
    let mut transient_err: Option<String> = None;
    // Set when the wall-clock budget runs out mid-vetting. The remaining
    // packages are unvetted, so we fail closed.
    let mut budget_blown = false;

    for install in installs {
        if budget_exceeded() {
            budget_blown = true;
            break;
        }
        let eco_cfg = match install.ecosystem {
            Ecosystem::Npm => &config.npm,
            Ecosystem::Pypi => &config.pypi,
        };
        let block_threshold = Severity::parse(&eco_cfg.block_severity).unwrap_or(Severity::High);

        // Install verb detected but the package set is unvettable: it comes
        // from a lockfile / requirements / constraints file the gate cannot
        // enumerate. Surface it (fail closed to Ask) instead of dropping the
        // install silently as a Skip — see #111 G1.
        if let Some(detail) = &install.unvettable {
            ask_findings.push(Finding {
                package: "<lockfile / requirements install>".to_string(),
                ecosystem: install.ecosystem.as_str().to_string(),
                reason: FindingReason::UnvettableInstall {
                    detail: detail.clone(),
                },
                severity: Severity::Medium,
            });
        }

        // Editable / path / URL token detected. If the ecosystem disallows
        // these (default for npm), we can't query a registry for that
        // source — surface a finding so the user reviews manually. Either
        // way we fall through and still vet any sibling named packages
        // (e.g. `pip install -e . requests` must still check `requests`).
        if install.has_editable && !eco_cfg.allow_editable {
            findings.push(Finding {
                package: "<editable / path / url>".to_string(),
                ecosystem: install.ecosystem.as_str().to_string(),
                reason: FindingReason::UnvettableSource {
                    token_kind: "editable_or_url".to_string(),
                },
                severity: Severity::High,
            });
        }

        // Dedupe within an install: pip install foo bar foo -> check foo once.
        let mut seen = std::collections::HashSet::<(String, Option<String>)>::new();
        for (pkg, pinned) in install.packages {
            // SEC-I2: stop vetting once the aggregate budget is spent. The
            // remaining packages are unvetted — fail closed below.
            if budget_exceeded() {
                budget_blown = true;
                break;
            }

            let key = (pkg.clone(), pinned.clone());
            if !seen.insert(key) {
                continue;
            }

            if matches_override(&pkg, &config.overrides.always_allow) {
                continue;
            }
            if matches_override(&pkg, &config.overrides.always_deny) {
                findings.push(Finding {
                    package: pkg.clone(),
                    ecosystem: install.ecosystem.as_str().to_string(),
                    reason: FindingReason::RecentRelease {
                        age_days: 0.0,
                        cooldown_days: 0,
                        version: "*".into(),
                    },
                    severity: Severity::Critical,
                });
                continue;
            }

            // Age check against (resolved or pinned) version
            let registry_result = match install.ecosystem {
                Ecosystem::Npm => npm_metadata(&pkg, pinned.as_deref()),
                Ecosystem::Pypi => pypi_metadata(&pkg, pinned.as_deref()),
            };
            let (version, publish) = match registry_result {
                Ok(v) => v,
                Err(e) => {
                    transient_err.get_or_insert(e);
                    continue;
                }
            };
            // SEC-I2: a registry-metadata call can itself take seconds. Re-check
            // the budget immediately after it so a single slow network call
            // cannot push us past the deadline before the next loop top.
            if budget_exceeded() {
                budget_blown = true;
                break;
            }
            // Clamp negative ages (registry/publisher clock skew, or a
            // genuinely future-dated entry) to zero so they always fall
            // below the cooldown threshold instead of skating past both
            // bounds of the old `> -1d` guard.
            let age = (Utc::now() - publish).max(ChronoDuration::zero());
            if age < ChronoDuration::days(eco_cfg.cooldown_days as i64) {
                findings.push(Finding {
                    package: pkg.clone(),
                    ecosystem: install.ecosystem.as_str().to_string(),
                    reason: FindingReason::RecentRelease {
                        age_days: age.num_seconds() as f64 / 86_400.0,
                        cooldown_days: eco_cfg.cooldown_days,
                        version: version.clone(),
                    },
                    severity: Severity::High,
                });
            }

            // CVE check against the specific resolved/pinned version
            if let Ok(vulns) = osv_query(install.ecosystem, &pkg, &version) {
                for (id, summary, sev) in vulns {
                    if sev >= block_threshold {
                        findings.push(Finding {
                            package: pkg.clone(),
                            ecosystem: install.ecosystem.as_str().to_string(),
                            reason: FindingReason::KnownVulnerability { id, summary },
                            severity: sev,
                        });
                    }
                }
            }
            // SEC-I2: an osv_query can take up to ~8s. Re-check the budget
            // right after it so the deadline cannot be overrun by a full slow
            // OSV call per package before the loop top is reached again.
            if budget_exceeded() {
                budget_blown = true;
                break;
            }
        }
    }

    // A hard Block (known-bad package / failed gate) outranks everything:
    // a package we positively identified as bad stays blocked even if the
    // budget later ran out.
    if !findings.is_empty() {
        return Verdict::Block(findings);
    }
    // SEC-I2: the wall-clock budget ran out before every package was vetted.
    // The remainder is unvetted, so fail closed rather than waving it through.
    if budget_blown {
        let budget_msg = format!(
            "vetting budget exceeded ({}s) — install not fully vetted",
            CHECK_WALL_BUDGET.as_secs()
        );
        // If we already accumulated Ask findings (e.g. an unvettable lockfile
        // install) before the budget expired, do not discard them: surface
        // them as Ask so the user sees the real concern, with an extra
        // finding noting the budget was exceeded so later packages went
        // unvetted. Block still outranks this (handled above).
        if !ask_findings.is_empty() {
            ask_findings.push(Finding {
                package: "<vetting budget exceeded>".to_string(),
                ecosystem: "*".to_string(),
                reason: FindingReason::UnvettableInstall { detail: budget_msg },
                severity: Severity::Medium,
            });
            return Verdict::Ask(ask_findings);
        }
        return Verdict::Unavailable(budget_msg);
    }
    if let Some(e) = transient_err {
        return Verdict::Unavailable(e);
    }
    // No hard findings, but one or more installs are unvettable — fail closed
    // to Ask so the user confirms the unvetted package set.
    if !ask_findings.is_empty() {
        return Verdict::Ask(ask_findings);
    }
    Verdict::Allow
}

fn matches_override(pkg: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if let Some(prefix) = pat.strip_suffix("/*") {
            if pkg.starts_with(prefix) && pkg.len() > prefix.len() {
                return true;
            }
        } else if pat == pkg {
            return true;
        }
    }
    false
}

/// One package extracted from an install command for telemetry purposes.
/// Best-effort, regex-based — captures package identity even when the gate
/// returns `Allow` (in which case there are no findings to inspect).
/// Closes codex peer-review HIGH (#162/#172): Allow-path installs used to
/// collapse to placeholder rows because `Verdict::Allow` carries no findings.
#[derive(Debug, Clone)]
pub struct TelemetryPackage {
    pub package: String,
    pub ecosystem: String,
}

lazy_static::lazy_static! {
    // Anchor mirrors the install-detect regexes — `/`, `\`, whitespace,
    // and shell operators all count as command-start delimiters.
    static ref NPM_INSTALL_RE: regex::Regex = regex::Regex::new(
        r"(?:^|[\s;/\\]|&&|\|\|)(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\s+([^\n|;&<>]+)"
    ).unwrap();
    static ref PIP_INSTALL_RE: regex::Regex = regex::Regex::new(
        r"(?:^|[\s;/\\]|&&|\|\|)(?:pip|pip3|uv\s+pip|poetry\s+add|pipx\s+install)\s+(?:install\s+)?([^\n|;&<>]+)"
    ).unwrap();
    static ref CARGO_INSTALL_RE: regex::Regex = regex::Regex::new(
        r"(?:^|[\s;/\\]|&&|\|\|)cargo\s+(?:add|install)\s+([^\n|;&<>]+)"
    ).unwrap();
    static ref GEM_INSTALL_RE: regex::Regex = regex::Regex::new(
        r"(?:^|[\s;/\\]|&&|\|\|)gem\s+install\s+([^\n|;&<>]+)"
    ).unwrap();
}

/// Best-effort extraction of package names from an install command. Returns
/// an empty vec for non-install commands. Used only for telemetry — the
/// real gate uses the full detect_installs pipeline.
pub fn extract_packages_for_telemetry(cmd: &str) -> Vec<TelemetryPackage> {
    let mut out = Vec::new();
    let mut push_pkgs = |captures_iter: regex::CaptureMatches, ecosystem: &str| {
        for cap in captures_iter {
            if let Some(args) = cap.get(1) {
                for tok in args.as_str().split_whitespace() {
                    if let Some(pkg) = normalise_install_token(tok) {
                        out.push(TelemetryPackage {
                            package: pkg,
                            ecosystem: ecosystem.to_string(),
                        });
                    }
                }
            }
        }
    };
    push_pkgs(NPM_INSTALL_RE.captures_iter(cmd), "npm");
    push_pkgs(PIP_INSTALL_RE.captures_iter(cmd), "PyPI");
    push_pkgs(CARGO_INSTALL_RE.captures_iter(cmd), "cargo");
    push_pkgs(GEM_INSTALL_RE.captures_iter(cmd), "RubyGems");
    out
}

/// Strip version pins / flags / paths from a single install-arg token.
/// Handles npm scoped names (`@scope/name`, `@scope/name@^4.0`) correctly.
/// Returns `None` if the token is a flag, a path/URL/lockfile, or empty.
fn normalise_install_token(tok: &str) -> Option<String> {
    // Flags: `-g`, `--save-dev`, etc.
    if tok.starts_with('-') {
        return None;
    }
    // Strip version pins. `@scope/name@version` splits via rsplit_once('@').
    // Bare `name@version` and `name==version` use the leading delimiter.
    let pkg = if let Some(rest) = tok.strip_prefix('@') {
        // Scoped — keep the `@` prefix, strip any trailing `@version`.
        match rest.rsplit_once('@') {
            Some((name, _)) => format!("@{name}"),
            None => tok.to_string(),
        }
    } else {
        // Bare — split on first `@`, `==`, `>=`, `~=`, `<=`, `>`, `<`.
        let cut = tok
            .find('@')
            .or_else(|| tok.find("=="))
            .or_else(|| tok.find(">="))
            .or_else(|| tok.find("~="))
            .or_else(|| tok.find("<="))
            .or_else(|| tok.find('>'))
            .or_else(|| tok.find('<'));
        match cut {
            Some(i) => tok[..i].to_string(),
            None => tok.to_string(),
        }
    };
    if pkg.is_empty() {
        return None;
    }
    // URL / path / file-like — the real gate handles those.
    if pkg.contains(':') {
        return None;
    }
    // Only allow `/` in scoped names (`@scope/name`).
    let slash_ok = pkg.starts_with('@') && pkg.matches('/').count() == 1;
    if pkg.contains('/') && !slash_ok {
        return None;
    }
    Some(pkg)
}

/// Append a gate event to the local log for `contextcrawler security --supply-chain-log`.
///
/// `telemetry` carries package identity for the Allow-verdict path where
/// `verdict.findings()` is empty (codex peer-review HIGH #172). Pass an
/// empty slice if the caller hasn't extracted packages.
pub fn log_event(cmd: &str, verdict: &Verdict, telemetry: &[TelemetryPackage]) {
    let Some(data_dir) = dirs::data_local_dir() else {
        return;
    };
    let dir = data_dir.join("contextcrawler");
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("supply_chain.jsonl");
    let kind = match verdict {
        Verdict::Skip => "skip",
        Verdict::Allow => "allow",
        Verdict::Block(_) => "block",
        Verdict::Ask(_) => "ask",
        Verdict::Unavailable(_) => "unavailable",
    };
    let findings_val = match verdict {
        Verdict::Block(f) | Verdict::Ask(f) => Some(f),
        _ => None,
    };
    let findings_json = findings_val
        .map(|f| serde_json::to_string(f).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());
    let ts = Utc::now().to_rfc3339();
    let record = format!(
        r#"{{"ts":"{}","verdict":"{}","cmd":{},"findings":{}}}"#,
        ts,
        kind,
        serde_json::to_string(cmd).unwrap_or_else(|_| "\"\"".into()),
        findings_json
    );
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", record);
    }

    // Mirror into the installs ledger (#172). Best-effort: any failure here
    // (no $HOME, locked DB, etc.) silently falls back to JSONL-only — the
    // backfill picks it up on next Tracker construction.
    record_install_to_db(
        &ts,
        kind,
        cmd,
        findings_val.map(|v| v.as_slice()),
        telemetry,
    );
}

/// DB-side mirror of `log_event` — populates the `installs` table so the
/// dashboard can query per-project install history without re-parsing JSONL.
///
/// Codex peer-review HIGH #172 fix: when `findings` is absent (Allow path)
/// OR carries no per-package entries, fall back to `telemetry` so the row
/// preserves package identity instead of becoming a blank placeholder.
///
/// Codex peer-review MED #172 fix: findings are aggregated by (package,
/// ecosystem) before insertion so a single package with two findings
/// (e.g. RecentRelease + KnownVulnerability) lands as one row with both
/// IDs in `finding_ids`, not as two rows where the second is silently
/// dropped by the UNIQUE(ts, raw_command, package) constraint.
///
/// project_path is `std::env::current_dir()`. JSONL backfill rows have
/// empty project_path (CWD was never captured historically).
fn record_install_to_db(
    ts: &str,
    verdict: &str,
    cmd: &str,
    findings: Option<&[Finding]>,
    telemetry: &[TelemetryPackage],
) {
    use crate::core::tracking::{InstallEvent, InstallPackage, Tracker};
    use std::collections::BTreeMap;

    let Ok(tracker) = Tracker::new() else {
        return;
    };
    // Canonicalise the CWD before persisting (codex peer-review LOW #172).
    // Symlinked project roots otherwise split across multiple dashboard
    // buckets; canonicalise_project_path falls back gracefully if the path
    // can't be resolved.
    let project_path = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .map(|s| crate::core::tracking::canonicalise_project_path(&s))
        .unwrap_or_default();

    // Aggregate findings by (package, ecosystem). BTreeMap for deterministic
    // ordering (otherwise the row contents depend on HashMap iteration order).
    let mut by_pkg: BTreeMap<(String, String), InstallPackage> = BTreeMap::new();
    if let Some(fs) = findings {
        for f in fs {
            let key = (f.package.clone(), f.ecosystem.clone());
            let resolved = match &f.reason {
                FindingReason::RecentRelease { version, .. } => Some(version.clone()),
                _ => None,
            };
            let fid = match &f.reason {
                FindingReason::KnownVulnerability { id, .. } => Some(id.clone()),
                _ => None,
            };
            let sev = format!("{:?}", f.severity).to_uppercase();
            by_pkg
                .entry(key)
                .and_modify(|p| {
                    if p.resolved_version.is_none() {
                        p.resolved_version = resolved.clone();
                    }
                    if let Some(id) = &fid {
                        if !p.finding_ids.contains(id) {
                            p.finding_ids.push(id.clone());
                        }
                    }
                    // Keep the highest severity seen.
                    if severity_rank(&sev) > severity_rank(&p.severity) {
                        p.severity = sev.clone();
                    }
                })
                .or_insert_with(|| InstallPackage {
                    ecosystem: f.ecosystem.clone(),
                    package: f.package.clone(),
                    version_spec: None,
                    resolved_version: resolved,
                    severity: sev,
                    finding_ids: fid.into_iter().collect(),
                });
        }
    }

    // Allow / Skip path: no findings, but the command might still be a real
    // install — fold telemetry packages in so we don't lose identity. Skip
    // any (package, ecosystem) already covered by a finding above.
    if by_pkg.is_empty() {
        for t in telemetry {
            let key = (t.package.clone(), t.ecosystem.clone());
            by_pkg.entry(key).or_insert_with(|| InstallPackage {
                ecosystem: t.ecosystem.clone(),
                package: t.package.clone(),
                version_spec: None,
                resolved_version: None,
                severity: String::new(),
                finding_ids: Vec::new(),
            });
        }
    }

    let packages: Vec<InstallPackage> = by_pkg.into_values().collect();
    let ev = InstallEvent {
        ts: ts.to_string(),
        project_path,
        verdict: verdict.to_string(),
        raw_command: cmd.to_string(),
        packages,
    };
    let _ = tracker.record_install(&ev);
}

/// Severity ranking for aggregation — higher wins.
fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod telemetry_extractor_tests {
    use super::extract_packages_for_telemetry;

    fn pkgs(cmd: &str) -> Vec<(String, String)> {
        extract_packages_for_telemetry(cmd)
            .into_iter()
            .map(|t| (t.package, t.ecosystem))
            .collect()
    }

    #[test]
    fn npm_bare_install() {
        assert_eq!(pkgs("npm install lodash"), vec![("lodash".into(), "npm".into())]);
    }

    #[test]
    fn npm_install_with_version_pin() {
        assert_eq!(
            pkgs("npm install express@4.18.2"),
            vec![("express".into(), "npm".into())]
        );
    }

    #[test]
    fn npm_install_scoped_package() {
        // The codex HIGH finding: `@scope/name` MUST round-trip; previous
        // implementation dropped these because of the `/` filter.
        assert_eq!(
            pkgs("npm install -g --ignore-scripts @earendil-works/pi-coding-agent"),
            vec![("@earendil-works/pi-coding-agent".into(), "npm".into())]
        );
    }

    #[test]
    fn npm_install_scoped_with_version() {
        assert_eq!(
            pkgs("npm install @types/node@^20.0.0"),
            vec![("@types/node".into(), "npm".into())]
        );
    }

    #[test]
    fn pip_install_with_pin() {
        assert_eq!(
            pkgs("pip install requests==2.20.0"),
            vec![("requests".into(), "PyPI".into())]
        );
    }

    #[test]
    fn cargo_add_with_features() {
        // `--features` is a flag — only the package should land.
        let result = pkgs("cargo add tokio --features full");
        assert!(
            result.iter().any(|(p, e)| p == "tokio" && e == "cargo"),
            "expected tokio in cargo result, got {result:?}"
        );
    }

    #[test]
    fn non_install_command_returns_empty() {
        assert!(pkgs("git status").is_empty());
        assert!(pkgs("ls -la").is_empty());
        // Note: `echo npm install foo` WILL false-positive because the
        // telemetry extractor is intentionally simpler than the real gate
        // (no data-utility allowlist, #141). This is acceptable for the
        // dashboard ledger — surfacing an echo'd install line is more
        // useful than silently dropping legitimate Allow-path installs.
    }

    #[test]
    fn url_and_path_tokens_skipped() {
        // Real gate handles these — telemetry just declines to invent a name.
        assert!(pkgs("npm install https://github.com/foo/bar.git").is_empty());
        assert!(pkgs("pip install /tmp/wheel.whl").is_empty());
    }

    #[test]
    fn multiple_packages_extracted() {
        let result = pkgs("npm install lodash express react");
        assert_eq!(result.len(), 3);
        assert!(result.iter().all(|(_, e)| e == "npm"));
    }

    #[test]
    fn flags_filtered() {
        let result = pkgs("npm install -g --save-dev lodash");
        assert_eq!(result, vec![("lodash".into(), "npm".into())]);
    }
}

/// Render a Verdict as a human-readable explanation (for hook warnings and CLI).
pub fn render(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Skip => {
            "[contextcrawler supply-chain] skipped (gate disabled or no install command)".into()
        }
        Verdict::Allow => "[contextcrawler supply-chain] all packages passed".into(),
        Verdict::Unavailable(e) => format!(
            "[contextcrawler supply-chain] WARN — gate unavailable ({}). \
             Failing closed: auto-allow downgraded to Ask.",
            e
        ),
        Verdict::Block(findings) => {
            let mut s = String::from("[contextcrawler supply-chain] BLOCKED\n");
            s.push_str(&render_findings(findings));
            s.push_str(
                "  Overrides: rerun with CONTEXTCRAWLER_SUPPLY_CHAIN=off, or add the package\n",
            );
            s.push_str("  to ~/.config/contextcrawler/supply-chain.toml [overrides.always_allow]");
            s
        }
        Verdict::Ask(findings) => {
            let mut s = String::from(
                "[contextcrawler supply-chain] WARN — install set could not be vetted. \
                 Failing closed: auto-allow downgraded to Ask.\n",
            );
            s.push_str(&render_findings(findings));
            s.push_str(
                "  Review the lockfile/requirements file, then confirm to proceed, or rerun\n",
            );
            s.push_str("  with CONTEXTCRAWLER_SUPPLY_CHAIN=off to skip the gate.");
            s
        }
    }
}

/// Render a list of findings as indented human-readable lines.
fn render_findings(findings: &[Finding]) -> String {
    let mut s = String::new();
    for f in findings {
        match &f.reason {
            FindingReason::RecentRelease {
                age_days,
                cooldown_days,
                version,
            } => {
                s.push_str(&format!(
                    "  {} [{}] @ {} published {:.2}d ago (cooldown {}d). Severity: {:?}\n",
                    f.package, f.ecosystem, version, age_days, cooldown_days, f.severity
                ));
            }
            FindingReason::KnownVulnerability { id, summary } => {
                s.push_str(&format!(
                    "  {} [{}]: {} — {} (severity {:?})\n",
                    f.package, f.ecosystem, id, summary, f.severity
                ));
            }
            FindingReason::UnvettableSource { token_kind } => {
                s.push_str(&format!(
                    "  {} [{}]: install command contained an {} token that the gate cannot query (severity {:?})\n",
                    f.package, f.ecosystem, token_kind, f.severity
                ));
            }
            FindingReason::UnvettableInstall { detail } => {
                s.push_str(&format!(
                    "  {} [{}]: {} (severity {:?})\n",
                    f.package, f.ecosystem, detail, f.severity
                ));
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn names(install: &ParsedInstall) -> Vec<&str> {
        install.packages.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn load_config_caches_after_first_read() {
        // `load_config()` is backed by a process-lifetime OnceLock. Whatever
        // the first call resolves, every subsequent call must return the
        // exact same `&'static Config` — no second disk read. Comparing the
        // pointer identity proves the cache (not just value equality).
        let first = load_config() as *const Config;
        let second = load_config() as *const Config;
        let third = load_config() as *const Config;
        assert_eq!(first, second);
        assert_eq!(second, third);
    }

    #[test]
    fn detect_npm_install() {
        let v = detect_installs("npm install lodash express");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash", "express"]);
    }

    #[test]
    fn detect_pip_install_with_pin() {
        let v = detect_installs("pip install requests==2.31.0 numpy");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(v[0].packages[0].0, "requests");
        assert_eq!(v[0].packages[0].1.as_deref(), Some("2.31.0"));
        assert_eq!(v[0].packages[1].0, "numpy");
        assert_eq!(v[0].packages[1].1, None);
    }

    #[test]
    fn detect_compound_install() {
        let v = detect_installs("cd foo && npm install x && pip install y");
        assert_eq!(v.len(), 2);
    }

    // ─── Absolute / relative path bypass regression ────────────────────────
    //
    // Invoking the package manager via an absolute or relative path —
    // `/Users/x/.nvm/.../bin/npm install foo`, `./bin/pnpm install bar` —
    // must NOT slip past the gate. The path separator before the install
    // verb has to count as a command-start delimiter (same role as a space
    // or `&&`). Empirically observed bypass on 2026-05-23; see the harden
    // commit. These tests pin the closure.

    #[test]
    fn abs_path_npm_install_detected() {
        let v = detect_installs(
            "/Users/x/.nvm/versions/node/v25.0.0/bin/npm install @earendil-works/pi-coding-agent",
        );
        assert_eq!(v.len(), 1, "abs-path npm install must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(v[0].packages[0].0, "@earendil-works/pi-coding-agent");
    }

    #[test]
    fn abs_path_pnpm_install_detected() {
        let v = detect_installs("/usr/local/bin/pnpm install lodash");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn abs_path_yarn_add_detected() {
        let v = detect_installs("/opt/homebrew/bin/yarn add react");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["react"]);
    }

    #[test]
    fn abs_path_pip_install_detected() {
        let v = detect_installs("/usr/bin/pip install requests");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn abs_path_uv_install_detected() {
        let v = detect_installs("/Users/me/.cargo/bin/uv pip install requests");
        assert_eq!(v.len(), 1, "abs-path uv must be claimed by UV pattern");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
    }

    #[test]
    fn abs_path_poetry_add_detected() {
        let v = detect_installs("/opt/python/bin/poetry add httpx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["httpx"]);
    }

    #[test]
    fn abs_path_pipx_install_detected() {
        let v = detect_installs("/usr/local/bin/pipx install poetry");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["poetry"]);
    }

    #[test]
    fn relative_path_npm_install_detected() {
        let v = detect_installs("./node_modules/.bin/npm install left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["left-pad"]);
    }

    #[test]
    fn abs_path_bare_npm_install_detected() {
        // Bare lockfile install via abs path — should still be classified as
        // an Unvettable npm install (see detect_bare_lockfile_installs).
        let v = detect_installs("/Users/x/.nvm/versions/node/v25/bin/npm install");
        assert_eq!(v.len(), 1, "bare abs-path npm install must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(
            v[0].unvettable.is_some(),
            "bare install has no named package, must surface as unvettable"
        );
    }

    // ─── Peer-review follow-ups (newline chain, Windows launchers,
    //     poetry/uv bare-install) ────────────────────────────────────────────

    #[test]
    fn newline_chain_both_installs_detected() {
        // BLOCKER (Antigravity peer review): `[^|;&<>]+` matched newlines, so
        // a multi-line script's first install greedily swallowed subsequent
        // lines and suppressed downstream detection. Newlines now end the
        // arg-capture and each line is its own install.
        let v = detect_installs("npm install left-pad\npip install requests");
        assert_eq!(
            v.len(),
            2,
            "newline must NOT chain-swallow: expected both installs, got {v:?}"
        );
        assert!(v.iter().any(|p| p.ecosystem == Ecosystem::Npm));
        assert!(v.iter().any(|p| p.ecosystem == Ecosystem::Pypi));
    }

    #[test]
    fn newline_chain_carriage_return_also_caught() {
        // Windows line endings (`\r\n`) — same guard must apply.
        let v = detect_installs("npm install left-pad\r\npip install requests");
        assert_eq!(v.len(), 2, "\\r\\n line ending must not chain: {v:?}");
    }

    #[test]
    fn windows_launcher_npm_cmd_detected() {
        let v = detect_installs("npm.cmd install lodash");
        assert_eq!(v.len(), 1, "npm.cmd install must classify as npm");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn windows_launcher_pip_exe_detected() {
        let v = detect_installs("pip.exe install requests");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn windows_launcher_abs_path_npm_cmd_detected() {
        // Combined: Windows abs path + .cmd suffix.
        let v = detect_installs(r"C:\Tools\node\npm.cmd install lodash");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn windows_launcher_bare_npm_cmd_detected() {
        // Bare lockfile install via Windows launcher — basename strip must
        // drop .cmd before the token-match arm fires.
        let v = detect_installs("npm.cmd install");
        assert_eq!(v.len(), 1, "bare npm.cmd install must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn poetry_install_bare_lockfile_detected() {
        // `poetry install` resolves from pyproject.toml / poetry.lock with no
        // package args — silent Skip before, now surfaced as Pypi unvettable.
        let v = detect_installs("poetry install");
        assert_eq!(v.len(), 1, "poetry install must surface as bare lockfile");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn poetry_install_with_flags_still_bare_lockfile() {
        // Flags after the verb must not turn this into a named install.
        let v = detect_installs("poetry install --no-dev --no-interaction");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn poetry_add_still_handled_by_regex() {
        // Sanity: `poetry add` is package-bearing and must stay claimed by
        // POETRY_RE, not the new bare-install path.
        let v = detect_installs("poetry add httpx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["httpx"]);
    }

    #[test]
    fn uv_sync_bare_lockfile_detected() {
        let v = detect_installs("uv sync");
        assert_eq!(v.len(), 1, "uv sync must surface as bare lockfile");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn uv_pip_sync_bare_lockfile_detected() {
        let v = detect_installs("uv pip sync");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn uv_abs_path_sync_detected() {
        let v = detect_installs("/Users/me/.cargo/bin/uv sync");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
    }

    #[test]
    fn abs_path_does_not_double_match_mid_path_substring() {
        // Defensive: `/some/random/path/install/notnpm.txt` mentions
        // "install" but contains no install verb. Must produce zero hits.
        let v = detect_installs("/some/random/path/install/notnpm.txt");
        assert!(v.is_empty(), "no install verb here, got: {:?}", v);
    }

    // ─── Peer-review round 2 (BLOCKER + HIGHs from #142) ───────────────────
    //
    // Both Codex and agy peer-reviewed #142 and converged on a BLOCKER:
    // value-consuming flags (`poetry install --with dev`, `uv sync --extra dev`)
    // misclassified the value token as a package, flipping `has_package=true`
    // and causing a silent Skip on the newly-expanded detection surface.
    // agy added line-continuation and case-sensitivity issues; Codex added
    // versioned pip and case-sensitivity. All pinned here.

    #[test]
    fn poetry_install_with_value_consuming_flag_still_bare() {
        // BLOCKER: `--with <group>` consumes the next token. Before this fix,
        // `dev` was treated as a package and the install was silently dropped.
        let v = detect_installs("poetry install --with dev");
        assert_eq!(v.len(), 1, "poetry install --with dev must still surface as bare");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn poetry_install_with_only_flag_still_bare() {
        let v = detect_installs("poetry install --only main");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn poetry_install_with_without_and_extras_flags_still_bare() {
        let v = detect_installs("poetry install --without dev --extras docs");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
    }

    #[test]
    fn uv_sync_with_extra_value_still_bare() {
        // BLOCKER mirror in PyPI/uv: `--extra dev` consumes a value.
        let v = detect_installs("uv sync --extra dev");
        assert_eq!(v.len(), 1, "uv sync --extra dev must still surface as bare");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn uv_sync_with_group_value_still_bare() {
        let v = detect_installs("uv sync --group dev --no-extra docs");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
    }

    #[test]
    fn npm_ci_with_value_consuming_flag_still_bare() {
        // npm ci never takes a positional package; treat any trailing token
        // as a flag value, never as a package.
        let v = detect_installs("npm ci --prefix /opt/build");
        assert_eq!(v.len(), 1, "npm ci is always bare");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn yarn_install_with_value_consuming_flag_still_bare() {
        let v = detect_installs("yarn install --modules-folder vendor");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
    }

    // Windows launcher case-insensitivity (Codex + agy HIGH on #142).

    #[test]
    fn windows_launcher_uppercase_npm_cmd_detected() {
        let v = detect_installs("NPM.CMD install lodash");
        assert_eq!(v.len(), 1, "NPM.CMD (all caps) must classify as npm");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn windows_launcher_mixed_case_detected() {
        let v = detect_installs("Npm.Cmd install lodash");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn windows_launcher_full_uppercase_no_suffix_detected() {
        let v = detect_installs("NPM install lodash");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn windows_launcher_pip_exe_uppercase_detected() {
        let v = detect_installs("PIP.EXE install requests");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn windows_launcher_double_extension_detected() {
        // agy MEDIUM: `npm.cmd.exe` only had one suffix layer stripped.
        // Loop strip now collapses both.
        let v = detect_installs("npm.cmd.exe install lodash");
        assert_eq!(v.len(), 1, "double-extension must strip recursively");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    // Versioned pip launcher (Codex HIGH on #142).

    #[test]
    fn versioned_pip_3_12_detected() {
        let v = detect_installs("pip3.12 install requests");
        assert_eq!(v.len(), 1, "pip3.12 must classify as pip");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn versioned_pip_3_12_exe_detected() {
        let v = detect_installs("pip3.12.exe install requests");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn versioned_pip_abs_path_detected() {
        let v = detect_installs("/usr/local/bin/pip3.11 install httpx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(names(&v[0]), vec!["httpx"]);
    }

    // Line continuation (agy HIGH on #142).

    #[test]
    fn line_continuation_multiline_install_caught() {
        // `\\<nl>  foo` → ` foo`. Without the preprocess, the `\r\n` guard
        // in the arg-capture truncated at the `\` and packages on the next
        // line went undetected.
        let v = detect_installs("npm install left-pad \\\n  lodash");
        assert_eq!(v.len(), 1, "line-continuation must collapse to one install");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        let pkgs: Vec<&str> = v[0].packages.iter().map(|(n, _)| n.as_str()).collect();
        assert!(pkgs.contains(&"left-pad"), "missing left-pad in {pkgs:?}");
        assert!(pkgs.contains(&"lodash"), "missing lodash in {pkgs:?}");
    }

    #[test]
    fn yarn_version_flag_not_a_bare_install() {
        // Codex LOW on #143: `yarn --version` is a diagnostic invocation;
        // the bare-yarn rule used to over-match any dash-prefixed next-token.
        let v = detect_installs("yarn --version");
        assert!(v.is_empty(), "yarn --version must NOT classify as install: {v:?}");
    }

    #[test]
    fn yarn_help_flag_not_a_bare_install() {
        let v = detect_installs("yarn --help");
        assert!(v.is_empty(), "yarn --help must NOT classify as install");
    }

    #[test]
    fn yarn_short_version_not_a_bare_install() {
        let v = detect_installs("yarn -v");
        assert!(v.is_empty(), "yarn -v must NOT classify as install");
    }

    #[test]
    fn yarn_with_other_flag_still_bare_install() {
        // Sanity: a non-diagnostic flag (`--frozen-lockfile`) should still
        // be treated as a bare yarn install (this is the shorthand form
        // `yarn install --frozen-lockfile`).
        let v = detect_installs("yarn --frozen-lockfile");
        assert_eq!(v.len(), 1, "yarn --frozen-lockfile is still a bare install");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn line_continuation_legacy_mac_cr_only_caught() {
        // agy BLOCKER on #143: backslash + bare `\r` (legacy mac line ending)
        // was not collapsed by the original `\\\r?\n\s*` regex, so a
        // continuation line on a `\r`-only script bypassed detection. Now
        // covered by `\\(?:\r\n|\n|\r)\s*`.
        let v = detect_installs("npm install foo \\\r  bar");
        assert_eq!(v.len(), 1, "bare \\r continuation must collapse like \\n");
        let pkgs: Vec<&str> = v[0].packages.iter().map(|(n, _)| n.as_str()).collect();
        assert!(pkgs.contains(&"foo"), "missing foo in {pkgs:?}");
        assert!(pkgs.contains(&"bar"), "missing bar in {pkgs:?}");
    }

    #[test]
    fn line_continuation_crlf_caught() {
        let v = detect_installs("npm install foo \\\r\n  bar");
        assert_eq!(v.len(), 1);
        let pkgs: Vec<&str> = v[0].packages.iter().map(|(n, _)| n.as_str()).collect();
        assert!(pkgs.contains(&"foo"));
        assert!(pkgs.contains(&"bar"));
    }

    #[test]
    fn line_continuation_does_not_merge_distinct_commands() {
        // Real newline (no backslash) still separates two installs — the
        // preprocess only collapses `\<nl>`, not bare `<nl>`.
        let v = detect_installs("npm install x\npip install y");
        assert_eq!(v.len(), 2, "bare newline still separates installs");
    }

    #[test]
    fn uv_does_not_double_match_via_pip() {
        // `uv pip install foo` must match the UV pattern once, NOT also
        // the bare PIP pattern on the inner `pip install foo` substring.
        let v = detect_installs("uv pip install requests");
        assert_eq!(v.len(), 1, "expected exactly one detection, got {}", v.len());
    }

    #[test]
    fn editable_install_flagged() {
        let v = detect_installs("pip install -e .");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn dot_extras_treated_as_editable() {
        let v = detect_installs("pip install .[dev]");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn npm_scoped_pkg_with_version_preserved() {
        let (n, v) = split_name_version("@types/node@22.10.0");
        assert_eq!(n, "@types/node");
        assert_eq!(v.as_deref(), Some("22.10.0"));
        let (n, v) = split_name_version("@types/node");
        assert_eq!(n, "@types/node");
        assert_eq!(v, None);
    }

    #[test]
    fn pip_version_specifiers() {
        assert_eq!(split_name_version("requests==2.31.0").0, "requests");
        assert_eq!(
            split_name_version("requests==2.31.0").1.as_deref(),
            Some("2.31.0")
        );
        assert_eq!(split_name_version("requests>=2.0").0, "requests");
        assert_eq!(split_name_version("requests>=2.0").1, None);
        assert_eq!(split_name_version("requests~=2.0").0, "requests");
        assert_eq!(split_name_version("requests~=2.0").1, None);
    }

    #[test]
    fn override_glob_pattern() {
        assert!(matches_override("@types/node", &["@types/*".into()]));
        assert!(!matches_override("@scope/x", &["@types/*".into()]));
        assert!(matches_override("lodash", &["lodash".into()]));
    }

    #[test]
    fn detect_no_install_returns_empty() {
        assert!(detect_installs("git status").is_empty());
        assert!(detect_installs("npm test").is_empty());
        assert!(detect_installs("pip list").is_empty());
    }

    #[test]
    fn skip_flag_args() {
        let v = detect_installs("pip install -r requirements.txt foo");
        // -r and requirements.txt should both be skipped; only `foo` remains
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn url_install_treated_as_editable() {
        let v = detect_installs("pip install https://example.com/pkg.tar.gz");
        assert!(v[0].has_editable);
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn mixed_editable_and_named_keeps_named_packages() {
        // `pip install -e . requests` must still surface `requests` as a
        // vettable package — the editable token is a sibling, not a free
        // pass for the whole install.
        let v = detect_installs("pip install -e . requests");
        assert_eq!(v.len(), 1);
        assert!(v[0].has_editable);
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn bare_npm_install_is_unvettable() {
        // `npm install` with no package args pulls the whole dependency tree
        // from package-lock.json — the gate cannot enumerate it. It must NOT
        // be dropped as a silent Skip (#111 G1).
        let v = detect_installs("npm install");
        assert_eq!(v.len(), 1, "bare npm install should yield one install");
        assert!(v[0].packages.is_empty());
        assert!(!v[0].has_editable);
        assert!(
            v[0].unvettable.is_some(),
            "bare npm install must be flagged unvettable"
        );
    }

    #[test]
    fn bare_npm_ci_and_yarn_install_are_unvettable() {
        for cmd in ["npm ci", "pnpm install", "pnpm i", "yarn install", "yarn"] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "`{}` should yield one install", cmd);
            assert!(
                v[0].unvettable.is_some(),
                "`{}` must be flagged unvettable",
                cmd
            );
        }
    }

    #[test]
    fn stdin_redirect_does_not_look_like_package_name() {
        // `npm install < f.txt` is a bare lockfile install with stdin
        // redirected (npm ignores it). The `<` must tokenise as a shell
        // operator, not be mistaken for a package name — otherwise the
        // bare-install guard misses it (Codex/Claude re-review, #111 G1).
        for cmd in [
            "npm install < packages.txt",
            "npm ci <<EOF",
            "yarn install < f",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "`{}` should yield one install", cmd);
            assert!(
                v[0].packages.is_empty(),
                "`{}` must not name a package",
                cmd
            );
            assert!(
                v[0].unvettable.is_some(),
                "`{}` must be flagged unvettable",
                cmd
            );
        }
    }

    #[test]
    fn pip_install_requirements_file_is_unvettable() {
        // `pip install -r requirements.txt` resolves its package set from a
        // file the gate cannot vet. The whole install must be surfaced, not
        // skipped (#111 G1).
        let v = detect_installs("pip install -r requirements.txt");
        assert_eq!(v.len(), 1);
        assert!(v[0].packages.is_empty());
        assert!(!v[0].has_editable);
        assert!(
            v[0].unvettable.is_some(),
            "pip install -r must be flagged unvettable"
        );
    }

    #[test]
    fn pip_install_constraint_file_is_unvettable() {
        let v = detect_installs("pip install -c constraints.txt");
        assert_eq!(v.len(), 1);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn normal_npm_install_still_names_package() {
        // Regression guard: a real `npm install lodash` must still resolve the
        // package name and must NOT be flagged unvettable.
        let v = detect_installs("npm install lodash");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["lodash"]);
        assert!(
            v[0].unvettable.is_none(),
            "a named install must not be flagged unvettable"
        );
    }

    #[test]
    fn requirements_install_with_named_pkg_keeps_name_and_stays_unvettable() {
        // `pip install -r req.txt foo` names `foo` (vettable) AND pulls the
        // requirements file contents (unvettable). The named package must
        // still be resolved, but the install must remain flagged unvettable
        // because the `-r` file is not enumerable — fail closed (#111 G1).
        let v = detect_installs("pip install -r requirements.txt foo");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["foo"]);
        assert!(
            v[0].unvettable.is_some(),
            "a -r requirements file alongside a named package must still flag unvettable"
        );
    }

    #[test]
    fn bare_install_not_matched_inside_named_install() {
        // `npm install lodash` must not ALSO trip the bare-lockfile regex.
        let v = detect_installs("npm install lodash");
        assert_eq!(v.len(), 1, "named install must not double-count as bare");
    }

    #[test]
    fn cache_file_rejects_traversal() {
        // Package name containing `..` must not resolve to a cache path
        // (would write to parent directory).
        assert!(cache_file(Ecosystem::Npm, "..").is_none());
        assert!(cache_file(Ecosystem::Npm, "../etc/passwd").is_none());
        assert!(cache_file(Ecosystem::Pypi, "foo..bar").is_none());
        assert!(cache_file(Ecosystem::Pypi, "").is_none());
        assert!(cache_file(Ecosystem::Npm, "foo\\bar").is_none());
        // Real names still work.
        assert!(cache_file(Ecosystem::Npm, "lodash").is_some());
        assert!(cache_file(Ecosystem::Npm, "@types/node").is_some());
    }

    #[test]
    fn lockfile_install_with_trailing_flags_is_unvettable() {
        // CRITICAL 1 (#111 G1 follow-up): a regex anchored on end-of-command
        // misses these CI-common forms. Token-stream classification must
        // catch them — trailing flags are not package names.
        for cmd in [
            "npm ci --ignore-scripts",
            "pnpm install --frozen-lockfile",
            "yarn install --immutable",
            "npm install --no-audit",
            "yarn --immutable",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "`{}` should yield one install", cmd);
            assert!(
                v[0].packages.is_empty(),
                "`{}` should name no package",
                cmd
            );
            assert!(
                v[0].unvettable.is_some(),
                "`{}` must be flagged unvettable",
                cmd
            );
        }
    }

    #[test]
    fn lockfile_install_followed_by_shell_operator_is_unvettable() {
        // A shell operator after the verb terminates the command — it is not
        // a package name. `npm install && echo x` is still a bare install.
        for cmd in [
            "npm install && echo done",
            "npm ci && echo done",
            "pnpm install ; echo x",
            "yarn install | tee log",
        ] {
            let v = detect_installs(cmd);
            assert!(
                v.iter().any(|i| i.unvettable.is_some()),
                "`{}` must flag a bare lockfile install",
                cmd
            );
        }
    }

    #[test]
    fn check_verdict_ask_for_lockfile_install_with_flags() {
        // End-to-end: a CI-form lockfile install must NOT be auto-allowed.
        // It carries no package name, so detection yields an unvettable
        // install and `check()` would downgrade to Ask (verified here via
        // detect_installs since `check()` needs config enabled + network).
        let v = detect_installs("npm ci --ignore-scripts && echo done");
        assert_eq!(v.len(), 1);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn pip_install_attached_requirement_form_is_unvettable() {
        // CRITICAL 2 (#111 G1 follow-up): the attached `=` form must be
        // recognised as a requirements indirection, not an ordinary install.
        for cmd in [
            "pip install --requirement=req.txt",
            "pip install -r=req.txt",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "`{}` should yield one install", cmd);
            assert!(
                v[0].unvettable.is_some(),
                "`{}` must be flagged unvettable",
                cmd
            );
        }
    }

    #[test]
    fn pip_install_attached_constraint_form_is_unvettable() {
        for cmd in [
            "pip install --constraint=constraints.txt",
            "pip install -c=constraints.txt",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1);
            assert!(
                v[0].unvettable.is_some(),
                "`{}` must be flagged unvettable",
                cmd
            );
        }
    }

    #[test]
    fn pip_install_attached_requirement_with_named_pkg_keeps_name() {
        // `--requirement=req.txt foo` names `foo` AND pulls the requirements
        // file — name resolved, install still flagged unvettable.
        let v = detect_installs("pip install --requirement=req.txt foo");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["foo"]);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn split_attached_flag_forms() {
        assert_eq!(split_attached_flag("lodash"), None);
        assert_eq!(split_attached_flag("-r"), Some(("-r", None)));
        assert_eq!(
            split_attached_flag("--requirement=req.txt"),
            Some(("--requirement", Some("req.txt")))
        );
        assert_eq!(
            split_attached_flag("-r=req.txt"),
            Some(("-r", Some("req.txt")))
        );
    }

    #[test]
    fn normal_pip_install_unaffected_by_attached_flag_fix() {
        // Regression: a plain `pip install requests` must still name the
        // package and must NOT be flagged unvettable.
        let v = detect_installs("pip install requests");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["requests"]);
        assert!(v[0].unvettable.is_none());
    }

    #[test]
    fn named_install_with_flags_not_double_counted_as_bare() {
        // `npm install lodash --no-audit` names a package — exactly one
        // install, not also a bare-lockfile detection.
        let v = detect_installs("npm install lodash --no-audit");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["lodash"]);
        assert!(v[0].unvettable.is_none());
    }

    #[test]
    fn yarn_add_not_flagged_as_bare_install() {
        // `yarn add lodash` is a named install, not a bare lockfile install.
        let v = detect_installs("yarn add lodash");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["lodash"]);
        assert!(v[0].unvettable.is_none());
    }

    // --- SEC-I3: parse_iso8601 hardening --------------------------------

    #[test]
    fn parse_iso8601_accepts_valid_rfc3339() {
        assert!(parse_iso8601("2024-01-15T10:30:00Z").is_ok());
        assert!(parse_iso8601("2024-01-15T10:30:00+00:00").is_ok());
        // Missing-Z bare form is conservatively retried.
        assert!(parse_iso8601("2024-01-15T10:30:00").is_ok());
    }

    #[test]
    fn parse_iso8601_rejects_malformed() {
        // Garbage must be an error, never coerced into a bogus value.
        assert!(parse_iso8601("not-a-date").is_err());
        assert!(parse_iso8601("").is_err());
        assert!(parse_iso8601("2024-13-99T99:99:99Z").is_err());
        // A trailing Z on otherwise-malformed input must NOT be "fixed".
        assert!(parse_iso8601("garbageZ").is_err());
    }

    #[test]
    fn parse_iso8601_rejects_far_future_timestamp() {
        // A package published >1d in the future is untrustworthy — the old
        // code clamped age to zero and waved it through. Must be Err now.
        let future = (Utc::now() + ChronoDuration::days(400)).to_rfc3339();
        assert!(
            parse_iso8601(&future).is_err(),
            "far-future timestamp must be rejected, not clamped"
        );
        // A timestamp slightly in the future (clock skew) is still accepted.
        let near = (Utc::now() + ChronoDuration::hours(2)).to_rfc3339();
        assert!(parse_iso8601(&near).is_ok());
    }

    #[test]
    fn parse_iso8601_far_past_still_parses() {
        // A genuine far-past date is valid (it just means the package is old
        // and clears the cooldown legitimately) — only future dates are
        // suspect. The fix must not reject the past.
        assert!(parse_iso8601("2001-09-11T00:00:00Z").is_ok());
    }

    // --- SEC-I2: package cap --------------------------------------------

    #[test]
    fn http_max_bytes_lowered_from_64mb() {
        // Regression guard: the per-response cap must stay well under the
        // old 64 MB. A hostile registry must not be able to stream 64 MB
        // per package into the short-lived hook process.
        assert!(
            HTTP_MAX_BYTES <= 16 * 1024 * 1024,
            "HTTP_MAX_BYTES must be lowered from the old 64MB"
        );
    }

    #[test]
    fn package_cap_constant_is_sane() {
        // The cap should be a small, reviewable number — not unbounded.
        assert!(MAX_PACKAGES_PER_CHECK > 0 && MAX_PACKAGES_PER_CHECK <= 50);
    }

    #[test]
    fn many_packages_exceed_cap() {
        // A command naming more than the cap of distinct packages must be
        // detectable as over-cap. We count via detect_installs (check()
        // itself needs config+network).
        let pkgs: Vec<String> = (0..MAX_PACKAGES_PER_CHECK + 5)
            .map(|i| format!("pkg{}", i))
            .collect();
        let cmd = format!("npm install {}", pkgs.join(" "));
        let installs = detect_installs(&cmd);
        let total: usize = installs.iter().map(|i| i.packages.len()).sum();
        assert!(
            total > MAX_PACKAGES_PER_CHECK,
            "expected over-cap package count, got {}",
            total
        );
    }

    #[test]
    fn check_budget_constant_is_bounded() {
        // The aggregate wall-clock budget must be a finite, sane value so a
        // hostile registry cannot stall the hook indefinitely.
        assert!(CHECK_WALL_BUDGET.as_secs() > 0 && CHECK_WALL_BUDGET.as_secs() <= 60);
    }

    #[test]
    fn osv_severity_extracts_from_database_specific() {
        let v: Value = serde_json::from_str(
            r#"{"database_specific":{"severity":"MODERATE"}}"#,
        )
        .unwrap();
        assert_eq!(osv_severity(&v), Severity::Medium);

        let v: Value = serde_json::from_str(
            r#"{"severity":[{"score":"CVSS:3.1/.../A:H CRITICAL"}]}"#,
        )
        .unwrap();
        assert_eq!(osv_severity(&v), Severity::Critical);

        // No severity info → default High (so it doesn't slip past a HIGH threshold).
        let v: Value = serde_json::from_str(r#"{"id":"OSV-2024"}"#).unwrap();
        assert_eq!(osv_severity(&v), Severity::High);
    }

    // ─── Shell-quote tokeniser bypass guards (#140) ────────────────────────
    //
    // Codex + Antigravity peer review of PR #139 flagged a HIGH bypass class:
    // the naive tokeniser does not honour shell quoting, so several install
    // shapes slip past the gate. These tests pin the closure.

    #[test]
    fn quoted_sh_c_install_detected() {
        // `sh -c '<install>'` wraps an install in a quoted argument. The
        // outer regex pass cannot see the verb because the quotes hide it
        // (and `&&` inside the quotes would split the outer scan). The
        // tokeniser must surface the inner command as a recursable segment.
        let v = detect_installs(r#"sh -c 'npm install left-pad'"#);
        assert_eq!(v.len(), 1, "sh -c '<install>' must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert_eq!(names(&v[0]), vec!["left-pad"]);
    }

    #[test]
    fn quoted_bash_c_install_detected() {
        // Same shape, double quotes, `bash -c`.
        let v = detect_installs(r#"bash -c "pip install requests==2.31.0""#);
        assert_eq!(v.len(), 1, "bash -c \"<install>\" must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert_eq!(v[0].packages[0].0, "requests");
        assert_eq!(v[0].packages[0].1.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn command_substitution_install_detected() {
        // `$(...)` evaluates its body. A reasonable adversary writes
        // `eval "$(npm install evil)"` or similar. The gate must surface
        // the substituted command so its install verb is vetted.
        let v = detect_installs(r#"eval "$(npm install evil-pkg)""#);
        assert!(
            !v.is_empty(),
            "$(npm install ...) substitution must surface the inner install"
        );
        assert!(
            v.iter()
                .any(|i| i.packages.iter().any(|(n, _)| n == "evil-pkg")),
            "inner install must be detected, got: {:?}",
            v
        );
    }

    #[test]
    fn backtick_substitution_install_detected() {
        // Backtick substitution is the older, still-valid form of $(...).
        let v = detect_installs("echo `npm install left-pad`");
        assert!(
            !v.is_empty(),
            "backtick substitution must surface the inner install"
        );
        assert!(
            v.iter()
                .any(|i| i.packages.iter().any(|(n, _)| n == "left-pad")),
            "backtick inner install must be detected, got: {:?}",
            v
        );
    }

    #[test]
    fn quoted_head_install_detected() {
        // The installer verb itself can be quoted: `'npm' install foo` is a
        // valid invocation. The tokeniser must strip the quotes before the
        // head is matched against `npm`/`pnpm`/`yarn`.
        let v = detect_installs(r#"'npm' install lodash"#);
        assert_eq!(v.len(), 1, "quoted-head install must be detected");
        assert_eq!(names(&v[0]), vec!["lodash"]);

        let v = detect_installs(r#""pip" install requests"#);
        assert_eq!(v.len(), 1, "double-quoted-head pip install must be detected");
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn quoted_operator_in_flag_value_does_not_truncate_scan() {
        // The package-list regex `[^|;&<>]+` stops at the literal `&` in
        // `--description="install & test"`. The quote-aware tokeniser must
        // mask operators inside quoted regions so the package name `lodash`
        // following the flag is still captured.
        let v = detect_installs(
            r#"npm install --description="install & test" lodash"#,
        );
        assert_eq!(v.len(), 1, "operator inside quotes must not truncate the scan");
        assert!(
            names(&v[0]).contains(&"lodash"),
            "lodash should still be captured past the quoted operator, got: {:?}",
            names(&v[0])
        );
    }

    #[test]
    fn ansi_c_quoted_install_detected() {
        // `$'...'` is the ANSI-C quote form. Treat it like a single-quoted
        // literal for tokenising — escape sequences are not expanded by the
        // gate (close enough; we only need the verb to surface).
        let v = detect_installs(r#"sh -c $'npm install lodash'"#);
        assert_eq!(v.len(), 1, "ANSI-C $'...' wrapped install must be detected");
        assert_eq!(names(&v[0]), vec!["lodash"]);
    }

    #[test]
    fn quoted_install_as_data_argument_still_flagged() {
        // `echo "$(npm install foo)"` — the substitution payload is data
        // here (echo prints whatever npm wrote to stdout), but the shell
        // STILL runs the inner `npm install foo`. We choose to flag it
        // because the install side-effect happens before echo runs.
        // Documenting the decision: be conservative — the install ran.
        let v = detect_installs(r#"echo "$(npm install foo)""#);
        assert!(
            !v.is_empty(),
            "$(npm install foo) inside double quotes still executes the install \
             and must be surfaced (conservative — fail closed)"
        );
        assert!(
            v.iter()
                .any(|i| i.packages.iter().any(|(n, _)| n == "foo")),
            "inner install package must be named, got: {:?}",
            v
        );
    }

    // ─── PR #146 peer-review follow-ups ──────────────────────────────────
    //
    // Both Codex and agy reviewed PR #146 (head 32fb6b2) and surfaced
    // 2 BLOCKERs + 1 HIGH + 1 LOW. Pinned below to prevent regression.

    #[test]
    fn quoted_install_verb_detected() {
        // BLOCKER (both reviewers, #146): `npm 'install' lodash` and
        // `pip "install" requests` were silently dropped — the regex did
        // not allow quotes around the SUBCOMMAND, so it missed; the bare
        // scan then saw a package after the quoted verb and flipped
        // has_package=true. Fix: optional `['"]?` around the subcommand.
        let v = detect_installs(r#"npm 'install' lodash"#);
        assert_eq!(v.len(), 1, "npm 'install' lodash must be detected: {v:?}");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(
            v[0].packages.iter().any(|(n, _)| n == "lodash"),
            "must capture lodash"
        );
    }

    #[test]
    fn double_quoted_install_verb_detected() {
        let v = detect_installs(r#"pip "install" requests"#);
        assert_eq!(v.len(), 1, r#"pip "install" requests must be detected"#);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].packages.iter().any(|(n, _)| n == "requests"));
    }

    #[test]
    fn quoted_install_verb_combined_with_quoted_head() {
        let v = detect_installs(r#"'npm' 'install' lodash"#);
        assert_eq!(v.len(), 1, "both head and verb quoted must still detect");
        assert!(v[0].packages.iter().any(|(n, _)| n == "lodash"));
    }

    #[test]
    fn bash_lc_combined_option_install_detected() {
        // HIGH (agy + Codex, #146): combined short options like `bash -lc`
        // skipped recursion because the original exact-`-c` match only
        // matched the canonical form. Now any `-[chars]c` cluster fires.
        let v = detect_installs(r#"bash -lc 'npm install evil'"#);
        assert!(
            v.iter().any(|i| i.packages.iter().any(|(n, _)| n == "evil")),
            "bash -lc must recurse: {v:?}"
        );
    }

    #[test]
    fn bash_xc_combined_option_install_detected() {
        let v = detect_installs(r#"bash -xc 'npm install nasty'"#);
        assert!(
            v.iter().any(|i| i.packages.iter().any(|(n, _)| n == "nasty")),
            "bash -xc must recurse: {v:?}"
        );
    }

    #[test]
    fn bash_separate_options_install_detected() {
        // `bash -x -c '<install>'` — option before `-c`, separate tokens.
        let v = detect_installs(r#"bash -x -c 'npm install sep'"#);
        assert!(
            v.iter().any(|i| i.packages.iter().any(|(n, _)| n == "sep")),
            "bash -x -c (separate options) must recurse: {v:?}"
        );
    }

    #[test]
    fn recursion_depth_limit_surfaces_unvettable_not_skip() {
        // BLOCKER (agy + Codex, #146): the original `if depth < MAX_RECURSION_DEPTH`
        // silently dropped recursion segments at depth >= 6. This
        // fail-OPEN behaviour meant a 7-deep nest could auto-allow.
        // Now: at the cap, if recursion segments still exist, surface an
        // Unvettable so the caller fails CLOSED.
        // Build a payload nested 7 deep — each `sh -c "$(…)"` layer
        // contributes depth.
        let mut payload = "npm install deeply-nested".to_string();
        for _ in 0..7 {
            payload = format!(r#"sh -c "$({})""#, payload);
        }
        let v = detect_installs(&payload);
        assert!(
            !v.is_empty(),
            "depth-cap must surface at least one ParsedInstall (Unvettable), not silently Skip"
        );
        // At least one item must be the Unvettable depth-cap marker.
        assert!(
            v.iter().any(|i| i.unvettable.as_deref().is_some_and(|s| s.contains("recursion depth limit"))),
            "depth-cap Unvettable marker missing: {v:?}"
        );
    }

    #[test]
    fn dedup_collapses_reordered_package_lists() {
        // LOW (agy, #146): dedup compared package lists with order-strict
        // `==`. Sort-before-compare collapses semantically identical
        // installs. Pin: `npm install a b && npm install b a` should
        // dedupe to one ParsedInstall.
        let v = detect_installs("npm install a b && npm install b a");
        assert_eq!(
            v.len(),
            1,
            "reordered duplicate must collapse to one detection: {v:?}"
        );
    }

    #[test]
    fn nested_sh_c_install_detected() {
        // Defence in depth: nesting `sh -c` inside `bash -c` is a known
        // adversarial shape (PR #139 review). The recursion must walk both
        // layers.
        let v = detect_installs(
            r#"bash -c 'sh -c "npm install nested"'"#,
        );
        assert!(
            v.iter()
                .any(|i| i.packages.iter().any(|(n, _)| n == "nested")),
            "nested sh -c install must be detected, got: {:?}",
            v
        );
    }

    #[test]
    fn bash_c_double_dash_install_detected() {
        let v = detect_installs("bash -c -- 'cd /tmp && sh -c \"npm install\"'");
        assert!(!v.is_empty(), "nested bare install under double dash -- must be detected: {v:?}");

        let v2 = detect_installs("bash -cce 'npm install lodash'");
        assert!(!v2.is_empty(), "bash -cce must be detected: {v2:?}");
    }

    #[test]
    fn unmatched_quote_falls_back_safely() {
        // A malformed command with an unmatched quote must not panic and
        // must not silently swallow an install. Best effort: treat the
        // remainder as one big quoted token. The result is allowed to be
        // empty (no detection) — what matters is no panic.
        let _ = detect_installs(r#"sh -c 'npm install foo"#);
        let _ = detect_installs(r#"echo \"npm install foo"#);
        // No assertion on contents — we only require this not to crash.
    }

    #[test]
    fn shell_tokens_strips_single_quotes() {
        // Direct tokeniser unit test: `'npm'` -> token text `npm`.
        let toks = shell_tokens(r#"'npm' install"#);
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].1, "npm");
        assert_eq!(toks[1].1, "install");
    }

    #[test]
    fn shell_tokens_strips_double_quotes() {
        let toks = shell_tokens(r#""pip" install"#);
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].1, "pip");
        assert_eq!(toks[1].1, "install");
    }

    #[test]
    fn shell_tokens_preserves_operators_in_unquoted_regions() {
        // Regression guard: the operator-splitting behaviour must survive
        // for unquoted regions. `npm install x && echo y` must still split
        // the `&&` as its own token.
        let toks = shell_tokens("npm install x && echo y");
        let ops: Vec<&str> = toks.iter().map(|(_, s)| s.as_str()).collect();
        assert!(
            ops.contains(&"&&"),
            "unquoted && must split as its own token, got: {:?}",
            ops
        );
    }

    #[test]
    fn shell_tokens_keeps_operators_inside_quotes_attached() {
        // `'a && b'` is one token whose text is `a && b`.
        let toks = shell_tokens(r#"foo 'a && b' bar"#);
        let texts: Vec<&str> = toks.iter().map(|(_, s)| s.as_str()).collect();
        assert!(
            texts.iter().any(|t| t.contains("&&")),
            "operator inside single quotes must stay inside the token, got: {:?}",
            texts
        );
        // And `&&` must NOT appear as its own token.
        assert!(
            !texts.contains(&"&&"),
            "&& inside single quotes must not split, got: {:?}",
            texts
        );
    }

    // ─── #141: plaintext false-positive guard (data-utility allowlist) ──────
    //
    // The supply-chain regexes match install-shaped substrings anywhere in a
    // command, including inside the ARGUMENTS of ordinary data-consuming
    // utilities. Hit live on 2026-05-23: `echo "/usr/bin/npm install foo"` is
    // just data printed to stdout, but the gate treated the substring as a
    // real install verb and blocked.
    //
    // Fix: head-verb allowlist (echo, printf, cat, tac, tee, grep, egrep,
    // fgrep, head, tail, nl, base64, xxd, od, hexdump, jq — all execution-
    // incapable; rg/awk/gawk/sed deliberately excluded, see #148). When the
    // head of a command segment basename-normalises to one of these, the
    // segment bytes are
    // overwritten with ASCII spaces in a same-length working copy before the
    // install-detection regexes run. Byte offsets are preserved so the
    // existing regex prefix-anchors and `claimed`-span dedup keep working.
    //
    // Re-implementation of #141 on top of develop @ c4f6e55, composing
    // cleanly with the now-merged #142/#143/#146 changes (line-continuation
    // preprocess, quote-aware tokeniser, recursion + depth-cap).

    #[test]
    fn echo_with_install_substring_is_not_an_install() {
        // The classic FP — observed in live peer review on 2026-05-23.
        let v = detect_installs(r#"echo "/usr/bin/npm install foo""#);
        assert!(
            v.is_empty(),
            "echo printing an install-shaped string must not trigger the gate, got: {:?}",
            v
        );
    }

    #[test]
    fn grep_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"grep "/opt/bin/pip install" README.md"#);
        assert!(
            v.is_empty(),
            "grep searching for an install-shaped pattern must not trigger the gate, got: {:?}",
            v
        );
    }

    #[test]
    fn printf_format_is_not_an_install() {
        let v = detect_installs(r#"printf '%s\n' "npm install lodash""#);
        assert!(
            v.is_empty(),
            "printf data argument must not trigger the gate, got: {:?}",
            v
        );
    }

    #[test]
    fn cat_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"cat /tmp/notes.txt # contains npm install foo"#);
        assert!(
            v.is_empty(),
            "cat reading a file with install-shaped content must not trigger, got: {:?}",
            v
        );
    }

    // ─── #148 round-1 BLOCKER (agy) — execution-capable utilities excluded ─

    #[test]
    fn awk_system_call_install_must_be_detected_not_masked() {
        // `awk 'BEGIN { system("...") }'` is a real command-execution path.
        // If awk were in DATA_CONSUMING_UTILITIES, the entire segment would
        // be masked to spaces and the install would silently bypass. This
        // test pins awk OUT of the allowlist.
        let v = detect_installs(r#"awk 'BEGIN { system("npm install evil") }'"#);
        assert!(
            !v.is_empty(),
            "awk segment must NOT be masked — system() can spawn an install: {v:?}"
        );
    }

    #[test]
    fn gawk_system_call_install_must_be_detected_not_masked() {
        let v = detect_installs(r#"gawk 'BEGIN { system("pip install bad") }'"#);
        assert!(
            !v.is_empty(),
            "gawk system() install must not be masked: {v:?}"
        );
    }

    #[test]
    fn sed_exec_flag_install_must_be_detected_not_masked() {
        // GNU sed's `s///e` flag executes the replacement as a shell command.
        let v = detect_installs(r#"sed 's/.*/npm install nasty/e' /tmp/x"#);
        assert!(
            !v.is_empty(),
            "sed `e` flag install must not be masked — sed can spawn shell: {v:?}"
        );
    }

    // ─── #148 round-1 MEDIUM (agy) — allowlist coverage additions ──────────

    #[test]
    fn jq_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"jq '.scripts | select(. == "npm install foo")' package.json"#);
        assert!(v.is_empty(), "jq filter is data processing, not install: {v:?}");
    }

    #[test]
    fn base64_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"base64 -d <<< "bnBtIGluc3RhbGwgZm9v""#);
        assert!(v.is_empty(), "base64 decode is data, not install: {v:?}");
    }

    #[test]
    fn xxd_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"xxd /tmp/notes # echoes hex of 'pip install x'"#);
        assert!(v.is_empty(), "xxd is data, not install: {v:?}");
    }

    #[test]
    fn od_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"od -c /tmp/log | grep 'npm install'"#);
        assert!(
            v.is_empty(),
            "od piped to grep — both data utilities, not an install: {v:?}"
        );
    }

    #[test]
    fn hexdump_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"hexdump -C /tmp/payload"#);
        assert!(v.is_empty(), "hexdump is data, not install: {v:?}");
    }

    // ─── #148 round-3 (agy) — explicit masking coverage for the rest of
    //     DATA_CONSUMING_UTILITIES (tac, tee, egrep, fgrep, head, tail, nl).
    //     Round-2 only pinned the exec-capable removals and the high-traffic
    //     data utilities. These seven were silently relying on indirect
    //     coverage; pin them here so future trims of the allowlist surface as
    //     an obvious test failure.

    #[test]
    fn tac_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"tac /tmp/log # contains 'npm install foo'"#);
        assert!(v.is_empty(), "tac is reverse-cat, pure data: {v:?}");
    }

    #[test]
    fn tee_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"echo data | tee /tmp/out # 'pip install x' in body"#);
        // `tee` is the head of the post-pipe segment; both `echo` and `tee`
        // are data utilities, so neither segment must trigger detection.
        assert!(v.is_empty(), "tee writes stdin to file+stdout, no exec: {v:?}");
    }

    #[test]
    fn egrep_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"egrep "npm install|pip install" /tmp/notes"#);
        assert!(v.is_empty(), "egrep is grep -E, no exec: {v:?}");
    }

    #[test]
    fn fgrep_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"fgrep "npm install foo" /tmp/notes"#);
        assert!(v.is_empty(), "fgrep is grep -F, no exec: {v:?}");
    }

    #[test]
    fn head_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"head -20 /tmp/install-instructions.md"#);
        assert!(v.is_empty(), "head prints first N lines, no exec: {v:?}");
    }

    #[test]
    fn tail_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"tail -f /var/log/npm-install.log"#);
        assert!(v.is_empty(), "tail prints last N lines, no exec: {v:?}");
    }

    #[test]
    fn nl_with_install_substring_is_not_an_install() {
        let v = detect_installs(r#"nl /tmp/notes # numbered 'npm install foo'"#);
        assert!(v.is_empty(), "nl numbers lines, no exec: {v:?}");
    }

    #[test]
    fn rg_pre_install_must_be_detected_not_masked() {
        // Codex BLOCKER on #148: `rg --pre <executable>` runs the named
        // executable as a preprocessor on every file. If `rg` were on the
        // allowlist, the segment would be masked and the install hidden.
        // `rg` is OUT of DATA_CONSUMING_UTILITIES for this reason.
        // (A plain `rg "<pattern>" src/` is also no longer masked — that
        //  produces a false-positive Ask in the rare case the pattern is
        //  install-shaped. Net: better to over-Ask than under-detect.)
        let v = detect_installs(r#"rg --pre /tmp/installer.sh 'npm install evil'"#);
        assert!(
            !v.is_empty(),
            "rg --pre install must NOT be masked — preprocessor can spawn shell: {v:?}"
        );
    }

    // ─── #141: positive guards — these MUST NOT regress ─────────────────────

    #[test]
    fn plain_npm_install_still_detected_141() {
        // Sanity: the data-utility guard must not break the base case.
        let v = detect_installs("npm install foo");
        assert_eq!(v.len(), 1, "vanilla npm install must still be detected");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn abs_path_npm_install_still_detected_141() {
        // The absolute-path bypass closed by #139 must remain closed —
        // the guard must not regress it.
        let v = detect_installs("/usr/local/bin/npm install foo");
        assert_eq!(v.len(), 1, "abs-path npm install must still be detected");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn chain_after_data_utility_still_detected_141() {
        // `cd` is not in the data-utility list (cd is a stateful builtin,
        // not data-printing). The second segment after `&&` MUST be
        // evaluated independently.
        let v = detect_installs("cd foo && npm install bar");
        assert_eq!(v.len(), 1, "install after && must still be detected");
        assert_eq!(names(&v[0]), vec!["bar"]);
    }

    #[test]
    fn echo_chained_with_real_install_still_detects_install_141() {
        // Tricky chain: the LEFT segment is suppressed (echo head), the
        // RIGHT segment is a real install and must be detected.
        let v = detect_installs(r#"echo "x" && npm install foo"#);
        assert_eq!(
            v.len(),
            1,
            "real install after && must survive even when left segment is suppressed, got: {:?}",
            v
        );
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pipe_into_install_is_detected_141() {
        // `echo foo | npm install bar` — npm is the head of the right-hand
        // pipe segment (it's being invoked, with `foo` piped into stdin),
        // so the install MUST be detected.
        let v = detect_installs("echo foo | npm install bar");
        assert_eq!(
            v.len(),
            1,
            "npm as RHS-of-pipe head must still be detected, got: {:?}",
            v
        );
        assert_eq!(names(&v[0]), vec!["bar"]);
    }

    #[test]
    fn semicolon_chain_with_data_utility_141() {
        // `;` is a segment boundary, same as `&&`.
        let v = detect_installs(r#"echo "npm install foo" ; npm install real"#);
        assert_eq!(
            v.len(),
            1,
            "echo suppressed, second segment must detect, got: {:?}",
            v
        );
        assert_eq!(names(&v[0]), vec!["real"]);
    }

    #[test]
    fn data_utility_with_abs_path_head_is_suppressed_141() {
        // The head check must basename-normalise — `/bin/echo "..."` is
        // still an echo head.
        let v = detect_installs(r#"/bin/echo "/usr/bin/npm install foo""#);
        assert!(
            v.is_empty(),
            "abs-path echo head must still be recognised as a data utility, got: {:?}",
            v
        );
    }

    #[test]
    fn command_head_is_data_utility_unit() {
        // Direct unit test on the helper, in case it's reused.
        assert!(command_head_is_data_utility("echo foo"));
        assert!(command_head_is_data_utility("  echo foo"));
        assert!(command_head_is_data_utility("printf '%s' x"));
        assert!(command_head_is_data_utility("grep pattern file"));
        assert!(command_head_is_data_utility("/bin/echo hi"));
        assert!(command_head_is_data_utility("/usr/bin/cat foo"));

        assert!(!command_head_is_data_utility("npm install foo"));
        assert!(!command_head_is_data_utility("/usr/bin/npm install foo"));
        assert!(!command_head_is_data_utility("pip install x"));
        assert!(!command_head_is_data_utility(""));
        assert!(!command_head_is_data_utility("   "));
        // `cd` is a stateful builtin, not a data utility — its segment is
        // benign because it has no install verb, but it must not be on
        // the allowlist (otherwise `cd && npm install` semantics get
        // muddied if cd ever gains install-shaped argv).
        assert!(!command_head_is_data_utility("cd foo"));
    }
}
