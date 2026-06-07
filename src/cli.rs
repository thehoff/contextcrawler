// cli.rs is a submodule of the library crate root (lib.rs), not the crate
// root itself. The module tree is declared once in lib.rs; pull the sibling
// modules into scope so the bare `cmds::`/`core::`/etc. references in the body
// below still resolve.
use crate::{analytics, cmds, core, discover, hooks, learn};

// Re-export command modules for routing
use cmds::cloud::{aws_cmd, container, curl_cmd, psql_cmd, wget_cmd};
use cmds::dotnet::dotnet_cmd;
use cmds::git::{diff_cmd, gh_cmd, git, glab_cmd, gt_cmd};
use cmds::go::{go_cmd, golangci_cmd};
use cmds::js::{
    lint_cmd, next_cmd, npm_cmd, playwright_cmd, pnpm_cmd, prettier_cmd, prisma_cmd, tsc_cmd,
    vitest_cmd,
};
use cmds::jvm::gradlew_cmd;
use cmds::python::{mypy_cmd, pip_cmd, pytest_cmd, ruff_cmd};
use cmds::ruby::{rake_cmd, rspec_cmd, rubocop_cmd};
use cmds::rust::{cargo_cmd, runner};
use cmds::system::{
    deps, env_cmd, find_cmd, format_cmd, grep_cmd, json_cmd, local_llm, log_cmd, ls, pipe_cmd,
    read, rg_cmd, summary, tree, wc_cmd,
};

use anyhow::{Context, Result};
use clap::error::ErrorKind;
use clap::{Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Target agent for hook installation.
#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum AgentTarget {
    /// Claude Code (default)
    Claude,
    /// Cursor Agent (editor and CLI)
    Cursor,
    /// Windsurf IDE (Cascade)
    Windsurf,
    /// Cline / Roo Code (VS Code)
    Cline,
    /// Kilo Code
    Kilocode,
    /// Google Antigravity
    Antigravity,
    /// Hermes CLI
    Hermes,
    /// Pi coding agent (earendil-works)
    Pidev,
}

#[derive(Parser)]
#[command(
    // Downstream rebrand: clap's `name` overrides the package name in
    // --version / --help output. Keep this in lock-step with Cargo.toml
    // `name` so `contextcrawler --version` doesn't print "rtk". See #22.
    name = "contextcrawler",
    version,
    about = "ContextCrawler — token-optimized CLI proxy for LLM agents",
    long_about = "Downstream of rtk-ai/rtk: filters and compresses command output before it reaches your LLM context, with the session compactor and an opt-in Tirith defense-in-depth gate."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Ultra-compact mode: ASCII icons, inline format (Level 2 optimizations)
    #[arg(long, global = true)]
    ultra_compact: bool,

    /// Set SKIP_ENV_VALIDATION=1 for child processes (Next.js, tsc, lint, prisma)
    #[arg(long = "skip-env", global = true)]
    skip_env: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// List directory contents with token-optimized output (proxy to native ls)
    Ls {
        /// Arguments passed to ls (supports all native ls flags like -l, -a, -h, -R)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Directory tree with token-optimized output (proxy to native tree)
    Tree {
        /// Arguments passed to tree (supports all native tree flags like -L, -d, -a)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Read file with intelligent filtering
    Read {
        /// Files to read (supports multiple, like cat)
        #[arg(required = true, num_args = 1..)]
        files: Vec<PathBuf>,
        /// Filter: none (default, full content), minimal, aggressive
        #[arg(short, long, default_value = "none")]
        level: core::filter::FilterLevel,
        /// Max lines
        #[arg(short, long, conflicts_with = "tail_lines")]
        max_lines: Option<usize>,
        /// Keep only last N lines
        #[arg(long, conflicts_with = "max_lines")]
        tail_lines: Option<usize>,
        /// Show line numbers
        #[arg(short = 'n', long)]
        line_numbers: bool,
        /// Surgical extraction: score heading-anchored sections by lexical
        /// match against the intent terms and return only the top matches
        /// + head/tail bookends. Only applies when file > 5KB and the
        /// splitter finds ≥ 3 sections; otherwise falls back to the normal
        /// render path. See issue #151.
        #[arg(long)]
        intent: Option<String>,
    },

    /// Generate 2-line technical summary (heuristic-based)
    Smart {
        /// File to analyze
        file: PathBuf,
        /// Model: heuristic
        #[arg(short, long, default_value = "heuristic")]
        model: String,
        /// Force model download
        #[arg(long)]
        force_download: bool,
    },

    /// Git commands with compact output
    Git {
        /// Change to directory before executing (like git -C <path>, can be repeated)
        #[arg(short = 'C', action = clap::ArgAction::Append)]
        directory: Vec<String>,

        /// Git configuration override (like git -c key=value, can be repeated)
        #[arg(short = 'c', action = clap::ArgAction::Append)]
        config_override: Vec<String>,

        /// Set the path to the .git directory
        #[arg(long = "git-dir")]
        git_dir: Option<String>,

        /// Set the path to the working tree
        #[arg(long = "work-tree")]
        work_tree: Option<String>,

        /// Disable pager (like git --no-pager)
        #[arg(long = "no-pager")]
        no_pager: bool,

        /// Skip optional locks (like git --no-optional-locks)
        #[arg(long = "no-optional-locks")]
        no_optional_locks: bool,

        /// Treat repository as bare (like git --bare)
        #[arg(long)]
        bare: bool,

        /// Treat pathspecs literally (like git --literal-pathspecs)
        #[arg(long = "literal-pathspecs")]
        literal_pathspecs: bool,

        #[command(subcommand)]
        command: GitCommands,
    },

    /// GitHub CLI (gh) commands with token-optimized output
    Gh {
        /// Subcommand: pr, issue, run, repo
        subcommand: String,
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// GitLab CLI (glab) commands with token-optimized output
    Glab {
        /// Target repository (owner/repo), passed as glab -R flag
        #[arg(short = 'R', long = "repo")]
        repo: Option<String>,
        /// Target group, passed as glab -g flag
        #[arg(short = 'g', long = "group")]
        group: Option<String>,
        /// Subcommand: mr, issue, ci, pipeline, api
        subcommand: String,
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// AWS CLI with compact output (force JSON, compress)
    Aws {
        /// AWS service subcommand (e.g., sts, s3, ec2, ecs, rds, cloudformation)
        subcommand: String,
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// PostgreSQL client with compact output (strip borders, compress tables)
    #[command(disable_help_flag = true)]
    Psql {
        /// psql arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// pnpm commands with ultra-compact output
    Pnpm {
        /// pnpm filter arguments (can be repeated: --filter @app1 --filter @app2)
        #[arg(long, short = 'F')]
        filter: Vec<String>,

        #[command(subcommand)]
        command: PnpmCommands,
    },

    /// Run command and show only errors/warnings
    Err {
        /// Opt into `sh -c` semantics. Default is argv-mode which rejects
        /// shell metacharacters (`|;&<>$`...) and shell binaries (`sh`,
        /// `bash`, `env`, `sudo`, ...) for GHSA-3mmh-86cm-g6w4. Use
        /// `--shell` when you need pipes, redirects, or chains and trust
        /// the command source.
        #[arg(long)]
        shell: bool,
        /// Command to run
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Run tests and show only failures
    Test {
        /// Opt into `sh -c` semantics. See `err --shell` for the security
        /// rationale.
        #[arg(long)]
        shell: bool,
        /// Test command (e.g. cargo test)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show JSON (compact values by default, or keys-only with --keys-only)
    Json {
        /// JSON file
        file: PathBuf,
        /// Max depth
        #[arg(short, long, default_value = "5")]
        depth: usize,
        /// Show keys only (strip all values, show structure)
        #[arg(long)]
        keys_only: bool,
    },

    /// Summarize project dependencies
    Deps {
        /// Project path
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Show environment variables (filtered, sensitive masked)
    Env {
        /// Filter by name (e.g. PATH, AWS)
        #[arg(short, long)]
        filter: Option<String>,
        /// Show all (include sensitive)
        #[arg(long)]
        show_all: bool,
    },

    /// Find files with compact tree output (accepts native find flags like -name, -type)
    Find {
        /// All find arguments (supports both ContextCrawler and native find syntax)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Ultra-condensed diff (only changed lines)
    Diff {
        /// First file or - for stdin (unified diff)
        file1: PathBuf,
        /// Second file (optional if stdin)
        file2: Option<PathBuf>,
    },

    /// Filter and deduplicate log output
    Log {
        /// Log file (omit for stdin)
        file: Option<PathBuf>,
    },

    /// .NET commands with compact output (build/test/restore/format)
    Dotnet {
        #[command(subcommand)]
        command: DotnetCommands,
    },

    /// Docker commands with compact output
    Docker {
        #[command(subcommand)]
        command: DockerCommands,
    },

    /// Kubectl commands with compact output
    Kubectl {
        #[command(subcommand)]
        command: KubectlCommands,
    },

    /// Run command and show heuristic summary
    Summary {
        /// Opt into `sh -c` semantics. See `err --shell` for the security
        /// rationale.
        #[arg(long)]
        shell: bool,
        /// Command to run and summarize
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Ripgrep wrapper — routes to the grep filter so `contextcrawler rg` no longer
    /// falls through unfiltered. Supports `rg PATTERN [PATH]`, `rg --files [PATH]`,
    /// `rg -l/-L/-c/-o/-Z PATTERN [PATH]`, and standard rg flags like `-n -i -A 3
    /// --glob '*.rs' -t rust`. Unmappable invocations fall back to raw rg with a
    /// single stderr note.
    Rg {
        /// All rg arguments (pattern, path, flags) in native rg order.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Compact grep - strips whitespace, truncates, groups by file
    Grep {
        /// Pattern to search
        pattern: String,
        /// Path to search in
        #[arg(default_value = ".")]
        path: String,
        /// Max line length
        #[arg(short = 'l', long, default_value = "80")]
        max_len: usize,
        /// Max results to show
        #[arg(short, long, default_value = "200")]
        max: usize,
        /// Show only match context (not full line)
        #[arg(long)]
        context_only: bool,
        /// Filter by file type (e.g., ts, py, rust)
        #[arg(short = 't', long)]
        file_type: Option<String>,
        /// Show line numbers (always on, accepted for grep/rg compatibility)
        #[arg(short = 'n', long)]
        line_numbers: bool,
        /// Extra ripgrep arguments (e.g., -i, -A 3, -w, --glob)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra_args: Vec<String>,
    },

    /// Initialize contextcrawler instructions for assistant CLI usage
    Init {
        /// Add to global assistant config directory instead of local project file
        #[arg(short, long)]
        global: bool,

        /// Install OpenCode plugin (in addition to Claude Code)
        #[arg(long)]
        opencode: bool,

        /// Initialize for Gemini CLI instead of Claude Code
        #[arg(long)]
        gemini: bool,

        /// Target agent to install hooks for (default: claude)
        #[arg(long, value_enum)]
        agent: Option<AgentTarget>,

        /// Show current configuration
        #[arg(long)]
        show: bool,

        /// Inject full instructions into CLAUDE.md (legacy mode)
        #[arg(long = "claude-md", group = "mode")]
        claude_md: bool,

        /// Hook only, no CONTEXTCRAWLER.md
        #[arg(long = "hook-only", group = "mode")]
        hook_only: bool,

        /// Auto-patch settings.json without prompting
        #[arg(long = "auto-patch", group = "patch")]
        auto_patch: bool,

        /// Skip settings.json patching (print manual instructions)
        #[arg(long = "no-patch", group = "patch")]
        no_patch: bool,

        /// Remove ContextCrawler artifacts for the selected assistant mode
        #[arg(long)]
        uninstall: bool,

        /// Target Codex CLI (uses AGENTS.md + CONTEXTCRAWLER.md, no Claude hook patching)
        #[arg(long)]
        codex: bool,

        /// Install GitHub Copilot integration (VS Code + CLI)
        #[arg(long)]
        copilot: bool,

        /// Preview changes without writing any files (combine with -v to show content)
        #[arg(long = "dry-run", conflicts_with = "show")]
        dry_run: bool,
    },

    /// Download with compact output (strips progress bars)
    Wget {
        /// URL to download
        url: String,
        /// Output file (-O - for stdout)
        #[arg(short = 'O', long = "output-document", allow_hyphen_values = true)]
        output: Option<String>,
        /// Additional wget arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Word/line/byte count with compact output (strips paths and padding)
    Wc {
        /// Arguments passed to wc (files, flags like -l, -w, -c)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show token savings summary and history
    Gain {
        /// Filter statistics to current project (current working directory) // added
        #[arg(short, long)]
        project: bool,
        /// Show ASCII graph of daily savings
        #[arg(short, long)]
        graph: bool,
        /// Show recent command history
        #[arg(short = 'H', long)]
        history: bool,
        /// Show monthly quota savings estimate
        #[arg(short, long)]
        quota: bool,
        /// Subscription tier for quota calculation: pro, 5x, 20x
        #[arg(short, long, default_value = "20x", requires = "quota")]
        tier: String,
        /// Show detailed daily breakdown (all days)
        #[arg(short, long)]
        daily: bool,
        /// Show weekly breakdown
        #[arg(short, long)]
        weekly: bool,
        /// Show monthly breakdown
        #[arg(short, long)]
        monthly: bool,
        /// Show all time breakdowns (daily + weekly + monthly)
        #[arg(short, long)]
        all: bool,
        /// Output format: text, json, csv
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Show parse failure log (commands that fell back to raw execution)
        #[arg(short = 'F', long)]
        failures: bool,
        /// Rank tools by leaked tokens — where a better filter would help most
        #[arg(short = 'W', long = "weak-filters")]
        weak_filters: bool,
        /// For --weak-filters: include rows from before the latest release
        /// boundary (default: slice from latest contextcrawler version install).
        #[arg(long = "all-time")]
        all_time: bool,
        /// Reset all token savings stats to zero
        #[arg(long)]
        reset: bool,
        /// Skip confirmation prompt when resetting
        #[arg(long, requires = "reset")]
        yes: bool,
    },

    /// Claude Code economics: spending (ccusage) vs savings (contextcrawler) analysis
    CcEconomics {
        /// Show detailed daily breakdown
        #[arg(short, long)]
        daily: bool,
        /// Show weekly breakdown
        #[arg(short, long)]
        weekly: bool,
        /// Show monthly breakdown
        #[arg(short, long)]
        monthly: bool,
        /// Show all time breakdowns (daily + weekly + monthly)
        #[arg(short, long)]
        all: bool,
        /// Output format: text, json, csv
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Show or create configuration file
    Config {
        /// Create default config file
        #[arg(long)]
        create: bool,
    },

    /// Jest commands with compact output
    Jest {
        /// Additional jest arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Vitest commands with compact output
    Vitest {
        /// Additional vitest arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Prisma commands with compact output (no ASCII art)
    Prisma {
        #[command(subcommand)]
        command: PrismaCommands,
    },

    /// TypeScript compiler with grouped error output
    Tsc {
        /// TypeScript compiler arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Next.js build with compact output
    Next {
        /// Next.js build arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// ESLint with grouped rule violations
    Lint {
        /// Linter arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Prettier format checker with compact output
    Prettier {
        /// Prettier arguments (e.g., --check, --write)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Universal format checker (prettier, black, ruff format)
    Format {
        /// Formatter arguments (auto-detects formatter from project files)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Playwright E2E tests with compact output
    Playwright {
        /// Playwright arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Cargo commands with compact output
    Cargo {
        #[command(subcommand)]
        command: CargoCommands,
    },

    /// npm run with filtered output (strip boilerplate)
    Npm {
        /// npm run arguments (script name + options)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// npx with intelligent routing (tsc, eslint, prisma -> specialized filters)
    Npx {
        /// npx arguments (command + options)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Curl with auto-JSON detection and schema output
    Curl {
        /// Curl arguments (URL + options)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Discover missed ContextCrawler savings from Claude Code history
    Discover {
        /// Filter by project path (substring match)
        #[arg(short, long)]
        project: Option<String>,
        /// Max commands per section
        #[arg(short, long, default_value = "15")]
        limit: usize,
        /// Scan all projects (default: current project only)
        #[arg(short, long)]
        all: bool,
        /// Limit to sessions from last N days
        #[arg(short, long, default_value = "30")]
        since: u64,
        /// Output format: text, json
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Scan Codex CLI job logs instead of Claude Code sessions
        /// (~/.claude/plugins/data/codex-openai-codex/state/*/jobs/*.log).
        /// Reports `contextcrawler ` prefix compliance %.
        #[arg(long, conflicts_with_all = ["project", "all"])]
        codex: bool,
    },

    /// Show ContextCrawler adoption across Claude Code sessions
    Session {},

    /// Manage telemetry consent and data (RGPD/GDPR)
    Telemetry {
        #[command(subcommand)]
        command: core::telemetry_cmd::TelemetrySubcommand,
    },

    /// Learn CLI corrections from Claude Code error history
    Learn {
        /// Filter by project path (substring match)
        #[arg(short, long)]
        project: Option<String>,
        /// Scan all projects (default: current project only)
        #[arg(short, long)]
        all: bool,
        /// Limit to sessions from last N days
        #[arg(short, long, default_value = "30")]
        since: u64,
        /// Output format: text, json
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Generate .claude/rules/cli-corrections.md file
        #[arg(short, long)]
        write_rules: bool,
        /// Minimum confidence threshold (0.0-1.0)
        #[arg(long, default_value = "0.6")]
        min_confidence: f64,
        /// Minimum occurrences to include in report
        #[arg(long, default_value = "1")]
        min_occurrences: usize,
    },

    /// Execute a shell command via sh -c (raw, no filtering or tracking)
    Run {
        /// Command string to execute (use -c for shell-like invocation)
        #[arg(short = 'c', long = "command")]
        command: Option<String>,
        /// Positional command arguments (alternative to -c)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Execute command without filtering but track usage
    Proxy {
        /// Interpret a single quoted argument as a shell command line.
        ///
        /// SECURITY: by default `args` is passed verbatim as argv —
        /// `args[0]` is the binary, `args[1..]` its arguments — so a binary
        /// path containing whitespace can never be split into the wrong
        /// program. `--via-shell` is the explicit opt-in for callers that
        /// genuinely need shell word-splitting / quoting of a single arg.
        ///
        /// The flag is `--via-shell` (not `--shell`, #100 G2 Codex 2nd pass
        /// PARTIAL 3) so a proxied child whose own arg is literally `--shell`
        /// is not stolen by clap. Either way, everything after a `--`
        /// separator is the verbatim child argv.
        #[arg(long = "via-shell")]
        shell: bool,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },

    /// Read stdin, apply filter, print filtered output (Unix pipe mode)
    Pipe {
        /// Filter name (cargo-test, pytest, grep, find, git-log, etc.)
        #[arg(short, long)]
        filter: Option<String>,

        /// Pass stdin through without filtering
        #[arg(long)]
        passthrough: bool,
    },

    /// Trust project-local TOML filters in current directory
    Trust {
        /// List all trusted projects
        #[arg(long)]
        list: bool,
        /// Operate on the user-global `~/.config/contextcrawler/filters.toml`
        /// instead of project-local `.ctxcrl/filters.toml`. Closes the H-3
        /// audit gap (v0.1.6) by exposing the global trust gate to the CLI.
        #[arg(long)]
        global: bool,
    },

    /// Revoke trust for project-local TOML filters
    Untrust {
        /// Operate on the user-global filter store. See `trust --global`.
        #[arg(long)]
        global: bool,
    },

    /// Verify hook integrity and run TOML filter inline tests
    Verify {
        /// Run tests only for this filter name
        #[arg(long)]
        filter: Option<String>,
        /// Fail if any filter has no inline tests (CI mode)
        #[arg(long)]
        require_all: bool,
    },

    /// Tirith defense-in-depth gate status + recent downgrade events
    Security {
        /// Show all logged downgrade events, not just the last 10
        #[arg(long)]
        all: bool,
        /// Emit machine-readable JSON instead of the human-readable dashboard
        #[arg(long)]
        json: bool,
        /// Scrub credentials from existing audit logs in place.
        /// Writes a `.bak-<ts>` backup alongside each rewritten file.
        /// Pair with `--dry-run` to preview without writing.
        #[arg(long, conflicts_with_all = ["all", "json"])]
        scrub_logs: bool,
        /// With `--scrub-logs`: report what would change without rewriting.
        #[arg(long, requires = "scrub_logs")]
        dry_run: bool,
    },

    /// Ruff linter/formatter with compact output
    Ruff {
        /// Ruff arguments (e.g., check, format --check)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Pytest test runner with compact output
    Pytest {
        /// Pytest arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Mypy type checker with grouped error output
    Mypy {
        /// Mypy arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Rake/Rails test with compact Minitest output (Ruby)
    Rake {
        /// Rake arguments (e.g., test, test TEST=path/to/test.rb)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// RuboCop linter with compact output (Ruby)
    Rubocop {
        /// RuboCop arguments (e.g., --auto-correct, -A)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// RSpec test runner with compact output (Rails/Ruby)
    Rspec {
        /// RSpec arguments (e.g., spec/models, --tag focus)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Pip package manager with compact output (auto-detects uv)
    Pip {
        /// Pip arguments (e.g., list, outdated, install)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Go commands with compact output
    Go {
        #[command(subcommand)]
        command: GoCommands,
    },

    /// Graphite (gt) stacked PR commands with compact output
    Gt {
        #[command(subcommand)]
        command: GtCommands,
    },

    /// golangci-lint wrapper with compact `run` support and passthrough for other invocations
    #[command(name = "golangci-lint")]
    GolangciLint {
        /// Additional golangci-lint arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Android Gradle wrapper with compact output (build, test, lint)
    #[command(name = "gradlew")]
    Gradlew {
        /// Gradle tasks and arguments (e.g., assembleDebug, testDebugUnitTest, lint, --info)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show hook rewrite audit metrics (requires RTK_HOOK_AUDIT=1)
    #[command(name = "hook-audit")]
    HookAudit {
        /// Show entries from last N days (0 = all time)
        #[arg(short, long, default_value = "7")]
        since: u64,
    },

    /// Rewrite a raw command to its ContextCrawler equivalent (single source of truth for hooks)
    ///
    /// Exits 0 and prints the rewritten command if supported.
    /// Exits 1 with no output if the command has no ContextCrawler equivalent.
    ///
    /// Used by Claude Code, Gemini CLI, and other LLM hooks:
    ///   REWRITTEN=$(contextcrawler rewrite "$CMD") || exit 0
    Rewrite {
        /// Raw command to rewrite (e.g. "git status", "cargo test && git push")
        /// Accepts multiple args: `contextcrawler rewrite ls -al` is equivalent to `contextcrawler rewrite "ls -al"`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Hook processors for LLM CLI tools (Gemini CLI, Copilot, etc.)
    Hook {
        #[command(subcommand)]
        command: HookCommands,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum HookCommands {
    /// Process Claude Code PreToolUse hook (reads JSON from stdin)
    Claude,
    /// Process Cursor Agent hook (reads JSON from stdin)
    Cursor,
    /// Process Gemini CLI BeforeTool hook (reads JSON from stdin)
    Gemini,
    /// Process Copilot preToolUse hook (VS Code + Copilot CLI, reads JSON from stdin)
    Copilot,
    /// Check how a command would be rewritten by the hook engine (dry-run)
    Check {
        /// Target agent
        #[arg(long, default_value = "claude")]
        agent: String,
        /// Command to check
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum GitCommands {
    /// Condensed diff output
    Diff {
        /// Git arguments (supports all git diff flags like --stat, --cached, etc)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// One-line commit history
    Log {
        /// Git arguments (supports all git log flags like --oneline, --graph, --all)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact status (supports all git status flags)
    Status {
        /// Git arguments (supports all git status flags like --porcelain, --short, -s)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact show (commit summary + stat + compacted diff)
    Show {
        /// Git arguments (supports all git show flags)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Add files → "ok"
    Add {
        /// Files and flags to add (supports all git add flags like -A, -p, --all, etc)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Commit → "ok \<hash\>"
    Commit {
        /// Git commit arguments (supports -a, -m, --amend, --allow-empty, etc)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Push → "ok \<branch\>"
    Push {
        /// Git push arguments (supports -u, remote, branch, etc.)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Pull → "ok \<stats\>"
    Pull {
        /// Git pull arguments (supports --rebase, remote, branch, etc.)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact branch listing (current/local/remote)
    Branch {
        /// Git branch arguments (supports -d, -D, -m, etc.)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Fetch → "ok fetched (N new refs)"
    Fetch {
        /// Git fetch arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Stash management (list, show, pop, apply, drop)
    Stash {
        /// Subcommand: list, show, pop, apply, drop, push
        subcommand: Option<String>,
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact worktree listing
    Worktree {
        /// Git worktree arguments (add, remove, prune, or empty for list)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Passthrough: runs any unsupported git subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PnpmCommands {
    /// List installed packages (ultra-dense)
    List {
        /// Depth level (default: 0)
        #[arg(short, long, default_value = "0")]
        depth: usize,
        /// Additional pnpm arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show outdated packages (condensed: "pkg: old → new")
    Outdated {
        /// Additional pnpm arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Install packages (filter progress bars)
    Install {
        /// Additional pnpm arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Typecheck (delegates to tsc filter)
    Typecheck {
        /// Additional typecheck arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Passthrough: runs any unsupported pnpm subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum DockerCommands {
    /// List running containers
    Ps,
    /// List images
    Images,
    /// Show container logs (deduplicated)
    Logs { container: String },
    /// Docker Compose commands with compact output
    Compose {
        #[command(subcommand)]
        command: ComposeCommands,
    },
    /// Passthrough: runs any unsupported docker subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ComposeCommands {
    /// List compose services (compact)
    Ps,
    /// Show compose logs (deduplicated)
    Logs {
        /// Optional service name
        service: Option<String>,
        /// Number of log lines to fetch
        #[arg(long, default_value_t = 100)]
        tail: u32,
    },
    /// Build compose services (summary)
    Build {
        /// Optional service name
        service: Option<String>,
    },
    /// Passthrough: runs any unsupported compose subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum KubectlCommands {
    /// Get Kubernetes resources (compact for pods/services)
    Get {
        /// kubectl get arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// List pods
    Pods {
        #[arg(short, long)]
        namespace: Option<String>,
        /// All namespaces
        #[arg(short = 'A', long)]
        all: bool,
    },
    /// List services
    Services {
        #[arg(short, long)]
        namespace: Option<String>,
        /// All namespaces
        #[arg(short = 'A', long)]
        all: bool,
    },
    /// Show pod logs (deduplicated)
    Logs {
        pod: String,
        #[arg(short, long)]
        container: Option<String>,
    },
    /// Passthrough: runs any unsupported kubectl subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PrismaCommands {
    /// Generate Prisma Client (strip ASCII art)
    Generate {
        /// Additional prisma arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage migrations
    Migrate {
        #[command(subcommand)]
        command: PrismaMigrateCommands,
    },
    /// Push schema to database
    DbPush {
        /// Additional prisma arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum PrismaMigrateCommands {
    /// Create and apply migration
    Dev {
        /// Migration name
        #[arg(short, long)]
        name: Option<String>,
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Check migration status
    Status {
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Deploy migrations to production
    Deploy {
        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum CargoCommands {
    /// Build with compact output (strip Compiling lines, keep errors)
    Build {
        /// Additional cargo build arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Test with failures-only output
    Test {
        /// Additional cargo test arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Clippy with warnings grouped by lint rule
    Clippy {
        /// Additional cargo clippy arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Check with compact output (strip Checking lines, keep errors)
    Check {
        /// Additional cargo check arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Install with compact output (strip dep compilation, keep installed/errors)
    Install {
        /// Additional cargo install arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Nextest with failures-only output
    Nextest {
        /// Additional cargo nextest arguments (e.g., run, list, --lib)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Passthrough: runs any unsupported cargo subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum DotnetCommands {
    /// Build with compact output
    Build {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Test with compact output
    Test {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Restore with compact output
    Restore {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Format with compact output
    Format {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Passthrough: runs any unsupported dotnet subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum GoCommands {
    /// Run tests with compact output (90% token reduction via JSON streaming)
    Test {
        /// Additional go test arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Build with compact output (errors only)
    Build {
        /// Additional go build arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Vet with compact output
    Vet {
        /// Additional go vet arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Passthrough: runs any unsupported go subcommand directly
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

/// CTXCRL-only subcommands that should never fall back to raw execution.
/// If Clap fails to parse these, show the Clap error directly.
const CTXCRL_META_COMMANDS: &[&str] = &[
    "gain",
    "discover",
    "learn",
    "init",
    "config",
    "proxy",
    "run",
    "hook",
    "hook-audit",
    "pipe",
    "cc-economics",
    "verify",
    "trust",
    "untrust",
    "session",
    "rewrite",
    "security",
];

/// Cloud CLI hardening guard for the clap-fallback path. Returns `Some(code)`
/// when the deny-list rejected the invocation (caller should exit with
/// `code`). Returns `None` when the tool either isn't one we harden or the
/// args are clean — caller then continues with the normal fallback.
///
/// We don't actually re-execute the tool here; we only validate and short-
/// circuit on rejection. The actual execution still runs through the
/// fallback's normal `resolved_command(...)` path, but we mutate the
/// process env so the strip applies via inheritance. This is the same
/// effect as `secure_kubectl_command()` since `resolved_command` builds on
/// top of inherited env.
fn cloud_fallback_hardening(tool: &str, args: &[String]) -> Option<i32> {
    use core::utils::{
        check_forbidden_aws_args, check_forbidden_curl_args, check_forbidden_docker_args,
        check_forbidden_gh_args, check_forbidden_glab_args, check_forbidden_gt_args,
        check_forbidden_kubectl_args, check_forbidden_psql_args, check_forbidden_wget_args,
        secure_aws_command, secure_curl_command, secure_docker_command, secure_gh_command,
        secure_glab_command, secure_gt_command, secure_kubectl_command, secure_psql_command,
        secure_wget_command,
    };

    // Match on the basename so absolute paths (/usr/local/bin/kubectl) still resolve.
    let basename = std::path::Path::new(tool)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(tool);

    // Look up the deny-check + secure Command builder for this tool.
    // Returning Some((check, builder)) means "this is a cloud tool we
    // harden"; None means "fall through to the normal fallback".
    let (check_result, mut cmd): (Result<(), String>, std::process::Command) = match basename {
        "kubectl" => (check_forbidden_kubectl_args(args), secure_kubectl_command()),
        "docker" => (check_forbidden_docker_args(args), secure_docker_command()),
        "aws" => (check_forbidden_aws_args(args), secure_aws_command()),
        "psql" => (check_forbidden_psql_args(args), secure_psql_command()),
        "curl" => (check_forbidden_curl_args(args), secure_curl_command()),
        "wget" => (check_forbidden_wget_args(args), secure_wget_command()),
        // gh/glab/gt fallback path (issue #50). If clap routing didn't match
        // a typed subcommand and the unknown command name is one of these,
        // still apply env-strip + arg deny rather than dropping back to a
        // raw spawn.
        "gh" => (check_forbidden_gh_args(args), secure_gh_command()),
        "glab" => (check_forbidden_glab_args(args), secure_glab_command()),
        "gt" => (check_forbidden_gt_args(args), secure_gt_command()),
        _ => return None,
    };

    if let Err(msg) = check_result {
        eprintln!("{}", msg);
        return Some(2);
    }

    // Spawn the hardened command directly here instead of falling back to
    // the normal `resolved_command(...)` path. The secure_*_command
    // helpers apply UNIVERSAL_ENV_STRIP + per-tool env_remove on the
    // spawned child only (Command::env_remove is safe; no process-wide
    // env mutation). This closes the regression codex P1 flagged on the
    // first F9 fix attempt: simply removing the unsafe `env::remove_var`
    // dropped the hardening for this path; spawning here keeps it.
    cmd.args(args);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    match cmd.status() {
        Ok(status) => Some(status.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("[contextcrawler] failed to spawn {}: {}", basename, e);
            Some(127)
        }
    }
}

fn run_fallback(parse_error: clap::Error) -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // No args → show Clap's error (user ran just "contextcrawler" with bad syntax)
    if args.is_empty() {
        parse_error.exit();
    }

    // CTXCRL meta-commands should never fall back to raw execution.
    // e.g. `contextcrawler gain --badtypo` should show Clap's error, not try to run `gain` from $PATH.
    if CTXCRL_META_COMMANDS.contains(&args[0].as_str()) {
        parse_error.exit();
    }

    // Cloud CLI hardening (issue #38): when the fallback spawns a tool we've
    // hardened, route the args through the per-tool deny-list and spawn with
    // the per-tool env strip. Without this, any clap-confusing arg like
    // `kubectl --kubeconfig <evil>` would bypass our hardening because it
    // takes the fallback path instead of the Kubectl subcommand path.
    if let Some(code) = cloud_fallback_hardening(&args[0], &args[1..]) {
        return Ok(code);
    }

    let raw_command = args.join(" ");
    let error_message = core::utils::strip_ansi(&parse_error.to_string());

    // Start timer before execution to capture actual command runtime
    let timer = core::tracking::TimedExecution::start();

    // TOML filter lookup — bypass with RTK_NO_TOML=1
    // Use basename of args[0] so absolute paths (/usr/bin/make) still match "^make\b".
    let lookup_cmd = {
        let base = std::path::Path::new(&args[0])
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| args[0].clone());
        std::iter::once(base.as_str())
            .chain(args[1..].iter().map(|s| s.as_str()))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let toml_match = if core::env_compat::env_flag("CTXCRL_NO_TOML") {
        None
    } else {
        core::toml_filter::find_matching_filter(&lookup_cmd)
    };

    if let Some(filter) = toml_match {
        // TOML match: capture stdout for filtering
        let result = if filter.filter_stderr {
            // Merge stderr into stdout so the filter can strip banners emitted by tools like liquibase
            core::utils::resolved_command(&args[0])
                .args(&args[1..])
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()) // captured for merging
                .output()
        } else {
            core::utils::resolved_command(&args[0])
                .args(&args[1..])
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::piped()) // capture
                .stderr(std::process::Stdio::inherit()) // stderr always direct
                .output()
        };

        match result {
            Ok(output) => {
                let exit_code = core::utils::exit_code_from_output(&output, &raw_command);
                let stdout_raw = String::from_utf8_lossy(&output.stdout);
                let stderr_raw = String::from_utf8_lossy(&output.stderr);

                // Merge stderr into the text to filter when filter_stderr is enabled;
                // otherwise emit stderr directly so it is always visible.
                let combined_raw = if filter.filter_stderr {
                    format!("{}{}", stdout_raw, stderr_raw)
                } else {
                    stdout_raw.to_string()
                };
                // Tee raw output BEFORE filtering on failure — lets LLM re-read if needed
                let tee_hint = if !output.status.success() {
                    core::tee::tee_and_hint(&combined_raw, &raw_command, exit_code)
                } else {
                    None
                };

                let filtered = core::toml_filter::apply_filter(filter, &combined_raw);
                println!("{}", filtered);
                if let Some(hint) = tee_hint {
                    println!("{}", hint);
                }

                timer.track(
                    &raw_command,
                    &format!("contextcrawler:toml {}", raw_command),
                    &combined_raw,
                    &filtered,
                );
                core::tracking::record_parse_failure_silent(&raw_command, &error_message, true);

                Ok(exit_code)
            }
            Err(e) => {
                // Command not found — same behaviour as no-TOML path
                core::tracking::record_parse_failure_silent(&raw_command, &error_message, false);
                eprintln!("[contextcrawler: {}]", e);
                Ok(127)
            }
        }
    } else {
        // No TOML match: original passthrough behaviour (Stdio::inherit, streaming)
        let status = core::utils::resolved_command(&args[0])
            .args(&args[1..])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();

        match status {
            Ok(s) => {
                timer.track_passthrough(
                    &raw_command,
                    &format!("contextcrawler fallback: {}", raw_command),
                );

                core::tracking::record_parse_failure_silent(&raw_command, &error_message, true);

                Ok(core::utils::exit_code_from_status(&s, &raw_command))
            }
            Err(e) => {
                core::tracking::record_parse_failure_silent(&raw_command, &error_message, false);
                // Command not found or other OS error — single message, no duplicate Clap error
                eprintln!("[contextcrawler: {}]", e);
                Ok(127)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum GtCommands {
    /// Compact stack log output
    Log {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact submit output
    Submit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact sync output
    Sync {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact restack output
    Restack {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compact create output
    Create {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Branch info and management
    Branch {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Passthrough: git-passthrough detection or direct gt execution
    #[command(external_subcommand)]
    Other(Vec<OsString>),
}

/// Split a string into shell-like tokens, respecting single and double quotes.
/// e.g. `git log --format="%H %s"` → ["git", "log", "--format=%H %s"]
fn shell_split(input: &str) -> Vec<String> {
    discover::lexer::shell_split(input)
}

/// Final path component of a binary token, used to normalise an
/// absolute/relative path (`/usr/bin/npm`) down to its name (`npm`) for
/// membership checks against `META_PASSTHROUGH_BINS` (#100 G2 IMPORTANT 3).
fn bin_basename(bin: &str) -> &str {
    std::path::Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin)
}

/// `true` when a proxy/meta `argv[0]` token contains a path separator
/// (`/` or `\`).
///
/// SECURITY (#100 G2 Codex 2nd pass — CRITICAL 2): `bin_basename` normalises
/// a token ONLY for the `META_PASSTHROUGH_BINS` membership check, but the
/// actual spawn ran the RAW token. `contextcrawler proxy ../../evil/npm` then
/// passed the `npm` membership/hardening check while executing the attacker's
/// `../../evil/npm`. Proxied/meta commands must be bare tool names resolved
/// via `PATH`, never a caller-smuggled path. Reject anything with a
/// separator at both call sites so hardening is applied to the binary that
/// actually runs.
fn token_has_path_separator(token: &str) -> bool {
    token.contains('/') || token.contains('\\')
}

/// `true` when the proxy nudge should be printed to stderr. Three independent
/// suppression knobs (any one silences the nudge): explicit env opt-out,
/// `CI=*` env marker, stderr is not a tty. The override env var can carry
/// any value — empty string still suppresses.
fn should_emit_proxy_nudge() -> bool {
    use std::io::IsTerminal;

    if std::env::var_os("CONTEXTCRAWLER_NO_PROXY_NUDGE").is_some() {
        return false;
    }
    if std::env::var_os("CI").is_some() {
        return false;
    }
    if !std::io::stderr().is_terminal() {
        return false;
    }
    true
}

/// Returns the suggested wrapped invocation if `tool` has a `contextcrawler`
/// equivalent. Drives the nudge in `Commands::Proxy`. Keep this list aligned
/// with `WRAPPED_TOOLS` in `discover::codex` — if we add a wrapper there,
/// callers should be steered here too.
///
/// Returns the literal text to suggest (e.g. `contextcrawler git`) so the
/// caller can format `Consider: <suggestion>` without re-templating.
fn proxy_wrapped_equivalent(tool: &str) -> Option<&'static str> {
    match tool {
        "git" => Some("contextcrawler git ..."),
        "gh" => Some("contextcrawler gh ..."),
        "glab" => Some("contextcrawler glab ..."),
        "gt" => Some("contextcrawler gt ..."),
        "rg" => Some("contextcrawler rg ..."),
        "grep" => Some("contextcrawler grep ..."),
        "find" => Some("contextcrawler find ..."),
        "ls" => Some("contextcrawler ls ..."),
        "tree" => Some("contextcrawler tree ..."),
        "wc" => Some("contextcrawler wc ..."),
        "diff" => Some("contextcrawler diff ..."),
        "cat" | "head" | "tail" | "nl" => Some(
            "contextcrawler read <file> (use -n for line numbers, --max-lines / --tail for range)",
        ),
        "sed" | "awk" => Some(
            "contextcrawler read <file> for slice/line-number patterns; \
             leave on proxy only if you genuinely need stream editing",
        ),
        "cargo" => Some("contextcrawler cargo ..."),
        "npm" => Some("contextcrawler npm ..."),
        "pnpm" => Some("contextcrawler pnpm ..."),
        "yarn" => Some("contextcrawler yarn ..."),
        "pytest" => Some("contextcrawler pytest ..."),
        "ruff" => Some("contextcrawler ruff ..."),
        "black" => Some("contextcrawler black ..."),
        "mypy" => Some("contextcrawler mypy ..."),
        "tsc" => Some("contextcrawler tsc ..."),
        "vitest" => Some("contextcrawler vitest ..."),
        "jest" => Some("contextcrawler jest ..."),
        "prettier" => Some("contextcrawler prettier ..."),
        "docker" => Some("contextcrawler docker ..."),
        "kubectl" => Some("contextcrawler kubectl ..."),
        "aws" => Some("contextcrawler aws ..."),
        "psql" => Some("contextcrawler psql ..."),
        "curl" => Some("contextcrawler curl ..."),
        "wget" => Some("contextcrawler wget ..."),
        "dotnet" => Some("contextcrawler dotnet ..."),
        "go" => Some("contextcrawler go ..."),
        "ruby" => Some("contextcrawler ruby ..."),
        "rake" => Some("contextcrawler rake ..."),
        "rspec" => Some("contextcrawler rspec ..."),
        "rubocop" => Some("contextcrawler rubocop ..."),
        _ => None,
    }
}

/// Merge pnpm global filters args with other ones for standard String-based commands
fn merge_pnpm_args(filters: &[String], args: &[String]) -> Vec<String> {
    filters
        .iter()
        .map(|filter| format!("--filter={}", filter))
        .chain(args.iter().cloned())
        .collect()
}

/// Merge pnpm global filters args with other ones, using OsString for passthrough compatibility
fn merge_pnpm_args_os(filters: &[String], args: &[OsString]) -> Vec<OsString> {
    filters
        .iter()
        .map(|filter| OsString::from(format!("--filter={}", filter)))
        .chain(args.iter().cloned())
        .collect()
}

/// Validate that pnpm filters are only used in the global context, not before subcommands like tsc.
fn validate_pnpm_filters(filters: &[String], command: &PnpmCommands) -> Option<String> {
    // Check if this is a Build or Typecheck command with filters
    match command {
        PnpmCommands::Typecheck { .. } => {
            // FIXME: if filters are present, we should find out which workspaces are selected before running ctxcrl dedicated commands
            if !filters.is_empty() {
                let cmd_name = match command {
                    PnpmCommands::Typecheck { .. } => "tsc",
                    _ => unreachable!(),
                };
                let msg = format!(
                    "[contextcrawler] warning: --filter is not yet supported for pnpm {}, filters preceding the subcommand will be ignored",
                    cmd_name
                );
                return Some(msg);
            }
            None
        }
        _ => None,
    }
}

/// SSRF block list for the `contextcrawler web` command.
///
/// Returns `Some(reason)` if the IP is in a range we refuse to fetch from.
/// `None` means safe to proceed.
///
/// Covers:
/// - Loopback (127.0.0.0/8, ::1)
/// - Link-local (169.254.0.0/16, fe80::/10) — includes AWS / GCP / Azure
///   metadata service at 169.254.169.254
/// - Azure metadata at 168.63.129.16 (not link-local, special-cased)
/// - Private RFC1918 (10/8, 172.16/12, 192.168/16) and ULA fc00::/7
/// - Multicast and "unspecified" (0.0.0.0, ::)
///
/// Initial-host only. An attacker who controls public DNS that resolves to
/// a private IP can still slip through via `--max-redirs`. The proper fix
/// is per-redirect-hop validation which would replace curl with a Rust
/// HTTP client we control end-to-end — tracked in docs/ROADMAP.md.
// Preserved for future SSRF wiring (was previously used by the
// web_cmd.rs that's been removed). Re-wire from curl/wget filter or a
// future Rust HTTP client; the IP classification logic is the expensive
// part to re-derive and is worth keeping in tree.
#[allow(dead_code)]
fn web_ssrf_block_reason(ip: &std::net::IpAddr) -> Option<&'static str> {
    use std::net::IpAddr;
    if ip.is_loopback() {
        return Some("loopback address");
    }
    if ip.is_unspecified() {
        return Some("unspecified address (0.0.0.0 / ::)");
    }
    if ip.is_multicast() {
        return Some("multicast address");
    }
    match ip {
        IpAddr::V4(v4) => {
            // Azure IMDS lives at a non-link-local public-looking address.
            if v4.octets() == [168, 63, 129, 16] {
                return Some("Azure metadata service");
            }
            if v4.is_link_local() {
                // 169.254.0.0/16 — includes AWS / GCP IMDS 169.254.169.254.
                return Some("link-local address (includes cloud metadata services)");
            }
            if v4.is_private() {
                return Some("private RFC1918 address");
            }
            // 100.64.0.0/10 — carrier-grade NAT, treat as private.
            let o = v4.octets();
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return Some("carrier-grade NAT (100.64.0.0/10)");
            }
            // 0.0.0.0/8 — "this network" reserved range. is_unspecified
            // catches only 0.0.0.0 exactly; the rest of /8 (0.0.0.1 .. 0.255.255.255)
            // is also blocked here. Codex review of the initial SSRF block flagged
            // this as missing.
            if o[0] == 0 {
                return Some("\"this network\" reserved 0.0.0.0/8");
            }
            // 198.18.0.0/15 — RFC 2544 benchmark range. Unlikely legitimate target;
            // historically used in network testing and pen-test labs.
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return Some("benchmark range 198.18.0.0/15 (RFC 2544)");
            }
            // 240.0.0.0/4 — future-use / experimental. No legitimate routable target
            // exists in this range as of 2026.
            if o[0] >= 240 && o[0] < 255 {
                return Some("future-use 240.0.0.0/4 (RFC 1112)");
            }
            // Reserved / benchmark / documentation ranges. Not strictly
            // SSRF-dangerous but unlikely to be a legitimate fetch target.
            if v4.is_documentation() || v4.is_broadcast() {
                return Some("reserved address (documentation/broadcast)");
            }
            None
        }
        IpAddr::V6(v6) => {
            // ULA fc00::/7
            if v6.octets()[0] & 0xfe == 0xfc {
                return Some("unique-local IPv6 (fc00::/7)");
            }
            // Link-local fe80::/10
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Some("link-local IPv6 (fe80::/10)");
            }
            // IPv4-mapped IPv6 — re-check as IPv4 so we catch ::ffff:10.0.0.1
            if let Some(v4) = v6.to_ipv4_mapped() {
                return web_ssrf_block_reason(&IpAddr::V4(v4));
            }
            None
        }
    }
}

/// Meta flags (`--version`, `-V`, `--help`, `-h`) that wrapper subcommands
/// don't explicitly declare. Without a pre-clap intercept these fall through
/// to `run_fallback` → raw exec, which writes a noisy parse_failure row per
/// invocation. Issue #90.
const META_FLAGS: &[&str] = &["--version", "-V", "--help", "-h"];

/// Wrappers that accept meta flags but don't pass them through cleanly via
/// clap. Pre-clap intercept routes these straight to a timed passthrough so
/// `contextcrawler cargo --version` works without a parse_failure row.
///
/// Codex review extension: the original list missed wrappers whose clap
/// subcommand structure also lacks a top-level `--version`/`--help` arm —
/// `gh`, `glab`, `aws`, `psql`, `prisma`, `gt`. Without these, meta flags
/// fell through to `run_fallback` → raw exec and produced parse_failure
/// rows. The regression test `meta_passthrough_covers_all_subcommand_only_wrappers`
/// guards against future drift.
///
/// Issue #96 extension: the Python/Ruby subcommand-style wrappers
/// (`pytest`, `ruff`, `mypy`, `rake`, `rubocop`, `rspec`, `pip`) have the
/// same shape — clap captures `--version` into a `trailing_var_arg` and the
/// filter handler then mangles version output (production DB recorded
/// `pytest --version` at −75% savings over 90 calls). Route their meta-flag
/// invocations to clean passthrough too.
const META_PASSTHROUGH_BINS: &[&str] = &[
    "cargo", "pnpm", "npm", "npx", "go", "docker", "kubectl", "gh", "glab", "aws", "psql",
    "prisma", "gt", "pytest", "ruff", "mypy", "rake", "rubocop", "rspec", "pip",
];

fn cmd_has_meta_flag(args: &[String]) -> bool {
    args.iter().any(|a| META_FLAGS.contains(&a.as_str()))
}

/// Timed raw passthrough used by the meta-flag intercept. Records a
/// passthrough row (so the call shows up in `gain --history`) but bypasses
/// clap/parse_failure entirely.
///
/// Uses `secure_meta_command` rather than a bare `resolved_command` so the
/// meta-flag path keeps the same runtime-env hardening (RUBYOPT/PYTHONPATH/
/// NODE_OPTIONS strip) the per-tool clap filter handlers apply. See #36/#96.
fn run_simple_passthrough(cmd: &str, args: &[String]) -> Result<i32> {
    use crate::core::tracking::TimedExecution;
    let timer = TimedExecution::start();
    let status = crate::core::utils::secure_meta_command(cmd)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    let raw_command = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{} {}", cmd, args.join(" "))
    };
    match status {
        Ok(s) => {
            timer.track_passthrough(
                &raw_command,
                &format!("contextcrawler {} (meta passthrough)", raw_command),
            );
            Ok(crate::core::utils::exit_code_from_status(&s, &raw_command))
        }
        Err(e) => {
            eprintln!("[contextcrawler: {}]", e);
            Ok(127)
        }
    }
}

/// Documented grep format flags that should run raw rather than go through
/// ctxcrl's filter. Short letters are matched anywhere inside a single-`-` bundle
/// (e.g. `-c`, `-ci`, `-cE`). Long forms match exactly.
///
/// `-l` is a special case (issue #97). clap's `Grep` variant claims `-l` for
/// `--max-len` (a usize). Standard `grep -l` (`--files-with-matches`) takes
/// no value, so `grep -l pattern file` makes clap try to parse `pattern` as a
/// usize and fail → `run_fallback`. We treat bare `-l` as a format flag (route
/// to rg) ONLY when it is NOT followed by a numeric token — `-l 80` stays the
/// app's `--max-len` and is left for clap.
fn grep_format_flag_present(args: &[String]) -> bool {
    const LONG_FLAGS: &[&str] = &[
        "--count",
        "--files-with-matches",
        "--files-without-match",
        "--only-matching",
        "--null",
    ];
    const SHORT_LETTERS: &[char] = &['c', 'L', 'o', 'Z'];

    for (i, arg) in args.iter().enumerate() {
        if LONG_FLAGS.contains(&arg.as_str()) {
            return true;
        }
        // Bare `-l`: standard grep --files-with-matches unless the next token
        // is numeric (then it's this app's `-l <max_len>`).
        if arg == "-l" {
            let next_is_numeric = args
                .get(i + 1)
                .map(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
            if !next_is_numeric {
                return true;
            }
            continue;
        }
        if arg.starts_with("--") || arg.len() < 2 || !arg.starts_with('-') {
            continue;
        }
        let body = &arg[1..];
        // Don't misread numeric/path-ish tokens like "-5" or "-3:foo".
        if !body.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        if body.chars().any(|c| SHORT_LETTERS.contains(&c)) {
            return true;
        }
        // Bundled `-l` (e.g. `-il`, `-ln`): a bundled `-l` can never carry a
        // separate numeric value, so it is always standard grep's
        // --files-with-matches. Route to rg.
        if body.len() > 1 && body.contains('l') {
            return true;
        }
    }
    false
}

/// Result of pre-clap grep preprocessing.
///
/// `Stripped` — recursive flags (`-r`/`-R`/`--recursive`) were removed and the
/// remaining args were reordered so the positional pattern/path come first
/// and any leading boolean grep flags (`-i`, `-n`, `-w`, …) trail behind them.
/// clap rejects an unknown short flag that appears *before* the `<PATTERN>`
/// positional — but the `extra_args` field is `trailing_var_arg` +
/// `allow_hyphen_values`, so once the positionals are consumed the same flags
/// parse cleanly. Reordering is what stops standard grep flags producing
/// `unexpected argument` parse failures (P0: 62% of all parse failures).
///
/// `Passthrough` — call contains context flags (`-A`/`-B`/`-C` or their long
/// forms), the print-filename flag (`-H`/`--with-filename`), a value-taking
/// flag (`-e`/`-f`/`-m`/…) or a documented format flag; route the whole call
/// to `run_grep_format_passthrough` (which uses rg natively and understands
/// recursive flags, context flags, and `-H`).
///
/// `Quiet` — call carries `-q`/`--quiet`. grep in quiet mode emits NO stdout
/// and is used purely for its exit code. Route to a quiet rg/grep run so the
/// filter never tries (and fails) to parse empty output, and never logs a
/// parse failure.
#[derive(Debug, PartialEq, Eq)]
enum GrepPreprocess {
    Stripped(Vec<String>),
    Passthrough(Vec<String>),
    Quiet(Vec<String>),
}

/// Boolean (valueless) standard grep flags that the ctxcrl-backed filter can
/// forward to rg and still filter the output normally. These are reordered
/// behind the positional pattern/path so clap parses them as `extra_args`.
/// `r`/`R`/`E` are NOT here — they are stripped separately (no-ops for rg).
/// `A`/`B`/`C`/`H` are NOT here — they route to passthrough.
/// `h`/`G` are NOT here — their grep meaning collides with rg: `rg -h` is
/// `--help` (grep `-h` is `--no-filename`) and rg has no `-G` (grep `-G` is
/// basic-regex). Reordering+forwarding either to rg yields silent help text
/// or an "unrecognized flag" exit 2. Both route to passthrough instead, where
/// the system-grep fallback handles them correctly — same as `-H`.
const GREP_BOOL_SHORTS: &[u8] = &[b'i', b'w', b'x', b'v', b'n', b's', b'F', b'P', b'a', b'I'];

/// Long-form boolean grep flags forwarded to rg with output still filtered.
const GREP_BOOL_LONGS: &[&str] = &[
    "--ignore-case",
    "--word-regexp",
    "--line-regexp",
    "--invert-match",
    "--line-number",
    "--no-filename",
    "--no-messages",
    "--fixed-strings",
    "--perl-regexp",
    "--basic-regexp",
    "--extended-regexp",
    "--text",
];

/// Standard grep value-taking flags (consume the next token, or carry it via
/// `--flag=value`). Reordering them safely is fragile, so any call carrying
/// one is routed to passthrough where rg parses the args natively.
const GREP_VALUE_LONGS: &[&str] = &[
    "--regexp",
    "--file",
    "--max-count",
    "--color",
    "--colour",
    "--label",
    "--binary-files",
    "--devices",
    "--directories",
    "--include",
    "--exclude",
    "--exclude-dir",
];

/// True if `arg` is a `-q`/`--quiet`/`--silent` quiet flag, bare or bundled.
fn is_grep_quiet_flag(arg: &str) -> bool {
    if arg == "--quiet" || arg == "--silent" {
        return true;
    }
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
        return false;
    }
    // Bare `-q` or `-q` inside an all-alphabetic short bundle (`-iq`, `-qn`).
    let body = &arg[1..];
    body.bytes().all(|b| b.is_ascii_alphabetic()) && body.bytes().any(|b| b == b'q')
}

/// True if `arg` is a standard grep value-taking flag (`-e`/`-f`/`-m` short,
/// or a long form in `GREP_VALUE_LONGS`, possibly `--flag=value`).
fn is_grep_value_flag(arg: &str) -> bool {
    for long in GREP_VALUE_LONGS {
        if arg == *long || arg.strip_prefix(long).is_some_and(|s| s.starts_with('=')) {
            return true;
        }
    }
    // Bare `-e`/`-f`/`-m` only — a bundle like `-ie` would mean something
    // else; keep this conservative and exact.
    matches!(arg, "-e" | "-f" | "-m")
}

/// True if `arg` is a recognised boolean grep flag (bare short, all-alpha
/// short bundle of bool letters, or a long form).
fn is_grep_bool_flag(arg: &str) -> bool {
    if GREP_BOOL_LONGS.contains(&arg) {
        return true;
    }
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
        return false;
    }
    let body = &arg[1..];
    body.bytes().all(|b| GREP_BOOL_SHORTS.contains(&b))
}

/// Short grep flags that are safe to drop entirely before handing args to
/// clap. clap's `Grep` variant doesn't declare them, so leaving them in
/// triggers a parse failure → `run_fallback`. Each is a behavioural no-op
/// for the downstream consumer:
///
/// - `r`/`R` — recursive. rg is recursive by default (issue #88).
/// - `E` — extended regex. rg's regex engine is extended by default, so
///   `grep -E` adds nothing (issue #97).
///
/// `-H` (print-filename-prefix) is intentionally NOT in this set. Codex
/// review of #96/#97: stripping it silently dropped filename output from
/// `grep -H -c …` / `grep -H -o …`. rg honours `-H` / `--with-filename`,
/// so any grep call carrying `-H` is routed to `run_grep_format_passthrough`
/// instead — same treatment as the `-A`/`-B`/`-C` context flags.
///
/// These are stripped from bare short flags AND from alphabetic bundles
/// (`-rnE` → `-n`). Stripping is applied on the passthrough path too — rg
/// reads bare `-r` as `--replace`, so a stale `-r` would silently corrupt
/// matches.
const GREP_STRIPPABLE_SHORTS: &[u8] = &[b'r', b'R', b'E'];

/// Two-pass pre-clap normaliser for `grep` subcommand args.
///
/// Pass 1 strips behavioural-no-op short flags (`-r`/`-R`/`-E`/`-H` and
/// `--recursive`) so clap can parse the remainder cleanly.
/// Pass 2 detects context flags (`-A`/`-B`/`-C`, `--after-context` etc.)
/// and routes the stripped args to passthrough so rg handles them
/// natively. Stripping is intentionally applied to the passthrough path
/// too — rg interprets bare `-r` as `--replace` (replacement string),
/// not recursive, so leaving it in would silently produce wrong matches.
/// See issues #88 and #97, and the Codex review on the original fix.
fn preprocess_grep_args(args: Vec<String>) -> GrepPreprocess {
    // Pass 1: strip no-op short flags from short bundles + long forms.
    // Iterator-based; only allocate a new String when a bundle actually
    // needs rewriting. Tokens that survive untouched are moved as-is.
    let mut stripped: Vec<String> = Vec::with_capacity(args.len());
    for arg in args.into_iter() {
        if arg == "-r" || arg == "-R" || arg == "-E" || arg == "--recursive" {
            continue;
        }
        // Single-`-` bundle of alphabetic chars: strip r/R/E, keep rest.
        // Avoid the chars().collect::<Vec<_>>() — scan bytes directly.
        if arg.len() > 1 && arg.starts_with('-') && !arg.starts_with("--") {
            let body = &arg[1..];
            let bytes = body.as_bytes();
            let all_alpha = bytes.iter().all(|b| b.is_ascii_alphabetic());
            if all_alpha {
                let has_strippable = bytes.iter().any(|b| GREP_STRIPPABLE_SHORTS.contains(b));
                if has_strippable {
                    let kept: String = body
                        .bytes()
                        .filter(|b| !GREP_STRIPPABLE_SHORTS.contains(b))
                        .map(|b| b as char)
                        .collect();
                    if kept.is_empty() {
                        continue;
                    }
                    stripped.push(format!("-{}", kept));
                    continue;
                }
            }
        }
        stripped.push(arg);
    }

    // Pass 2: quiet mode. `-q`/`--quiet` produces no stdout — the call is
    // used purely for its exit code. Route to a dedicated quiet run so the
    // filter never logs a parse failure for a flag it can't model.
    if stripped.iter().any(|a| is_grep_quiet_flag(a)) {
        return GrepPreprocess::Quiet(stripped);
    }

    // Pass 3: detect context flags, the print-filename flag (`-H`), or a
    // value-taking flag (`-e`/`-f`/`-m`/`--include`/…). If any present, route
    // to passthrough — rg honours `-A`/`-B`/`-C`, `-H` and value flags
    // natively, the ctxcrl-backed line-by-line filter can't reorder them safely.
    if has_grep_context_flag(&stripped)
        || has_grep_with_filename_flag(&stripped)
        || stripped.iter().any(|a| is_grep_value_flag(a))
    {
        return GrepPreprocess::Passthrough(stripped);
    }

    // Pass 4: reorder. clap rejects an unknown short flag that appears before
    // the `<PATTERN>` positional. Move every recognised boolean grep flag
    // behind the positionals so clap parses them into `extra_args` (which is
    // `trailing_var_arg` + `allow_hyphen_values`). `grep_cmd::run` forwards
    // `extra_args` to rg unchanged and still filters the output. Any token
    // that is not a recognised flag is treated as a positional and keeps its
    // relative order, so `pattern` and `path` stay correct.
    let mut positionals: Vec<String> = Vec::with_capacity(stripped.len());
    let mut bool_flags: Vec<String> = Vec::new();
    for arg in stripped {
        if is_grep_bool_flag(&arg) {
            bool_flags.push(arg);
        } else {
            positionals.push(arg);
        }
    }
    positionals.extend(bool_flags);
    GrepPreprocess::Stripped(positionals)
}

/// True if any arg is a grep context flag (`-A`/`-B`/`-C` short or long).
fn has_grep_context_flag(args: &[String]) -> bool {
    const LONG_FLAGS: &[&str] = &["--after-context", "--before-context", "--context"];

    for arg in args {
        // Long forms — match exact and `--flag=value`.
        if LONG_FLAGS
            .iter()
            .any(|f| arg == f || arg.strip_prefix(f).is_some_and(|s| s.starts_with('=')))
        {
            return true;
        }
        if arg.starts_with("--") || !arg.starts_with('-') || arg.len() < 2 {
            continue;
        }
        // Standalone `-A`/`-B`/`-C` (next arg is the value).
        if arg.len() == 2 {
            let c = arg.chars().nth(1).unwrap();
            if c == 'A' || c == 'B' || c == 'C' {
                return true;
            }
            continue;
        }
        // Bundle like `-A3`, `-iA3`, `-B2`. A/B/C followed by digits.
        let body = &arg[1..];
        let bytes = body.as_bytes();
        for i in 0..bytes.len() {
            let c = bytes[i];
            if (c == b'A' || c == b'B' || c == b'C')
                && bytes
                    .get(i + 1)
                    .map(|n| n.is_ascii_digit())
                    .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

/// True if any arg carries a grep short flag whose meaning collides with rg
/// and so must route to passthrough rather than be reordered+forwarded:
///
/// - `-H` / `--with-filename` — print-filename. Codex review of #96/#97:
///   stripping `-H` silently dropped filename output from `grep -H -c …`.
/// - `-h` / `--no-filename` — grep suppresses filenames, but `rg -h` is
///   `--help`. Forwarding it makes rg print help text the filter mangles.
/// - `-G` / `--basic-regexp` — grep basic-regex, but rg has no `-G` and
///   exits 2 with "unrecognized flag".
///
/// Long forms (`--with-filename`, `--no-filename`, `--basic-regexp`) are in
/// `GREP_BOOL_LONGS` and rg understands those, so only the short forms need
/// this special routing. The system-grep fallback in the passthrough path
/// handles all three correctly.
fn has_grep_with_filename_flag(args: &[String]) -> bool {
    for arg in args {
        if arg == "--with-filename" {
            return true;
        }
        if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
            continue;
        }
        // Bare `-H`/`-h`/`-G` or any of them inside an all-alphabetic short
        // bundle (`-Hn`, `-iHc`, `-hn`, `-iG`). Digits would mean it's a
        // context-flag bundle, handled separately; none of these take a value.
        let body = &arg[1..];
        if body.bytes().any(|b| b == b'H' || b == b'h' || b == b'G') {
            return true;
        }
    }
    false
}

/// Run the user's grep command through `rg` (ripgrep), bypassing clap and
/// parse_failure tracking. We route through `rg` rather than bare `grep`
/// because rg understands both the documented format flags (`-c`, `-L`, `-o`,
/// `--null`, `--count`, `--files-with-matches`, etc.) AND the ctxcrl-extra
/// options the ctxcrl-backed grep path accepts (`--glob`, `--type`/`-t`,
/// `--include`). Falls back to system `grep` only if rg cannot be located.
fn run_grep_format_passthrough(args: &[String]) -> Result<i32> {
    run_grep_passthrough_labelled(args, "format-flag passthrough")
}

/// Variant of `run_grep_format_passthrough` that lets the caller supply an
/// accurate tracking-DB label for the route taken (e.g. "quiet passthrough"
/// for `-q` calls, where "format-flag passthrough" would be misleading).
fn run_grep_passthrough_labelled(args: &[String], route: &str) -> Result<i32> {
    let raw_command = args.join(" ");
    let timer = core::tracking::TimedExecution::start();
    let user_args = &args[1..];

    // Reject `--pre`, `--pre-glob`, `--search-zip` / `-z` before they reach
    // rg — they enable arbitrary code execution per file. See issue #32.
    if let Err(msg) = core::utils::check_forbidden_rg_args(user_args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    // Prefer rg so mixed invocations like `grep -c --glob '*.rs' pat` keep
    // working. If rg isn't on PATH, fall through to system grep.
    let preferred = if which::which("rg").is_ok() {
        "rg"
    } else {
        "grep"
    };

    // `secure_rg_command` strips RIPGREP_CONFIG_PATH/_FILE from the inherited
    // env so a tainted parent process can't hijack this rg invocation via
    // a config file containing `--pre`. See issue #32.
    let status = core::utils::secure_rg_command(preferred)
        .args(user_args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    match status {
        Ok(s) => {
            timer.track_passthrough(
                &raw_command,
                &format!(
                    "contextcrawler grep ({} via {}): {}",
                    route, preferred, raw_command
                ),
            );
            Ok(core::utils::exit_code_from_status(&s, &raw_command))
        }
        Err(e) => {
            eprintln!("[contextcrawler: {}]", e);
            Ok(127)
        }
    }
}

/// Run a context-flag grep call (`-A`/`-B`/`-C`) through rg, CAPTURE the
/// output, and filter it (issue #193). The old behaviour inherited stdout
/// straight to the terminal — zero token savings on the single highest-yield
/// grep shape (recursive search with surrounding context). Here we capture
/// rg's grouped output and cap it via `grep_cmd::filter_context_output` using
/// the same `[limits]` knobs as the non-context path. The `no_bloat` guard
/// ensures a small result is never inflated by the framing.
///
/// Falls back to a raw passthrough run if rg cannot be located or capture
/// fails, so the user always gets their matches (ContextCrawler fallback discipline).
fn run_grep_context_filtered(args: &[String]) -> Result<i32> {
    let raw_command = args.join(" ");
    let timer = core::tracking::TimedExecution::start();
    let user_args = &args[1..];

    // Reject `--pre`, `--pre-glob`, `--search-zip` / `-z` before they reach rg
    // — they enable arbitrary code execution per file. See issue #32.
    if let Err(msg) = core::utils::check_forbidden_rg_args(user_args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    // ctxcrl-backed filtering needs rg's grouped, machine-parseable output. If rg
    // is not on PATH, fall back to the raw passthrough (system grep) path —
    // we can't reliably filter arbitrary system-grep context output.
    if which::which("rg").is_err() {
        return run_grep_passthrough_labelled(args, "context passthrough (no rg)");
    }

    // `secure_rg_command` strips RIPGREP_CONFIG_PATH/_FILE from the inherited
    // env so a tainted parent can't hijack this rg invocation via a config
    // file containing `--pre`. See issue #32.
    let mut cmd = core::utils::secure_rg_command("rg");
    cmd.args(user_args);

    let captured = match core::stream::exec_capture(&mut cmd) {
        Ok(c) => c,
        Err(_) => {
            // Capture failed (spawn error, timeout): fall back to raw so the
            // user is never left without output.
            return run_grep_passthrough_labelled(args, "context passthrough (capture failed)");
        }
    };

    let raw_stdout = captured.stdout;
    let exit_code = captured.exit_code;

    // No matches: emit nothing but surface real errors (bad regex, etc.).
    if raw_stdout.trim().is_empty() {
        if exit_code == 2 && !captured.stderr.trim().is_empty() {
            eprintln!("{}", captured.stderr.trim());
        }
        timer.track(&raw_command, "rtk grep (context)", &raw_stdout, "");
        return Ok(exit_code);
    }

    let limits = core::config::limits();
    let (filtered, _groups) = grep_cmd::filter_context_output(
        &raw_stdout,
        limits.grep_max_results,
        limits.grep_max_per_file,
    );

    // no_bloat: never let the framing cost more than the raw output saves.
    let emitted = core::runner::no_bloat(&raw_stdout, &filtered);
    print!("{}", emitted);
    if !captured.stderr.trim().is_empty() && exit_code == 2 {
        eprintln!("{}", captured.stderr.trim());
    }
    timer.track(&raw_command, "rtk grep (context)", &raw_stdout, emitted);
    Ok(exit_code)
}

/// Library entrypoint for the CLI. Returns the process exit code; the thin
/// binary shim (`src/main.rs`) calls `std::process::exit` on the result so the
/// binary dogfoods this exact path.
pub fn run() -> i32 {
    // SIGPIPE fix (#startup-crash): Rust sets SIGPIPE to SIG_IGN by default,
    // so a broken pipe on stdout returns EPIPE instead of terminating the
    // process. When println!() gets EPIPE it panics with
    // "failed printing to stdout", and with panic=abort that becomes SIGABRT.
    // Restore SIG_DFL here so a broken-pipe write terminates the process
    // cleanly (exit 141) instead of aborting with a crash report.
    //
    // Uses the same `#[cfg(unix)] unsafe { libc::signal(...) }` idiom as
    // the proxy path (SIGINT/SIGTERM handler; search PROXY_CHILD_PID). The
    // unsafe block is the only way to reset signal disposition portably
    // without an extra crate.
    //
    // nosemgrep: unsafe-block
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // Move any legacy `rtk` config/data/project dirs to the canonical `ctxcrl`
    // names before anything reads them. Cheap + idempotent (guarded by a Once).
    core::path_migrate::migrate_legacy_dirs_once();

    match run_cli() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("contextcrawler: {:#}", e);
            1
        }
    }
}

// 8 args: one per special-cased agent (Hermes, Pi) plus the standard
// fallback, with the dispatch flags (agent, global, gemini, codex, ctx).
// Collapsing into a struct buys little — these are call-site-level routing
// callbacks, not domain state.
#[allow(clippy::too_many_arguments)]
fn uninstall_init_dispatch<UninstallHermes, UninstallPidev, UninstallStandard>(
    agent: Option<AgentTarget>,
    global: bool,
    gemini: bool,
    codex: bool,
    ctx: hooks::init::InitContext,
    uninstall_hermes: UninstallHermes,
    uninstall_pidev: UninstallPidev,
    uninstall_standard: UninstallStandard,
) -> Result<()>
where
    UninstallHermes: FnOnce(hooks::init::InitContext) -> Result<()>,
    UninstallPidev: FnOnce(hooks::init::InitContext) -> Result<()>,
    UninstallStandard: FnOnce(bool, bool, bool, bool, hooks::init::InitContext) -> Result<()>,
{
    if agent == Some(AgentTarget::Hermes) {
        uninstall_hermes(ctx)
    } else if agent == Some(AgentTarget::Pidev) {
        uninstall_pidev(ctx)
    } else {
        let cursor = agent == Some(AgentTarget::Cursor);
        uninstall_standard(global, gemini, codex, cursor, ctx)
    }
}

#[cfg(test)]
mod cli_branding_tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn test_cli_name_pinned_to_contextcrawler() {
        // REGRESSION GUARD (issue #22). The clap `name` attribute drives
        // `--version` / `--help` output. The downstream rebrand requires
        // it to read "contextcrawler", not the upstream "rtk". A previous
        // rebase silently flipped this with no test to catch it.
        let cmd = Cli::command();
        assert_eq!(
            cmd.get_name(),
            "contextcrawler",
            "branding regression: see issue #22"
        );
    }
}

#[cfg(test)]
mod grep_format_flag_tests {
    use super::grep_format_flag_present;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn short_c_triggers() {
        assert!(grep_format_flag_present(&args(&["-c", "pattern", "file"])));
    }

    #[test]
    #[allow(non_snake_case)] // -L names the grep --files-without-match flag
    fn short_L_triggers() {
        assert!(grep_format_flag_present(&args(&["-L", "pattern", "file"])));
    }

    #[test]
    fn short_o_triggers() {
        assert!(grep_format_flag_present(&args(&["-o", "pattern", "file"])));
    }

    #[test]
    #[allow(non_snake_case)] // -Z names the grep --null flag
    fn short_Z_triggers() {
        assert!(grep_format_flag_present(&args(&["-Z", "pattern"])));
    }

    #[test]
    fn bundled_short_with_format_letter_triggers() {
        assert!(grep_format_flag_present(&args(&["-ci", "pattern", "file"])));
        assert!(grep_format_flag_present(&args(&["-cE", "pattern", "file"])));
        assert!(grep_format_flag_present(&args(&["-cn", "pattern", "file"])));
        assert!(grep_format_flag_present(&args(&[
            "-iLn", "pattern", "file"
        ])));
    }

    #[test]
    fn long_forms_trigger() {
        assert!(grep_format_flag_present(&args(&[
            "--count", "pattern", "file"
        ])));
        assert!(grep_format_flag_present(&args(&[
            "--files-with-matches",
            "pattern",
            "file"
        ])));
        assert!(grep_format_flag_present(&args(&[
            "--files-without-match",
            "pattern",
            "file"
        ])));
        assert!(grep_format_flag_present(&args(&[
            "--only-matching",
            "pattern",
            "file"
        ])));
        assert!(grep_format_flag_present(&args(&[
            "--null", "pattern", "file"
        ])));
    }

    #[test]
    fn dash_l_with_numeric_value_does_not_trigger() {
        // `-l 80` is this app's --max-len; leave it for clap. Issue #97.
        assert!(!grep_format_flag_present(&args(&[
            "-l", "80", "pattern", "file"
        ])));
    }

    #[test]
    fn dash_l_with_non_numeric_next_triggers() {
        // `grep -l pattern file` is standard grep --files-with-matches.
        // clap would try to read `pattern` as the --max-len usize and fail,
        // so route to rg. Issue #97.
        assert!(grep_format_flag_present(&args(&["-l", "needle", "a.txt"])));
    }

    #[test]
    fn dash_l_at_end_triggers() {
        // Trailing `-l` has no value to consume — standard grep -l.
        assert!(grep_format_flag_present(&args(&["needle", "-l"])));
    }

    #[test]
    fn bundled_dash_l_triggers() {
        // `-il` / `-ln` bundle `-l` with other flags — a bundled `-l` can
        // never carry a numeric value, so it is always standard grep -l.
        assert!(grep_format_flag_present(&args(&["-il", "pattern", "file"])));
        assert!(grep_format_flag_present(&args(&["-ln", "pattern", "file"])));
    }

    #[test]
    fn normal_recursive_grep_does_not_trigger() {
        assert!(!grep_format_flag_present(&args(&[
            "-rn", "pattern", "src/"
        ])));
        assert!(!grep_format_flag_present(&args(&[
            "-r", "-n", "pattern", "src/"
        ])));
        assert!(!grep_format_flag_present(&args(&["-i", "pattern", "file"])));
    }

    #[test]
    fn numeric_dash_tokens_ignored() {
        // e.g. `-5` as a context value or a stray number, not a flag bundle.
        assert!(!grep_format_flag_present(&args(&["-5", "pattern"])));
        assert!(!grep_format_flag_present(&args(&["-A", "3", "pattern"])));
    }

    #[test]
    fn empty_args_ok() {
        assert!(!grep_format_flag_present(&args(&[])));
    }

    #[test]
    fn double_dash_unrelated_does_not_trigger() {
        assert!(!grep_format_flag_present(&args(&[
            "--include=*.rs",
            "pattern"
        ])));
    }
}

#[cfg(test)]
mod grep_preprocess_tests {
    use super::{preprocess_grep_args, GrepPreprocess};

    fn v(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_preprocess_grep_strips_bare_r() {
        let out = preprocess_grep_args(v(&["-r", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", "."])));
    }

    #[test]
    fn test_preprocess_grep_strips_bundled_rn() {
        // -rn: r stripped, -n survives but is reordered behind the
        // positionals (Pass 4) so clap parses it as trailing extra_args.
        let out = preprocess_grep_args(v(&["-rn", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", ".", "-n"])));
    }

    #[test]
    fn test_preprocess_grep_strips_bundled_nr() {
        let out = preprocess_grep_args(v(&["-nr", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", ".", "-n"])));
    }

    #[test]
    #[allow(non_snake_case)] // -R names the grep --dereference-recursive flag
    fn test_preprocess_grep_strips_capital_R() {
        let out = preprocess_grep_args(v(&["-Rn", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", ".", "-n"])));
    }

    #[test]
    fn test_preprocess_grep_strips_long_recursive() {
        let out = preprocess_grep_args(v(&["--recursive", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", "."])));
    }

    #[test]
    fn test_preprocess_grep_keeps_other_short_letters() {
        // -in is a recognised boolean bundle: kept, reordered behind the
        // positionals so clap parses it as trailing extra_args.
        let out = preprocess_grep_args(v(&["-in", "needle", "file"]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", "file", "-in"])));
    }

    #[test]
    fn test_preprocess_grep_strips_rin_to_in() {
        let out = preprocess_grep_args(v(&["-rin", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", ".", "-in"])));
    }

    #[test]
    fn test_preprocess_grep_context_flag_short_routes_passthrough() {
        let out = preprocess_grep_args(v(&["-A3", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-A3", "needle", "file"]))
        );
    }

    #[test]
    fn test_preprocess_grep_context_flag_long_routes_passthrough() {
        let out = preprocess_grep_args(v(&["--after-context=3", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["--after-context=3", "needle", "file"]))
        );
    }

    #[test]
    fn test_preprocess_grep_context_flag_with_space() {
        let out = preprocess_grep_args(v(&["-A", "3", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-A", "3", "needle", "file"]))
        );
    }

    #[test]
    #[allow(non_snake_case)] // names the grep -iA3 bundled flags
    fn test_preprocess_grep_bundled_iA3_routes_passthrough_with_original() {
        // -iA3 contains a context flag bundled with -i. Route to passthrough
        // with original args so rg sees the full intent.
        let out = preprocess_grep_args(v(&["-iA3", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-iA3", "needle", "file"]))
        );
    }

    #[test]
    fn test_preprocess_grep_recursive_plus_context_strips_r_before_passthrough() {
        // Codex review: rg reads bare `-r` as --replace, not recursive,
        // so the stripper MUST run before passthrough too. rg is recursive
        // by default — dropping `-r` is safe.
        let out = preprocess_grep_args(v(&["-r", "-A3", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Passthrough(v(&["-A3", "needle", "."])));
    }

    #[test]
    fn test_preprocess_grep_long_recursive_plus_context_strips_before_passthrough() {
        let out = preprocess_grep_args(v(&["--recursive", "-A", "2", "needle", "."]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-A", "2", "needle", "."]))
        );
    }

    #[test]
    fn test_preprocess_grep_bundled_rn_plus_context_strips_r() {
        // Bundled -rn alongside -A3: r gets stripped from the bundle,
        // -n + -A3 survive, route to passthrough.
        let out = preprocess_grep_args(v(&["-rn", "-A3", "needle", "."]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-n", "-A3", "needle", "."]))
        );
    }

    #[test]
    fn test_preprocess_grep_reorders_leading_bool_flags_behind_positionals() {
        // P0 fix: leading boolean grep flags (`-i`, `-w`) are reordered
        // behind the positionals so clap parses them as `extra_args` instead
        // of rejecting them as `unexpected argument`.
        let out = preprocess_grep_args(v(&["-i", "-w", "pattern", "path"]));
        assert_eq!(
            out,
            GrepPreprocess::Stripped(v(&["pattern", "path", "-i", "-w"]))
        );
    }

    #[test]
    #[allow(non_snake_case)] // -B names the grep --before-context flag
    fn test_preprocess_grep_dash_B_alone_routes_passthrough() {
        let out = preprocess_grep_args(v(&["-B", "2", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-B", "2", "needle", "file"]))
        );
    }

    // ---- issue #97: strip -E no-op flag, route -H to passthrough ----

    #[test]
    #[allow(non_snake_case)] // -E names the grep --extended-regexp flag
    fn test_preprocess_grep_strips_bare_E() {
        // -E (extended regex) is a no-op for rg → strip, clap parses cleanly.
        let out = preprocess_grep_args(v(&["-E", "needle", "a.txt"]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", "a.txt"])));
    }

    #[test]
    #[allow(non_snake_case)] // -H names the grep --with-filename flag
    fn test_preprocess_grep_routes_bare_H_to_passthrough() {
        // Codex review of #96/#97: -H (print-filename) is NOT stripped —
        // doing so dropped filename output. It routes to passthrough so rg
        // honours --with-filename. -H is preserved in the args.
        let out = preprocess_grep_args(v(&["-H", "needle", "a.txt"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-H", "needle", "a.txt"]))
        );
    }

    #[test]
    fn test_preprocess_grep_lowercase_h_routes_passthrough() {
        // grep -h = --no-filename; rg -h = --help. Must route to passthrough.
        let out = preprocess_grep_args(v(&["-h", "needle", "file"]));
        assert!(matches!(out, GrepPreprocess::Passthrough(_)), "got {out:?}");
    }

    #[test]
    #[allow(non_snake_case)] // -G names the grep --basic-regexp flag
    fn test_preprocess_grep_basic_regex_G_routes_passthrough() {
        let out = preprocess_grep_args(v(&["-G", "needle", "file"]));
        assert!(matches!(out, GrepPreprocess::Passthrough(_)), "got {out:?}");
    }

    #[test]
    #[allow(non_snake_case)] // -rnE names bundled grep flags (incl. -E)
    fn test_preprocess_grep_strips_bundled_rnE() {
        // -rnE: r + E stripped, -n survives and reorders behind positionals.
        let out = preprocess_grep_args(v(&["-rnE", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", ".", "-n"])));
    }

    #[test]
    #[allow(non_snake_case)] // -HnE names bundled grep flags (incl. -H, -E)
    fn test_preprocess_grep_bundled_HnE_routes_to_passthrough() {
        // -HnE: E stripped, but the surviving -Hn bundle carries -H so the
        // call routes to passthrough (rg honours -H natively). -n is kept.
        let out = preprocess_grep_args(v(&["-HnE", "needle", "a.txt"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-Hn", "needle", "a.txt"]))
        );
    }

    #[test]
    #[allow(non_snake_case)] // -E names the grep --extended-regexp flag
    fn test_preprocess_grep_strips_E_only_bundle_fully() {
        // -E alone in a bundle leaves nothing → token dropped entirely.
        // The surviving -n reorders behind the positionals.
        let out = preprocess_grep_args(v(&["-E", "-n", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", ".", "-n"])));
    }

    #[test]
    #[allow(non_snake_case)] // -E names the grep --extended-regexp flag
    fn test_preprocess_grep_E_with_context_strips_E_before_passthrough() {
        // -E + -A3: E stripped, context flag routes to passthrough.
        let out = preprocess_grep_args(v(&["-E", "-A3", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Passthrough(v(&["-A3", "needle", "."])));
    }

    // ---- P0 fix: standard grep flags must never cause a parse failure ----
    // 1,255 production parse failures (62% of all) were `grep` invocations
    // where clap rejected a standard flag appearing before the <PATTERN>
    // positional. Each case below MUST resolve to a route that parses
    // cleanly — never `run_fallback` with an `unexpected argument` error.

    #[test]
    fn test_preprocess_grep_quiet_short_routes_to_quiet() {
        // `-q` is the single biggest source of parse failures (811 cases).
        let out = preprocess_grep_args(v(&["-q", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Quiet(v(&["-q", "needle", "."])));
    }

    #[test]
    fn test_preprocess_grep_quiet_long_routes_to_quiet() {
        let out = preprocess_grep_args(v(&["--quiet", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Quiet(v(&["--quiet", "needle", "."])));
    }

    #[test]
    fn test_preprocess_grep_quiet_bundled_routes_to_quiet() {
        // `-iq` — quiet bundled with ignore-case.
        let out = preprocess_grep_args(v(&["-iq", "needle", "."]));
        assert_eq!(out, GrepPreprocess::Quiet(v(&["-iq", "needle", "."])));
    }

    #[test]
    fn test_preprocess_grep_recursive_then_pattern() {
        // `grep -r pattern dir` — r stripped, pattern/dir kept as positionals.
        let out = preprocess_grep_args(v(&["-r", "pattern", "dir"]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["pattern", "dir"])));
    }

    #[test]
    #[allow(non_snake_case)] // -E names the grep --extended-regexp flag
    fn test_preprocess_grep_E_then_pattern() {
        // `grep -E 'a|b' file` — E stripped (no-op for rg), positionals kept.
        let out = preprocess_grep_args(v(&["-E", "a|b", "file"]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["a|b", "file"])));
    }

    #[test]
    fn test_preprocess_grep_i_n_reorders_behind_pattern() {
        // `grep -i -n pattern file` — both bool flags reorder behind the
        // positionals so clap parses them as `extra_args`, not unexpected.
        let out = preprocess_grep_args(v(&["-i", "-n", "pattern", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Stripped(v(&["pattern", "file", "-i", "-n"]))
        );
    }

    #[test]
    #[allow(non_snake_case)] // -A/-B name the grep --after/--before-context flags
    fn test_preprocess_grep_context_AB_routes_passthrough() {
        // `grep -A2 -B2 pattern file` — context flags route to passthrough
        // (rg honours them natively); never an `unexpected argument` error.
        let out = preprocess_grep_args(v(&["-A2", "-B2", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-A2", "-B2", "needle", "file"]))
        );
    }

    #[test]
    fn test_preprocess_grep_regex_flavour_flags_reorder() {
        // -F/-P regex-flavour flags are accepted, reordered behind the
        // positionals and forwarded to rg. -G is NOT here — rg has no -G,
        // so it routes to passthrough (see
        // test_preprocess_grep_basic_regex_G_routes_passthrough).
        for flag in ["-F", "-P"] {
            let out = preprocess_grep_args(v(&[flag, "needle", "file"]));
            assert_eq!(
                out,
                GrepPreprocess::Stripped(v(&["needle", "file", flag])),
                "flag {flag} should reorder behind positionals"
            );
        }
    }

    #[test]
    fn test_preprocess_grep_value_flag_routes_passthrough() {
        // `grep -e pattern file` — `-e` takes a value; reordering it is
        // fragile, so the call routes to passthrough where rg parses it.
        let out = preprocess_grep_args(v(&["-e", "needle", "file"]));
        assert_eq!(
            out,
            GrepPreprocess::Passthrough(v(&["-e", "needle", "file"]))
        );
    }

    #[test]
    fn test_preprocess_grep_invert_match_reorders() {
        // `-v` (invert-match) is a standard bool flag. NB: clap also declares
        // `-v` as the global verbosity flag, but on the grep path it is a
        // recognised grep bool flag and reorders into extra_args.
        let out = preprocess_grep_args(v(&["-v", "needle", "file"]));
        assert_eq!(out, GrepPreprocess::Stripped(v(&["needle", "file", "-v"])));
    }

    // Helper-level coverage for the classifiers.
    #[test]
    fn test_classifier_quiet() {
        use super::is_grep_quiet_flag;
        assert!(is_grep_quiet_flag("-q"));
        assert!(is_grep_quiet_flag("--quiet"));
        assert!(is_grep_quiet_flag("--silent"));
        assert!(is_grep_quiet_flag("-iq"));
        assert!(!is_grep_quiet_flag("-i"));
        assert!(!is_grep_quiet_flag("needle"));
        assert!(!is_grep_quiet_flag("--q")); // not a real long flag
    }

    #[test]
    fn test_classifier_bool() {
        use super::is_grep_bool_flag;
        assert!(is_grep_bool_flag("-i"));
        assert!(is_grep_bool_flag("-in"));
        assert!(is_grep_bool_flag("--ignore-case"));
        assert!(!is_grep_bool_flag("-A")); // context flag
        assert!(!is_grep_bool_flag("-c")); // format flag
        assert!(!is_grep_bool_flag("needle"));
    }

    #[test]
    fn test_classifier_value() {
        use super::is_grep_value_flag;
        assert!(is_grep_value_flag("-e"));
        assert!(is_grep_value_flag("-f"));
        assert!(is_grep_value_flag("-m"));
        assert!(is_grep_value_flag("--include"));
        assert!(is_grep_value_flag("--include=*.rs"));
        assert!(!is_grep_value_flag("-i"));
        assert!(!is_grep_value_flag("needle"));
    }

    // ---- run_cli pipeline-ordering regression tests ----
    //
    // These mirror the run_cli ordering: preprocess first, then format-flag
    // check on the stripped args. They guard against the Codex-reported bug
    // where mixed `grep -c -r pat .` invocations bypassed the recursive
    // stripper and reached rg with `-r` (which rg reads as --replace).

    use super::grep_format_flag_present;

    fn run_cli_grep_pipeline(args: Vec<String>) -> Vec<String> {
        // Reproduces the relevant slice of run_cli's pre-clap routing so
        // we can assert what the downstream consumer (rg or clap) actually
        // sees. Returns the final args slice (without the leading "grep").
        let preprocessed = preprocess_grep_args(args);
        let working: &[String] = match &preprocessed {
            GrepPreprocess::Stripped(a)
            | GrepPreprocess::Passthrough(a)
            | GrepPreprocess::Quiet(a) => a.as_slice(),
        };
        if grep_format_flag_present(working) {
            return working.to_vec();
        }
        match preprocessed {
            GrepPreprocess::Passthrough(a)
            | GrepPreprocess::Stripped(a)
            | GrepPreprocess::Quiet(a) => a,
        }
    }

    #[test]
    fn test_grep_format_flag_with_recursive_strips_r_before_passthrough() {
        // Codex review case: `grep -c -r needle .` MUST NOT reach rg with
        // -r in the args (rg would treat it as --replace).
        let out = run_cli_grep_pipeline(v(&["-c", "-r", "needle", "."]));
        assert!(!out.iter().any(|a| a == "-r"), "stale -r in: {:?}", out);
        assert_eq!(out, v(&["-c", "needle", "."]));
    }

    #[test]
    fn test_grep_format_flag_with_long_recursive() {
        let out = run_cli_grep_pipeline(v(&["-c", "--recursive", "needle", "."]));
        assert!(
            !out.iter().any(|a| a == "--recursive"),
            "stale --recursive in: {:?}",
            out
        );
        assert_eq!(out, v(&["-c", "needle", "."]));
    }

    #[test]
    fn test_grep_format_flag_with_bundled_recursive_strips_only_r() {
        // `grep -cr needle .` — bundled. -c is the format trigger, -r must
        // be peeled out, surviving args go to passthrough.
        let out = run_cli_grep_pipeline(v(&["-cr", "needle", "."]));
        // -cr bundle: -r stripped → -c remains. Format-flag check on the
        // stripped args fires and we route to passthrough with -c.
        assert_eq!(out, v(&["-c", "needle", "."]));
    }

    // ---- issue #97: residual flags must never reach clap unrecognised ----

    /// No alphabetic single-`-` token in the pipeline output is a flag that
    /// clap's `Grep` variant would reject. clap declares `-l -m -t -n`
    /// (plus `trailing_var_arg`). `-r/-R/-E` get stripped; `-H` and format
    /// flags route to passthrough (never reaching clap). Anything else
    /// surviving here must be a clap-known short or part of a passthrough
    /// route.
    fn pipeline_has_clap_rejecting_flag(out: &[String]) -> bool {
        // `-E` is the only flag #97 strips outright; if it survives a
        // Stripped route it would hit clap and fail. `-H` is intentionally
        // NOT checked here — it routes to passthrough, so a surviving bare
        // `-H` is correct (Codex review of #96/#97).
        out.iter().any(|a| a == "-E")
    }

    #[test]
    #[allow(non_snake_case)] // -E names the grep --extended-regexp flag
    fn test_pipeline_E_does_not_leave_clap_rejecting_flag() {
        let out = run_cli_grep_pipeline(v(&["-E", "needle", "a.txt"]));
        assert!(!pipeline_has_clap_rejecting_flag(&out), "got {:?}", out);
        assert_eq!(out, v(&["needle", "a.txt"]));
    }

    #[test]
    #[allow(non_snake_case)] // -H names the grep --with-filename flag
    fn test_pipeline_H_routes_to_passthrough_preserving_filename_flag() {
        // Codex review of #96/#97: `grep -H needle a.txt` routes to
        // passthrough with `-H` preserved so rg emits the filename prefix.
        // `-H` reaching the output here is correct — it goes to rg, not clap.
        let out = run_cli_grep_pipeline(v(&["-H", "needle", "a.txt"]));
        assert!(!pipeline_has_clap_rejecting_flag(&out), "got {:?}", out);
        assert_eq!(out, v(&["-H", "needle", "a.txt"]));
    }

    #[test]
    #[allow(non_snake_case)] // -rnE names bundled grep flags (incl. -E)
    fn test_pipeline_rnE_bundle_clean() {
        let out = run_cli_grep_pipeline(v(&["-rnE", "needle", "."]));
        assert!(!pipeline_has_clap_rejecting_flag(&out), "got {:?}", out);
        assert!(!out.iter().any(|a| a == "-r"), "stale -r in {:?}", out);
        // -n reorders behind the positionals so clap parses it as extra_args.
        assert_eq!(out, v(&["needle", ".", "-n"]));
    }

    #[test]
    #[allow(non_snake_case)] // -HnE names bundled grep flags (incl. -H, -E)
    fn test_pipeline_HnE_bundle_routes_to_passthrough() {
        // -HnE: -E stripped, surviving -Hn bundle carries -H → passthrough.
        let out = run_cli_grep_pipeline(v(&["-HnE", "needle", "a.txt"]));
        assert!(!pipeline_has_clap_rejecting_flag(&out), "got {:?}", out);
        assert_eq!(out, v(&["-Hn", "needle", "a.txt"]));
    }

    #[test]
    fn test_pipeline_bare_l_routes_to_format_passthrough() {
        // `grep -l needle a.txt` → format-flag intercept fires (standard
        // grep --files-with-matches), routed to rg. `-l` survives because
        // run_grep_format_passthrough hands it to rg, which understands it.
        let out = run_cli_grep_pipeline(v(&["-l", "needle", "a.txt"]));
        assert_eq!(out, v(&["-l", "needle", "a.txt"]));
    }

    #[test]
    fn test_pipeline_dash_o_routes_to_format_passthrough() {
        // `-o` (only-matching) was already a format flag — verify it still
        // routes to passthrough rather than reaching clap.
        let out = run_cli_grep_pipeline(v(&["-o", "needle", "a.txt"]));
        assert_eq!(out, v(&["-o", "needle", "a.txt"]));
    }
}

#[cfg(test)]
mod meta_flag_tests {
    use super::{cmd_has_meta_flag, META_PASSTHROUGH_BINS};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_cmd_has_meta_flag_detects_version() {
        assert!(cmd_has_meta_flag(&args(&["--version"])));
    }

    #[test]
    fn test_cmd_has_meta_flag_short_v() {
        assert!(cmd_has_meta_flag(&args(&["-V"])));
    }

    #[test]
    fn test_cmd_has_meta_flag_help() {
        assert!(cmd_has_meta_flag(&args(&["--help"])));
        assert!(cmd_has_meta_flag(&args(&["-h"])));
    }

    #[test]
    fn test_cmd_has_meta_flag_ignores_subcmd() {
        assert!(!cmd_has_meta_flag(&args(&["build"])));
        assert!(!cmd_has_meta_flag(&args(&["test", "--release"])));
        assert!(!cmd_has_meta_flag(&args(&[])));
    }

    #[test]
    fn test_cmd_has_meta_flag_meta_anywhere() {
        // Meta flag mid-args still counts (e.g. `cargo build --version` is
        // unusual but harmless to intercept).
        assert!(cmd_has_meta_flag(&args(&["build", "--version"])));
    }

    /// Regression guard (Codex review of #90/#91): all wrappers that route
    /// to filters via clap subcommand structure but don't accept
    /// `--version`/`--help` at the top level MUST be in
    /// `META_PASSTHROUGH_BINS`. Otherwise meta-flag invocations fall through
    /// to `run_fallback` → raw exec and pollute `parse_failures`.
    ///
    /// If you add a new subcommand-only wrapper in this binary, add it to
    /// `META_PASSTHROUGH_BINS` AND extend the `expected` list below.
    #[test]
    fn test_meta_passthrough_covers_all_subcommand_only_wrappers() {
        let expected = [
            "cargo", "pnpm", "npm", "npx", "go", "docker", "kubectl", "gh", "glab", "aws", "psql",
            "prisma", "gt", "pytest", "ruff", "mypy", "rake", "rubocop", "rspec", "pip",
        ];
        for bin in expected {
            assert!(
                META_PASSTHROUGH_BINS.contains(&bin),
                "missing {} from META_PASSTHROUGH_BINS — meta-flag \
                 invocations of `contextcrawler {} --version` will pollute \
                 parse_failures",
                bin,
                bin
            );
        }
    }
}

fn run_cli() -> Result<i32> {
    // Fire-and-forget telemetry ping (1/day, non-blocking)
    core::telemetry::maybe_ping();

    // Pre-clap intercept: `grep` with documented format flags (-c, -L, -o, -Z and
    // the listed long forms) routes straight to passthrough. Clap rejects these
    // (e.g. -c is unknown) and recording a parse_failure for each one clutters
    // the tracking DB without informing the user of anything actionable. See #13.
    // Note: `-l` is ambiguous — this app's clap claims `-l` for `--max-len`
    // (a usize). `grep -l <numeric>` is left for clap as `--max-len`; bare
    // `grep -l <pattern>` and bundled `-l` are standard grep --files-with-
    // matches and get routed to rg, since clap would otherwise fail parsing
    // the pattern as a usize (#97).
    // `parsed_argv` mirrors `std::env::args()` but is swapped out below when
    // the grep pre-clap stripper removes recursive / no-op flags — so clap
    // re-parses the cleaned form rather than the raw one it would have
    // rejected (#88, #97).
    let mut parsed_argv: Vec<String> = std::env::args().collect();
    {
        let raw_args: Vec<String> = std::env::args().skip(1).collect();
        if raw_args.first().map(|s| s.as_str()) == Some("grep") {
            // Codex review fix: ALWAYS strip recursive flags first. Otherwise
            // mixed invocations like `grep -c -r pat .` short-circuit on the
            // format-flag check and reach rg with -r intact, where rg reads
            // it as --replace (replacement string), not recursive — silent
            // wrong behaviour. Strip first, then route.
            let preprocessed = preprocess_grep_args(raw_args[1..].to_vec());
            let working_args: &[String] = match &preprocessed {
                GrepPreprocess::Stripped(a)
                | GrepPreprocess::Passthrough(a)
                | GrepPreprocess::Quiet(a) => a.as_slice(),
            };

            // Format-flag intercept runs on the stripped args so -r/-R/
            // --recursive cannot leak through to rg. `grep_format_flag_present`
            // scans every token position-independently, so it still fires
            // after the Pass-4 reorder.
            if grep_format_flag_present(working_args) {
                let mut full = Vec::with_capacity(working_args.len() + 1);
                full.push("grep".to_string());
                full.extend_from_slice(working_args);
                return run_grep_format_passthrough(&full);
            }

            match preprocessed {
                GrepPreprocess::Quiet(stripped) => {
                    // `-q`/`--quiet`: no stdout, exit code only. rg honours
                    // `-q` natively; route the call straight to rg so the
                    // filter never tries to model empty output and never
                    // logs a parse failure (P0: `-q` is the single biggest
                    // source of grep parse failures).
                    let mut full = Vec::with_capacity(stripped.len() + 1);
                    full.push("grep".to_string());
                    full.extend(stripped);
                    return run_grep_passthrough_labelled(&full, "quiet passthrough");
                }
                GrepPreprocess::Passthrough(stripped) => {
                    let mut full = Vec::with_capacity(stripped.len() + 1);
                    full.push("grep".to_string());
                    full.extend(stripped);
                    // Issue #193: context-flag calls (`-A`/`-B`/`-C`) are the
                    // single highest-yield grep shape (861 of 1629 fallbacks).
                    // rg understands them natively and emits grouped output we
                    // CAN filter — capture it and cap per-file/global instead
                    // of inheriting raw (zero savings). `-H`/value-flag calls
                    // (no context flag) stay on the raw passthrough: their
                    // output is single-line and reordering value flags is
                    // unsafe, so there's nothing to group/cap.
                    if has_grep_context_flag(&full) {
                        return run_grep_context_filtered(&full);
                    }
                    return run_grep_format_passthrough(&full);
                }
                GrepPreprocess::Stripped(stripped) => {
                    // Rebuild argv: argv0, "grep", stripped... so clap parses
                    // the cleaned form.
                    let argv0 = std::env::args().next().unwrap_or_default();
                    let mut full = Vec::with_capacity(stripped.len() + 2);
                    full.push(argv0);
                    full.push("grep".to_string());
                    full.extend(stripped);
                    parsed_argv = full;
                }
            }
        }

        // Pre-clap intercept: meta flags (--version, -V, --help, -h) on
        // wrapper subcommands. Without this, `contextcrawler cargo --version`
        // falls through clap → run_fallback → raw exec, writing a
        // parse_failure row per call. Issue #90.
        if let Some(bin) = raw_args.first().map(|s| s.as_str()) {
            // SECURITY (#100 G2 IMPORTANT 3): basename-normalise the bin
            // token before the membership check. `contextcrawler
            // /usr/bin/npm --version` must still hit the hardened
            // `run_simple_passthrough` path — matching on the raw token
            // would miss it and fall through to `run_fallback` without the
            // per-tool env hardening. Same basename logic the fallback
            // hardening path uses (`cloud_fallback_hardening`).
            let bin_base = bin_basename(bin);
            if META_PASSTHROUGH_BINS.contains(&bin_base) && cmd_has_meta_flag(&raw_args[1..]) {
                // SECURITY (#100 G2 Codex 2nd pass — CRITICAL 2): refuse a
                // path-bearing token. `bin_basename` would let
                // `contextcrawler ../../evil/npm --version` pass the
                // membership check; `run_simple_passthrough` would then spawn
                // a binary other than the one the basename matched. A
                // meta-flag passthrough target must be a bare tool name
                // resolved via PATH.
                if token_has_path_separator(bin) {
                    anyhow::bail!(
                        "contextcrawler: refusing to passthrough a path-bearing \
                         command token `{bin}` — pass a bare tool name resolved \
                         via PATH"
                    );
                }
                return run_simple_passthrough(bin_base, &raw_args[1..]);
            }
        }
    }

    let cli = match Cli::try_parse_from(&parsed_argv) {
        Ok(cli) => cli,
        Err(e) => {
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                e.exit();
            }
            return run_fallback(e);
        }
    };

    // Warn if installed hook is outdated/missing (1/day, non-blocking).
    // Skip for Gain — it shows its own inline hook warning.
    if !matches!(cli.command, Commands::Gain { .. }) {
        hooks::hook_check::maybe_warn();
    }

    // Runtime integrity check for operational commands.
    // Meta commands (init, gain, verify, config, etc.) skip the check
    // because they don't go through the hook pipeline.
    if is_operational_command(&cli.command) {
        hooks::integrity::runtime_check()?;
    }

    let code = match cli.command {
        Commands::Ls { args } => ls::run(&args, cli.verbose)?,

        Commands::Tree { args } => tree::run(&args, cli.verbose)?,

        // ISSUE #989: support multiple files (cat file1 file2 → contextcrawler read file1 file2)
        Commands::Read {
            files,
            level,
            max_lines,
            tail_lines,
            line_numbers,
            intent,
        } => {
            let mut had_error = false;
            let mut stdin_seen = false;
            let intent_ref = intent.as_deref();
            for file in &files {
                let result = if file == Path::new("-") {
                    if stdin_seen {
                        eprintln!("contextcrawler: warning: stdin specified more than once");
                        continue;
                    }
                    stdin_seen = true;
                    read::run_stdin(
                        level,
                        max_lines,
                        tail_lines,
                        line_numbers,
                        intent_ref,
                        cli.verbose,
                    )
                } else {
                    read::run(
                        file,
                        level,
                        max_lines,
                        tail_lines,
                        line_numbers,
                        intent_ref,
                        cli.verbose,
                    )
                };
                if let Err(e) = result {
                    eprintln!("cat: {}: {}", file.display(), e.root_cause());
                    had_error = true;
                }
            }
            if had_error {
                1
            } else {
                0
            }
        }

        Commands::Smart {
            file,
            model,
            force_download,
        } => {
            local_llm::run(&file, &model, force_download, cli.verbose)?;
            0
        }

        Commands::Git {
            directory,
            config_override,
            git_dir,
            work_tree,
            no_pager,
            no_optional_locks,
            bare,
            literal_pathspecs,
            command,
        } => {
            // Build global git args (inserted between "git" and subcommand)
            let mut global_args: Vec<String> = Vec::new();
            for dir in &directory {
                global_args.push("-C".to_string());
                global_args.push(dir.clone());
            }
            // Validate `-c key=val` overrides BEFORE pushing them into
            // global_args — `core::utils::check_forbidden_git_args` rejects
            // `-c diff.external=…`, `-c core.sshCommand=…`, `-c protocol.*`,
            // etc., which would otherwise let an attacker drive git into
            // exec'ing an arbitrary program during ordinary subcommands.
            // See issue #35 for the empirical PoCs. Synthesize the `-c <entry>`
            // pair the validator expects.
            for cfg in &config_override {
                let synth = ["-c".to_string(), cfg.clone()];
                if let Err(msg) = core::utils::check_forbidden_git_args(&synth) {
                    eprintln!("{}", msg);
                    return Ok(2);
                }
                global_args.push("-c".to_string());
                global_args.push(cfg.clone());
            }
            if let Some(ref dir) = git_dir {
                global_args.push("--git-dir".to_string());
                global_args.push(dir.clone());
            }
            if let Some(ref tree) = work_tree {
                global_args.push("--work-tree".to_string());
                global_args.push(tree.clone());
            }
            if no_pager {
                global_args.push("--no-pager".to_string());
            }
            if no_optional_locks {
                global_args.push("--no-optional-locks".to_string());
            }
            if bare {
                global_args.push("--bare".to_string());
            }
            if literal_pathspecs {
                global_args.push("--literal-pathspecs".to_string());
            }

            match command {
                GitCommands::Diff { args } => git::run(
                    git::GitCommand::Diff,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Log { args } => {
                    git::run(git::GitCommand::Log, &args, None, cli.verbose, &global_args)?
                }
                GitCommands::Status { args } => git::run(
                    git::GitCommand::Status,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Show { args } => git::run(
                    git::GitCommand::Show,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Add { args } => {
                    git::run(git::GitCommand::Add, &args, None, cli.verbose, &global_args)?
                }
                GitCommands::Commit { args } => git::run(
                    git::GitCommand::Commit,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Push { args } => git::run(
                    git::GitCommand::Push,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Pull { args } => git::run(
                    git::GitCommand::Pull,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Branch { args } => git::run(
                    git::GitCommand::Branch,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Fetch { args } => git::run(
                    git::GitCommand::Fetch,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Stash { subcommand, args } => git::run(
                    git::GitCommand::Stash { subcommand },
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Worktree { args } => git::run(
                    git::GitCommand::Worktree,
                    &args,
                    None,
                    cli.verbose,
                    &global_args,
                )?,
                GitCommands::Other(args) => git::run_passthrough(&args, &global_args, cli.verbose)?,
            }
        }

        Commands::Gh { subcommand, args } => {
            gh_cmd::run(&subcommand, &args, cli.verbose, cli.ultra_compact)?
        }

        Commands::Glab {
            repo,
            group,
            subcommand,
            mut args,
        } => {
            // Append -R / -g flags at end so they don't interfere with
            // subcommand dispatch (args[0] must be the sub-subcommand like "list")
            if let Some(r) = repo {
                args.push("-R".to_string());
                args.push(r);
            }
            if let Some(g) = group {
                args.push("-g".to_string());
                args.push(g);
            }
            glab_cmd::run(&subcommand, &args, cli.verbose, cli.ultra_compact)?
        }

        Commands::Aws { subcommand, args } => aws_cmd::run(&subcommand, &args, cli.verbose)?,

        Commands::Psql { args } => psql_cmd::run(&args, cli.verbose)?,

        Commands::Pnpm { filter, command } => {
            // Warns user if filters are used with unsupported subcommands like typecheck
            if let Some(warning) = validate_pnpm_filters(&filter, &command) {
                eprintln!("{}", warning);
            }

            match command {
                PnpmCommands::List { depth, args } => pnpm_cmd::run(
                    pnpm_cmd::PnpmCommand::List { depth },
                    &merge_pnpm_args(&filter, &args),
                    cli.verbose,
                )?,
                PnpmCommands::Outdated { args } => pnpm_cmd::run(
                    pnpm_cmd::PnpmCommand::Outdated,
                    &merge_pnpm_args(&filter, &args),
                    cli.verbose,
                )?,
                PnpmCommands::Install { args } => pnpm_cmd::run(
                    pnpm_cmd::PnpmCommand::Install {
                        subcommand: "install".to_string(),
                    },
                    &merge_pnpm_args(&filter, &args),
                    cli.verbose,
                )?,
                PnpmCommands::Typecheck { args } => tsc_cmd::run(&args, cli.verbose)?,
                PnpmCommands::Other(args) => {
                    // #100 G5#7 follow-up: pnpm's install-class aliases
                    // (`i`, `add`, `up`, `dedupe`, `rebuild`/`rb`, `prune`,
                    // `import`) land here as an external subcommand. The raw
                    // passthrough path does NOT surface postinstall / audit /
                    // deprecation warnings, so route those aliases through the
                    // same `filter_pnpm_install` treatment `pnpm install` gets.
                    let first = args.first().and_then(|s| s.to_str()).map(str::to_string);
                    match first {
                        Some(sub) if pnpm_cmd::is_install_subcommand(&sub) => {
                            // Drop the leading subcommand; the rest are args.
                            let rest: Vec<String> = args
                                .iter()
                                .skip(1)
                                .map(|s| s.to_string_lossy().into_owned())
                                .collect();
                            pnpm_cmd::run(
                                pnpm_cmd::PnpmCommand::Install { subcommand: sub },
                                &merge_pnpm_args(&filter, &rest),
                                cli.verbose,
                            )?
                        }
                        _ => pnpm_cmd::run_passthrough(
                            &merge_pnpm_args_os(&filter, &args),
                            cli.verbose,
                        )?,
                    }
                }
            }
        }

        Commands::Err { command, shell } => {
            let cmd = command.join(" ");
            runner::run_err(&cmd, shell, cli.verbose)?
        }

        Commands::Test { command, shell } => {
            let cmd = command.join(" ");
            runner::run_test(&cmd, shell, cli.verbose)?
        }

        Commands::Json {
            file,
            depth,
            keys_only,
        } => {
            if file == Path::new("-") {
                json_cmd::run_stdin(depth, keys_only, cli.verbose)?;
            } else {
                json_cmd::run(&file, depth, keys_only, cli.verbose)?;
            }
            0
        }

        Commands::Deps { path } => {
            deps::run(&path, cli.verbose)?;
            0
        }

        Commands::Env { filter, show_all } => {
            env_cmd::run(filter.as_deref(), show_all, cli.verbose)?;
            0
        }

        Commands::Find { args } => {
            find_cmd::run_from_args(&args, cli.verbose)?;
            0
        }

        Commands::Diff { file1, file2 } => {
            if let Some(f2) = file2 {
                diff_cmd::run(&file1, &f2, cli.verbose)?;
            } else {
                diff_cmd::run_stdin(cli.verbose)?;
            }
            0
        }

        Commands::Log { file } => {
            if let Some(f) = file {
                log_cmd::run_file(&f, cli.verbose)?;
            } else {
                log_cmd::run_stdin(cli.verbose)?;
            }
            0
        }

        Commands::Dotnet { command } => match command {
            DotnetCommands::Build { args } => dotnet_cmd::run_build(&args, cli.verbose)?,
            DotnetCommands::Test { args } => dotnet_cmd::run_test(&args, cli.verbose)?,
            DotnetCommands::Restore { args } => dotnet_cmd::run_restore(&args, cli.verbose)?,
            DotnetCommands::Format { args } => dotnet_cmd::run_format(&args, cli.verbose)?,
            DotnetCommands::Other(args) => dotnet_cmd::run_passthrough(&args, cli.verbose)?,
        },

        Commands::Docker { command } => match command {
            DockerCommands::Ps => {
                container::run(container::ContainerCmd::DockerPs, &[], cli.verbose)?
            }
            DockerCommands::Images => {
                container::run(container::ContainerCmd::DockerImages, &[], cli.verbose)?
            }
            DockerCommands::Logs { container: c } => {
                container::run(container::ContainerCmd::DockerLogs, &[c], cli.verbose)?
            }
            DockerCommands::Compose { command: compose } => match compose {
                ComposeCommands::Ps => container::run_compose_ps(cli.verbose)?,
                ComposeCommands::Logs { service, tail } => {
                    container::run_compose_logs(service.as_deref(), tail, cli.verbose)?
                }
                ComposeCommands::Build { service } => {
                    container::run_compose_build(service.as_deref(), cli.verbose)?
                }
                ComposeCommands::Other(args) => {
                    container::run_compose_passthrough(&args, cli.verbose)?
                }
            },
            DockerCommands::Other(args) => container::run_docker_passthrough(&args, cli.verbose)?,
        },

        Commands::Kubectl { command } => match command {
            KubectlCommands::Get { args } => container::run_kubectl_get(&args, cli.verbose)?,
            KubectlCommands::Pods { namespace, all } => {
                let mut args: Vec<String> = Vec::new();
                if all {
                    args.push("-A".to_string());
                } else if let Some(n) = namespace {
                    args.push("-n".to_string());
                    args.push(n);
                }
                container::run(container::ContainerCmd::KubectlPods, &args, cli.verbose)?
            }
            KubectlCommands::Services { namespace, all } => {
                let mut args: Vec<String> = Vec::new();
                if all {
                    args.push("-A".to_string());
                } else if let Some(n) = namespace {
                    args.push("-n".to_string());
                    args.push(n);
                }
                container::run(container::ContainerCmd::KubectlServices, &args, cli.verbose)?
            }
            KubectlCommands::Logs { pod, container: c } => {
                let mut args = vec![pod];
                if let Some(cont) = c {
                    args.push("-c".to_string());
                    args.push(cont);
                }
                container::run(container::ContainerCmd::KubectlLogs, &args, cli.verbose)?
            }
            KubectlCommands::Other(args) => container::run_kubectl_passthrough(&args, cli.verbose)?,
        },

        Commands::Summary { command, shell } => {
            let cmd = command.join(" ");
            summary::run(&cmd, shell, cli.verbose)?
        }

        Commands::Grep {
            pattern,
            path,
            max_len,
            max,
            context_only,
            file_type,
            line_numbers: _, // no-op: line numbers always enabled in grep_cmd::run
            extra_args,
        } => grep_cmd::run(
            &pattern,
            &path,
            max_len,
            max,
            context_only,
            file_type.as_deref(),
            &extra_args,
            cli.verbose,
        )?,

        // Issue #165A: `rg` is no longer a 0% fallback. Parse rg-native
        // syntax (incl. `--files`, `-l`, `-A 3`) and route to grep_cmd.
        Commands::Rg { args } => rg_cmd::run_from_args(&args, cli.verbose)?,

        Commands::Init {
            global,
            opencode,
            gemini,
            agent,
            show,
            claude_md,
            hook_only,
            auto_patch,
            no_patch,
            uninstall,
            codex,
            copilot,
            dry_run,
        } => {
            let ctx = hooks::init::InitContext {
                verbose: cli.verbose,
                dry_run,
            };
            if show {
                hooks::init::show_config(codex)?;
            } else if uninstall {
                uninstall_init_dispatch(
                    agent,
                    global,
                    gemini,
                    codex,
                    ctx,
                    hooks::init::uninstall_hermes,
                    hooks::init::uninstall_pidev,
                    hooks::init::uninstall,
                )?;
            } else if gemini {
                let patch_mode = if auto_patch {
                    hooks::init::PatchMode::Auto
                } else if no_patch {
                    hooks::init::PatchMode::Skip
                } else {
                    hooks::init::PatchMode::Ask
                };
                hooks::init::run_gemini(global, hook_only, patch_mode, ctx)?;
            } else if copilot {
                hooks::init::run_copilot(ctx)?;
            } else if agent == Some(AgentTarget::Kilocode) {
                if global {
                    anyhow::bail!("Kilo Code is project-scoped. Use: contextcrawler init --agent kilocode");
                }
                hooks::init::run_kilocode_mode(ctx)?;
            } else if agent == Some(AgentTarget::Antigravity) {
                if global {
                    anyhow::bail!(
                        "Antigravity is project-scoped. Use: contextcrawler init --agent antigravity"
                    );
                }
                hooks::init::run_antigravity_mode(ctx)?;
            } else if agent == Some(AgentTarget::Hermes) {
                hooks::init::run_hermes_mode(ctx)?;
            } else if agent == Some(AgentTarget::Pidev) {
                hooks::init::run_pidev_mode(ctx)?;
            } else {
                let install_opencode = opencode;
                let install_claude = !opencode;
                let install_cursor = agent == Some(AgentTarget::Cursor);
                let install_windsurf = agent == Some(AgentTarget::Windsurf);
                let install_cline = agent == Some(AgentTarget::Cline);

                let patch_mode = if auto_patch {
                    hooks::init::PatchMode::Auto
                } else if no_patch {
                    hooks::init::PatchMode::Skip
                } else {
                    hooks::init::PatchMode::Ask
                };
                hooks::init::run(
                    global,
                    install_claude,
                    install_opencode,
                    install_cursor,
                    install_windsurf,
                    install_cline,
                    claude_md,
                    hook_only,
                    codex,
                    patch_mode,
                    ctx,
                )?;
            }
            0
        }

        Commands::Wget { url, output, args } => {
            if output.as_deref() == Some("-") {
                wget_cmd::run_stdout(&url, &args, cli.verbose)?
            } else {
                // Pass -O <file> through to wget via args
                let mut all_args = Vec::new();
                if let Some(out_file) = &output {
                    all_args.push("-O".to_string());
                    all_args.push(out_file.clone());
                }
                all_args.extend(args);
                wget_cmd::run(&url, &all_args, cli.verbose)?
            }
        }

        Commands::Wc { args } => wc_cmd::run(&args, cli.verbose)?,

        Commands::Gain {
            project, // added
            graph,
            history,
            quota,
            tier,
            daily,
            weekly,
            monthly,
            all,
            format,
            failures,
            weak_filters,
            all_time,
            reset,
            yes,
        } => {
            analytics::gain::run(
                project, // added: pass project flag
                graph,
                history,
                quota,
                &tier,
                daily,
                weekly,
                monthly,
                all,
                &format,
                failures,
                weak_filters,
                reset,
                yes,
                cli.verbose,
                all_time,
            )?;
            0
        }

        Commands::CcEconomics {
            daily,
            weekly,
            monthly,
            all,
            format,
        } => {
            analytics::cc_economics::run(daily, weekly, monthly, all, &format, cli.verbose)?;
            0
        }

        Commands::Config { create } => {
            if create {
                let path = core::config::Config::create_default()?;
                println!("Created: {}", path.display());
            } else {
                core::config::show_config()?;
            }
            0
        }

        Commands::Jest { ref args } | Commands::Vitest { ref args } => {
            vitest_cmd::run_test(&cli.command, args, cli.verbose)?
        }

        Commands::Prisma { command } => match command {
            PrismaCommands::Generate { args } => {
                prisma_cmd::run(prisma_cmd::PrismaCommand::Generate, &args, cli.verbose)?
            }
            PrismaCommands::Migrate { command } => match command {
                PrismaMigrateCommands::Dev { name, args } => prisma_cmd::run(
                    prisma_cmd::PrismaCommand::Migrate {
                        subcommand: prisma_cmd::MigrateSubcommand::Dev { name },
                    },
                    &args,
                    cli.verbose,
                )?,
                PrismaMigrateCommands::Status { args } => prisma_cmd::run(
                    prisma_cmd::PrismaCommand::Migrate {
                        subcommand: prisma_cmd::MigrateSubcommand::Status,
                    },
                    &args,
                    cli.verbose,
                )?,
                PrismaMigrateCommands::Deploy { args } => prisma_cmd::run(
                    prisma_cmd::PrismaCommand::Migrate {
                        subcommand: prisma_cmd::MigrateSubcommand::Deploy,
                    },
                    &args,
                    cli.verbose,
                )?,
            },
            PrismaCommands::DbPush { args } => {
                prisma_cmd::run(prisma_cmd::PrismaCommand::DbPush, &args, cli.verbose)?
            }
        },

        Commands::Tsc { args } => tsc_cmd::run(&args, cli.verbose)?,

        Commands::Next { args } => next_cmd::run(&args, cli.verbose)?,

        Commands::Lint { args } => lint_cmd::run(&args, cli.verbose)?,

        Commands::Prettier { args } => prettier_cmd::run(&args, cli.verbose)?,

        Commands::Format { args } => format_cmd::run(&args, cli.verbose)?,

        Commands::Playwright { args } => playwright_cmd::run(&args, cli.verbose)?,

        Commands::Cargo { command } => match command {
            CargoCommands::Build { args } => {
                cargo_cmd::run(cargo_cmd::CargoCommand::Build, &args, cli.verbose)?
            }
            CargoCommands::Test { args } => {
                cargo_cmd::run(cargo_cmd::CargoCommand::Test, &args, cli.verbose)?
            }
            CargoCommands::Clippy { args } => {
                cargo_cmd::run(cargo_cmd::CargoCommand::Clippy, &args, cli.verbose)?
            }
            CargoCommands::Check { args } => {
                cargo_cmd::run(cargo_cmd::CargoCommand::Check, &args, cli.verbose)?
            }
            CargoCommands::Install { args } => {
                cargo_cmd::run(cargo_cmd::CargoCommand::Install, &args, cli.verbose)?
            }
            CargoCommands::Nextest { args } => {
                cargo_cmd::run(cargo_cmd::CargoCommand::Nextest, &args, cli.verbose)?
            }
            CargoCommands::Other(args) => cargo_cmd::run_passthrough(&args, cli.verbose)?,
        },

        Commands::Npm { args } => npm_cmd::run(&args, cli.verbose, cli.skip_env)?,

        Commands::Curl { args } => curl_cmd::run(&args, cli.verbose)?,

        Commands::Discover {
            project,
            limit,
            all,
            since,
            format,
            codex,
        } => {
            if codex {
                discover::run_codex(since, &format)?;
            } else {
                discover::run(project.as_deref(), all, since, limit, &format, cli.verbose)?;
            }
            0
        }

        Commands::Session {} => {
            analytics::session_cmd::run(cli.verbose)?;
            0
        }

        Commands::Telemetry { command } => {
            core::telemetry_cmd::run(&command)?;
            0
        }

        Commands::Learn {
            project,
            all,
            since,
            format,
            write_rules,
            min_confidence,
            min_occurrences,
        } => {
            learn::run(
                project,
                all,
                since,
                format,
                write_rules,
                min_confidence,
                min_occurrences,
            )?;
            0
        }

        Commands::Npx { args } => {
            if args.is_empty() {
                anyhow::bail!("npx requires a command argument");
            }

            // Intelligent routing: delegate to specialized filters
            match args[0].as_str() {
                "tsc" | "typescript" => tsc_cmd::run(&args[1..], cli.verbose)?,
                "eslint" => lint_cmd::run(&args[1..], cli.verbose)?,
                "prisma" => {
                    // Route to prisma_cmd based on subcommand
                    if args.len() > 1 {
                        let prisma_args: Vec<String> = args[2..].to_vec();
                        match args[1].as_str() {
                            "generate" => prisma_cmd::run(
                                prisma_cmd::PrismaCommand::Generate,
                                &prisma_args,
                                cli.verbose,
                            )?,
                            "db" if args.len() > 2 && args[2] == "push" => prisma_cmd::run(
                                prisma_cmd::PrismaCommand::DbPush,
                                &args[3..],
                                cli.verbose,
                            )?,
                            _ => {
                                // Passthrough other prisma subcommands
                                let timer = core::tracking::TimedExecution::start();
                                let mut cmd = core::utils::resolved_command("npx");
                                for arg in &args {
                                    cmd.arg(arg);
                                }
                                let status = cmd.status().context("Failed to run npx prisma")?;
                                let args_str = args.join(" ");
                                timer.track_passthrough(
                                    &format!("npx {}", args_str),
                                    &format!("contextcrawler npx {} (passthrough)", args_str),
                                );
                                core::utils::exit_code_from_status(&status, "npx prisma")
                            }
                        }
                    } else {
                        let timer = core::tracking::TimedExecution::start();
                        let status = core::utils::resolved_command("npx")
                            .arg("prisma")
                            .status()
                            .context("Failed to run npx prisma")?;
                        timer.track_passthrough("npx prisma", "rtk npx prisma (passthrough)");
                        core::utils::exit_code_from_status(&status, "npx prisma")
                    }
                }
                "next" => next_cmd::run(&args[1..], cli.verbose)?,
                "prettier" => prettier_cmd::run(&args[1..], cli.verbose)?,
                "playwright" => playwright_cmd::run(&args[1..], cli.verbose)?,
                // ServiceNow Fluent SDK: capture output and route through the
                // `servicenow-sdk-build` TOML filter. npm_cmd::exec barely
                // touches this output (~0.5% savings) because it's not npm —
                // it's a verbose, ANSI-heavy SDK build log.
                "@servicenow/sdk" => {
                    let timer = core::tracking::TimedExecution::start();
                    let output = core::utils::resolved_command("npx")
                        .args(&args)
                        .stdin(std::process::Stdio::inherit())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output()
                        .context("Failed to run npx @servicenow/sdk")?;
                    // SDK emits [now-sdk] lines to stdout; merge stderr in case
                    // a future version splits diagnostics across both streams.
                    let raw = format!(
                        "{}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    );
                    let lookup = format!("npx {}", args.join(" "));
                    let filtered = match core::toml_filter::find_matching_filter(&lookup) {
                        Some(f) => core::toml_filter::apply_filter(f, &raw),
                        None => raw.clone(),
                    };
                    print!("{}", filtered);
                    if !filtered.ends_with('\n') {
                        println!();
                    }
                    timer.track(
                        &lookup,
                        &format!("contextcrawler npx {}", args.join(" ")),
                        &raw,
                        &filtered,
                    );
                    core::utils::exit_code_from_output(&output, &lookup)
                }
                _ => npm_cmd::exec(&args, cli.verbose, cli.skip_env)?,
            }
        }

        Commands::Ruff { args } => ruff_cmd::run(&args, cli.verbose)?,

        Commands::Pytest { args } => pytest_cmd::run(&args, cli.verbose)?,

        Commands::Mypy { args } => mypy_cmd::run(&args, cli.verbose)?,

        Commands::Rake { args } => rake_cmd::run(&args, cli.verbose)?,

        Commands::Rubocop { args } => rubocop_cmd::run(&args, cli.verbose)?,

        Commands::Rspec { args } => rspec_cmd::run(&args, cli.verbose)?,

        Commands::Pip { args } => pip_cmd::run(&args, cli.verbose)?,

        Commands::Go { command } => match command {
            GoCommands::Test { args } => go_cmd::run_test(&args, cli.verbose)?,
            GoCommands::Build { args } => go_cmd::run_build(&args, cli.verbose)?,
            GoCommands::Vet { args } => go_cmd::run_vet(&args, cli.verbose)?,
            GoCommands::Other(args) => go_cmd::run_other(&args, cli.verbose)?,
        },

        Commands::Gt { command } => match command {
            GtCommands::Log { args } => gt_cmd::run_log(&args, cli.verbose)?,
            GtCommands::Submit { args } => gt_cmd::run_submit(&args, cli.verbose)?,
            GtCommands::Sync { args } => gt_cmd::run_sync(&args, cli.verbose)?,
            GtCommands::Restack { args } => gt_cmd::run_restack(&args, cli.verbose)?,
            GtCommands::Create { args } => gt_cmd::run_create(&args, cli.verbose)?,
            GtCommands::Branch { args } => gt_cmd::run_branch(&args, cli.verbose)?,
            GtCommands::Other(args) => gt_cmd::run_other(&args, cli.verbose)?,
        },

        Commands::GolangciLint { args } => golangci_cmd::run(&args, cli.verbose)?,

        Commands::Gradlew { args } => gradlew_cmd::run(&args, cli.verbose)?,

        Commands::HookAudit { since } => {
            hooks::hook_audit_cmd::run(since, cli.verbose)?;
            0
        }

        Commands::Hook { command } => match command {
            HookCommands::Claude => {
                hooks::hook_cmd::run_claude()?;
                0
            }
            HookCommands::Cursor => {
                hooks::hook_cmd::run_cursor()?;
                0
            }
            HookCommands::Gemini => {
                hooks::hook_cmd::run_gemini()?;
                0
            }
            HookCommands::Copilot => {
                hooks::hook_cmd::run_copilot()?;
                0
            }
            HookCommands::Check { agent: _, command } => {
                use crate::discover::registry::rewrite_command;
                let raw = command.join(" ");
                let (excluded, transparent_prefixes) = crate::core::config::Config::load()
                    .map(|c| (c.hooks.exclude_commands, c.hooks.transparent_prefixes))
                    .unwrap_or_default();
                match rewrite_command(&raw, &excluded, &transparent_prefixes) {
                    Some(rewritten) => {
                        println!("{}", rewritten);
                        0
                    }
                    None => {
                        eprintln!("No rewrite for: {}", raw);
                        1
                    }
                }
            }
        },

        Commands::Rewrite { args } => {
            let cmd = args.join(" ");
            hooks::rewrite_cmd::run(&cmd)?;
            0
        }

        Commands::Pipe {
            filter,
            passthrough,
        } => {
            pipe_cmd::run(filter.as_deref(), passthrough)?;
            0
        }

        Commands::Run { command, args } => {
            let raw = match command {
                Some(c) => c,
                None if !args.is_empty() => args.join(" "),
                None => String::new(),
            };
            if raw.trim().is_empty() {
                0
            } else {
                use std::process::Command as ProcCommand;
                let shell = if cfg!(windows) { "cmd" } else { "sh" };
                let flag = if cfg!(windows) { "/C" } else { "-c" };
                let status = ProcCommand::new(shell)
                    .arg(flag)
                    .arg(&raw)
                    .status()
                    .with_context(|| format!("Failed to execute: {}", raw))?;
                status.code().unwrap_or(1)
            }
        }

        Commands::Proxy { shell, args } => {
            use std::ffi::OsString;
            use std::io::{Read, Write};
            use std::process::Stdio;
            use std::sync::atomic::{AtomicU32, Ordering};
            use std::thread;

            if args.is_empty() {
                anyhow::bail!(
                    "proxy requires a command to execute\n\
                     Usage: contextcrawler proxy <command> [args...]"
                );
            }

            let timer = core::tracking::TimedExecution::start();

            // SECURITY (#100 G2 CRITICAL 2): keep argv as OsString end-to-end.
            // The default path passes argv verbatim — argv[0] is the binary,
            // argv[1..] its arguments — so a binary path containing
            // whitespace can never be word-split into the wrong program.
            //
            // `--via-shell` is the explicit opt-in for callers that genuinely
            // need shell word-splitting of a single quoted argument
            // (formerly #388). It is gated, never a heuristic on a
            // positional arg.
            let (cmd_name, cmd_args): (OsString, Vec<OsString>) = if shell {
                if args.len() != 1 {
                    anyhow::bail!(
                        "proxy --via-shell expects exactly one quoted command-line argument"
                    );
                }
                let full = args[0].to_string_lossy();
                let parts = shell_split(&full);
                match parts.split_first() {
                    Some((first, rest)) => (
                        OsString::from(first),
                        rest.iter().map(OsString::from).collect(),
                    ),
                    None => anyhow::bail!("proxy --via-shell: empty command line"),
                }
            } else {
                (args[0].clone(), args[1..].to_vec())
            };

            // SECURITY (#100 G2 Codex 2nd pass — CRITICAL 2): refuse a
            // path-bearing `argv[0]`. The spawn below would otherwise exec
            // the RAW token, while any basename-normalised hardening/nudge
            // was computed for the bare tool name — i.e. hardening applied
            // cosmetically to the wrong binary
            // (`proxy ../../evil/npm ...`). Proxied commands must be bare
            // tool names resolved via PATH.
            if token_has_path_separator(&cmd_name.to_string_lossy()) {
                anyhow::bail!(
                    "contextcrawler: refusing to proxy a path-bearing command \
                     token `{}` — pass a bare tool name resolved via PATH",
                    cmd_name.to_string_lossy()
                );
            }

            // Lossy String forms — used ONLY for display, the nudge and
            // usage tracking, never for spawning the process.
            let cmd_name_display = cmd_name.to_string_lossy().into_owned();
            let cmd_args_display: Vec<String> = cmd_args
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();

            if cli.verbose > 0 {
                eprintln!(
                    "Proxy mode: {} {}",
                    cmd_name_display,
                    cmd_args_display.join(" ")
                );
            }

            // SECURITY (council P0-2 / task #2): the proxy path must pass the
            // same defence-in-depth gates (Tirith + supply-chain) as the hook
            // path. Without this, `contextcrawler proxy <cmd>` was a complete
            // gate bypass — a hook-rewritten command got gated while the
            // documented "raw" escape hatch did not. Both gates are opt-in,
            // so with Tirith absent and supply-chain disabled this is a no-op
            // and proxy behaviour is unchanged.
            {
                let gate_cmd = if cmd_args_display.is_empty() {
                    cmd_name_display.clone()
                } else {
                    format!("{} {}", cmd_name_display, cmd_args_display.join(" "))
                };
                let decision = hooks::hook_cmd::run_gates(&gate_cmd);
                let ack = std::env::var("CONTEXTCRAWLER_PROXY_ACK").as_deref() == Ok("1");
                match hooks::hook_cmd::proxy_gate_outcome(decision, ack) {
                    hooks::hook_cmd::ProxyGateOutcome::Run => {}
                    hooks::hook_cmd::ProxyGateOutcome::Refuse { reason, exit_code } => {
                        eprintln!("{}", reason);
                        timer.track(
                            &format!("proxy {} (gate refused)", cmd_name_display),
                            &format!("contextcrawler proxy {}", cmd_name_display),
                            "",
                            "",
                        );
                        std::process::exit(exit_code);
                    }
                }
            }

            // Nudge: if the proxied tool has a wrapped equivalent, point the
            // caller at it. The wrap exists for a reason (token-savings filter
            // + env-strip + arg deny-list), and `proxy <wrapped-tool>` is
            // currently the #1 token leak in the dashboard. Don't auto-rewrite
            // — measure adoption of the nudge first.
            //
            // Suppression order (any one silences the nudge):
            //   1. `CONTEXTCRAWLER_NO_PROXY_NUDGE=<anything>` — explicit opt-out
            //   2. `CI=<anything>` — common CI marker (GitHub Actions, GitLab,
            //      CircleCI, Travis all set this) so pipeline stderr stays clean
            //   3. stderr not a tty — script/pipe consumer can't act on the nudge
            if should_emit_proxy_nudge() {
                let basename = std::path::Path::new(&cmd_name_display)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&cmd_name_display);
                if let Some(suggestion) = proxy_wrapped_equivalent(basename) {
                    eprintln!(
                        "[contextcrawler] note: `proxy {basename}` bypasses the wrapped filter. \
                         Consider: `{suggestion}`. \
                         Set CONTEXTCRAWLER_NO_PROXY_NUDGE=1 to suppress."
                    );
                }
            }

            // ISSUE #897: Kill proxy child on SIGINT/SIGTERM to prevent orphan
            // processes. Drop-based ChildGuard doesn't run on signals with
            // panic=abort, so we register a signal handler that kills the child
            // PID stored in this atomic.
            static PROXY_CHILD_PID: AtomicU32 = AtomicU32::new(0);

            #[cfg(unix)]
            #[allow(unsafe_code)]
            {
                unsafe extern "C" fn handle_signal(sig: libc::c_int) {
                    let pid = PROXY_CHILD_PID.load(Ordering::SeqCst);
                    if pid != 0 {
                        libc::kill(pid as libc::pid_t, libc::SIGTERM);
                        libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0);
                    }
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
                // nosemgrep: unsafe-block
                unsafe {
                    libc::signal(
                        libc::SIGINT,
                        handle_signal as *const () as libc::sighandler_t,
                    );
                    libc::signal(
                        libc::SIGTERM,
                        handle_signal as *const () as libc::sighandler_t,
                    );
                }
            }

            struct ChildGuard(Option<std::process::Child>);
            impl Drop for ChildGuard {
                fn drop(&mut self) {
                    if let Some(mut child) = self.0.take() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    PROXY_CHILD_PID.store(0, Ordering::SeqCst);
                }
            }

            // SECURITY (#100 G2 Codex 2nd pass — CRITICAL 2): `cmd_name` is
            // guaranteed separator-free at this point (path-bearing tokens
            // are rejected above), so always resolve the bare name via PATH.
            // argv[0] and argv[1..] stay OsString — never word-split, never
            // shell-interpreted.
            let mut proc_cmd = core::utils::resolved_command(&cmd_name_display);
            let _ = &cmd_name; // OsString retained for argv-shape guarantees
            let mut child = ChildGuard(Some(
                proc_cmd
                    .args(&cmd_args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context(format!("Failed to execute command: {}", cmd_name_display))?,
            ));

            // Store child PID for signal handler before anything can fail
            if let Some(ref inner) = child.0 {
                PROXY_CHILD_PID.store(inner.id(), Ordering::SeqCst);
            }

            let inner = child.0.as_mut().context("Child process missing")?;
            let stdout_pipe = inner
                .stdout
                .take()
                .context("Failed to capture child stdout")?;
            let stderr_pipe = inner
                .stderr
                .take()
                .context("Failed to capture child stderr")?;

            const CAP: usize = 1_048_576;

            let stdout_handle = thread::spawn(move || -> std::io::Result<Vec<u8>> {
                let mut reader = stdout_pipe;
                let mut captured = Vec::new();
                let mut buf = [0u8; 8192];

                loop {
                    let count = reader.read(&mut buf)?;
                    if count == 0 {
                        break;
                    }
                    if captured.len() < CAP {
                        let take = count.min(CAP - captured.len());
                        captured.extend_from_slice(&buf[..take]);
                    }
                    let mut out = std::io::stdout().lock();
                    out.write_all(&buf[..count])?;
                    out.flush()?;
                }

                Ok(captured)
            });

            let stderr_handle = thread::spawn(move || -> std::io::Result<Vec<u8>> {
                let mut reader = stderr_pipe;
                let mut captured = Vec::new();
                let mut buf = [0u8; 8192];

                loop {
                    let count = reader.read(&mut buf)?;
                    if count == 0 {
                        break;
                    }
                    if captured.len() < CAP {
                        let take = count.min(CAP - captured.len());
                        captured.extend_from_slice(&buf[..take]);
                    }
                    let mut err = std::io::stderr().lock();
                    err.write_all(&buf[..count])?;
                    err.flush()?;
                }

                Ok(captured)
            });

            let status = child
                .0
                .take()
                .context("Child process missing")?
                .wait()
                .context(format!("Failed waiting for command: {}", cmd_name_display))?;

            let stdout_bytes = stdout_handle
                .join()
                .map_err(|_| anyhow::anyhow!("stdout streaming thread panicked"))??;
            let stderr_bytes = stderr_handle
                .join()
                .map_err(|_| anyhow::anyhow!("stderr streaming thread panicked"))??;

            let stdout = String::from_utf8_lossy(&stdout_bytes);
            let stderr = String::from_utf8_lossy(&stderr_bytes);
            let full_output = format!("{}{}", stdout, stderr);

            // Track usage (input = output since no filtering)
            timer.track(
                &format!("{} {}", cmd_name_display, cmd_args_display.join(" ")),
                &format!(
                    "contextcrawler proxy {} {}",
                    cmd_name_display,
                    cmd_args_display.join(" ")
                ),
                &full_output,
                &full_output,
            );

            core::utils::exit_code_from_status(&status, &cmd_name_display)
        }

        Commands::Trust { list, global } => {
            hooks::trust::run_trust(list, global)?;
            0
        }

        Commands::Untrust { global } => {
            hooks::trust::run_untrust(global)?;
            0
        }

        Commands::Verify {
            filter,
            require_all,
        } => {
            if filter.is_some() {
                // Filter-specific mode: run only that filter's tests
                hooks::verify_cmd::run(filter, require_all)?;
            } else {
                // Default or --require-all: always run integrity check first
                hooks::integrity::run_verify(cli.verbose)?;
                hooks::verify_cmd::run(None, require_all)?;
            }
            0
        }

        Commands::Security {
            all,
            json,
            scrub_logs,
            dry_run,
        } => {
            if scrub_logs {
                hooks::tirith_gate::run_scrub_logs(dry_run)?
            } else {
                hooks::tirith_gate::run_security_dashboard(all, json)?
            }
        }
    };

    Ok(code)
}

/// Returns true for commands that are invoked via the hook pipeline
/// (i.e., commands that process rewritten shell commands).
/// Meta commands (init, gain, verify, etc.) are excluded because
/// they are run directly by the user, not through the hook.
/// Returns true for commands that go through the hook pipeline
/// and therefore require integrity verification.
///
/// SECURITY: whitelist pattern — new commands are NOT integrity-checked
/// until explicitly added here. A forgotten command fails open (no check)
/// rather than creating false confidence about what's protected.
fn is_operational_command(cmd: &Commands) -> bool {
    matches!(
        cmd,
        Commands::Ls { .. }
            | Commands::Tree { .. }
            | Commands::Read { .. }
            | Commands::Smart { .. }
            | Commands::Git { .. }
            | Commands::Gh { .. }
            | Commands::Glab { .. }
            | Commands::Pnpm { .. }
            | Commands::Err { .. }
            | Commands::Test { .. }
            | Commands::Json { .. }
            | Commands::Deps { .. }
            | Commands::Env { .. }
            | Commands::Find { .. }
            | Commands::Diff { .. }
            | Commands::Log { .. }
            | Commands::Dotnet { .. }
            | Commands::Docker { .. }
            | Commands::Kubectl { .. }
            | Commands::Summary { .. }
            | Commands::Grep { .. }
            | Commands::Wget { .. }
            | Commands::Vitest { .. }
            | Commands::Prisma { .. }
            | Commands::Tsc { .. }
            | Commands::Next { .. }
            | Commands::Lint { .. }
            | Commands::Prettier { .. }
            | Commands::Playwright { .. }
            | Commands::Cargo { .. }
            | Commands::Npm { .. }
            | Commands::Npx { .. }
            | Commands::Curl { .. }
            | Commands::Ruff { .. }
            | Commands::Pytest { .. }
            | Commands::Rake { .. }
            | Commands::Rubocop { .. }
            | Commands::Rspec { .. }
            | Commands::Pip { .. }
            | Commands::Go { .. }
            | Commands::GolangciLint { .. }
            | Commands::Gt { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::cell::Cell;

    #[test]
    fn test_proxy_wrapped_equivalent_known_tools() {
        // Sanity: every tool in the codex template's "Applies to:" list should
        // either have a wrapper hint here or be intentionally absent. This
        // assertion just spot-checks the gap-pattern tools from issue #53.
        assert!(proxy_wrapped_equivalent("git").is_some());
        assert!(proxy_wrapped_equivalent("rg").is_some());
        assert!(proxy_wrapped_equivalent("nl").is_some());
        assert!(proxy_wrapped_equivalent("sed").is_some());
        assert!(proxy_wrapped_equivalent("awk").is_some());
        assert!(proxy_wrapped_equivalent("kubectl").is_some());
        // Negative cases — the nudge should stay quiet for tools we don't wrap.
        assert!(proxy_wrapped_equivalent("whoami").is_none());
        assert!(proxy_wrapped_equivalent("date").is_none());
        assert!(proxy_wrapped_equivalent("env").is_none());
    }

    #[test]
    fn test_proxy_wrapped_equivalent_message_does_not_recurse() {
        // REGRESSION: the first draft templated `contextcrawler {basename}`
        // around the suggestion, producing "contextcrawler contextcrawler read".
        // Suggestions now embed the literal command, so the eprintln template
        // is just `Consider: {suggestion}`. If a suggestion starts with
        // "contextcrawler" it should be the first token, never repeated.
        for tool in &["git", "rg", "nl", "sed", "kubectl"] {
            let suggestion = proxy_wrapped_equivalent(tool).unwrap();
            // First word is "contextcrawler"; "contextcrawler" should NOT appear twice.
            assert!(
                suggestion.starts_with("contextcrawler "),
                "suggestion for `{}` should start with 'contextcrawler ': {}",
                tool,
                suggestion
            );
            assert_eq!(
                suggestion.matches("contextcrawler").count(),
                1,
                "suggestion for `{}` repeats 'contextcrawler': {}",
                tool,
                suggestion
            );
        }
    }

    #[test]
    fn test_git_commit_single_message() {
        let cli = Cli::try_parse_from(["rtk", "git", "commit", "-m", "fix: typo"]).unwrap();
        match cli.command {
            Commands::Git {
                command: GitCommands::Commit { args },
                ..
            } => {
                assert_eq!(args, vec!["-m", "fix: typo"]);
            }
            _ => panic!("Expected Git Commit command"),
        }
    }

    #[test]
    fn test_git_commit_multiple_messages() {
        let cli = Cli::try_parse_from([
            "rtk",
            "git",
            "commit",
            "-m",
            "feat: add support",
            "-m",
            "Body paragraph here.",
        ])
        .unwrap();
        match cli.command {
            Commands::Git {
                command: GitCommands::Commit { args },
                ..
            } => {
                assert_eq!(
                    args,
                    vec!["-m", "feat: add support", "-m", "Body paragraph here."]
                );
            }
            _ => panic!("Expected Git Commit command"),
        }
    }

    // #327: git commit -am "msg" was rejected by Clap
    #[test]
    fn test_git_commit_am_flag() {
        let cli = Cli::try_parse_from(["rtk", "git", "commit", "-am", "quick fix"]).unwrap();
        match cli.command {
            Commands::Git {
                command: GitCommands::Commit { args },
                ..
            } => {
                assert_eq!(args, vec!["-am", "quick fix"]);
            }
            _ => panic!("Expected Git Commit command"),
        }
    }

    #[test]
    fn test_git_commit_amend() {
        let cli =
            Cli::try_parse_from(["rtk", "git", "commit", "--amend", "-m", "new msg"]).unwrap();
        match cli.command {
            Commands::Git {
                command: GitCommands::Commit { args },
                ..
            } => {
                assert_eq!(args, vec!["--amend", "-m", "new msg"]);
            }
            _ => panic!("Expected Git Commit command"),
        }
    }

    #[test]
    fn test_git_global_options_parsing() {
        let cli =
            Cli::try_parse_from(["rtk", "git", "--no-pager", "--no-optional-locks", "status"])
                .unwrap();
        match cli.command {
            Commands::Git {
                no_pager,
                no_optional_locks,
                bare,
                literal_pathspecs,
                ..
            } => {
                assert!(no_pager);
                assert!(no_optional_locks);
                assert!(!bare);
                assert!(!literal_pathspecs);
            }
            _ => panic!("Expected Git command"),
        }
    }

    #[test]
    fn test_git_commit_long_flag_multiple() {
        let cli = Cli::try_parse_from([
            "rtk",
            "git",
            "commit",
            "--message",
            "title",
            "--message",
            "body",
            "--message",
            "footer",
        ])
        .unwrap();
        match cli.command {
            Commands::Git {
                command: GitCommands::Commit { args },
                ..
            } => {
                assert_eq!(
                    args,
                    vec![
                        "--message",
                        "title",
                        "--message",
                        "body",
                        "--message",
                        "footer"
                    ]
                );
            }
            _ => panic!("Expected Git Commit command"),
        }
    }

    #[test]
    fn test_try_parse_valid_git_status() {
        let result = Cli::try_parse_from(["rtk", "git", "status"]);
        assert!(result.is_ok(), "git status should parse successfully");
    }

    #[test]
    fn test_try_parse_init_agent_hermes() {
        let cli = Cli::try_parse_from(["rtk", "init", "--agent", "hermes"]).unwrap();
        match cli.command {
            Commands::Init { agent, .. } => {
                assert_eq!(agent, Some(AgentTarget::Hermes));
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_try_parse_kubectl_get_alias() {
        let cli = Cli::try_parse_from(["rtk", "kubectl", "get", "pods", "-n", "default"]).unwrap();

        match cli.command {
            Commands::Kubectl {
                command: KubectlCommands::Get { args },
            } => assert_eq!(args, vec!["pods", "-n", "default"]),
            _ => panic!("Expected Kubectl Get command"),
        }
    }

    #[test]
    fn test_try_parse_init_agent_hermes_uninstall() {
        let cli = Cli::try_parse_from(["rtk", "init", "--agent", "hermes", "--uninstall"]).unwrap();
        match cli.command {
            Commands::Init {
                agent, uninstall, ..
            } => {
                assert_eq!(agent, Some(AgentTarget::Hermes));
                assert!(uninstall);
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_try_parse_init_agent_pidev() {
        let cli = Cli::try_parse_from(["rtk", "init", "--agent", "pidev"]).unwrap();
        match cli.command {
            Commands::Init { agent, .. } => {
                assert_eq!(agent, Some(AgentTarget::Pidev));
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_try_parse_init_agent_pidev_uninstall() {
        let cli = Cli::try_parse_from(["rtk", "init", "--agent", "pidev", "--uninstall"]).unwrap();
        match cli.command {
            Commands::Init {
                agent, uninstall, ..
            } => {
                assert_eq!(agent, Some(AgentTarget::Pidev));
                assert!(uninstall);
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_init_uninstall_dispatch_routes_hermes_to_hermes_cleanup() {
        let hermes_called = Cell::new(false);
        let pidev_called = Cell::new(false);
        let standard_called = Cell::new(false);
        let ctx = hooks::init::InitContext {
            verbose: 2,
            dry_run: true,
        };

        let result = uninstall_init_dispatch(
            Some(AgentTarget::Hermes),
            true,
            false,
            false,
            ctx,
            |ctx| {
                hermes_called.set(true);
                assert_eq!(ctx.verbose, 2);
                assert!(ctx.dry_run);
                Ok(())
            },
            |_| {
                pidev_called.set(true);
                Ok(())
            },
            |_, _, _, _, _| {
                standard_called.set(true);
                Ok(())
            },
        );

        assert!(result.is_ok());
        assert!(hermes_called.get());
        assert!(!pidev_called.get());
        assert!(!standard_called.get());
    }

    #[test]
    fn test_init_uninstall_dispatch_routes_pidev_to_pidev_cleanup() {
        let hermes_called = Cell::new(false);
        let pidev_called = Cell::new(false);
        let standard_called = Cell::new(false);
        let ctx = hooks::init::InitContext {
            verbose: 1,
            dry_run: true,
        };

        let result = uninstall_init_dispatch(
            Some(AgentTarget::Pidev),
            true,
            false,
            false,
            ctx,
            |_| {
                hermes_called.set(true);
                Ok(())
            },
            |ctx| {
                pidev_called.set(true);
                assert_eq!(ctx.verbose, 1);
                assert!(ctx.dry_run);
                Ok(())
            },
            |_, _, _, _, _| {
                standard_called.set(true);
                Ok(())
            },
        );

        assert!(result.is_ok());
        assert!(pidev_called.get(), "Pidev should route to pidev cleanup");
        assert!(!hermes_called.get());
        assert!(!standard_called.get());
    }

    #[test]
    fn test_try_parse_help_is_display_help() {
        match Cli::try_parse_from(["rtk", "--help"]) {
            Err(e) => assert_eq!(e.kind(), ErrorKind::DisplayHelp),
            Ok(_) => panic!("Expected DisplayHelp error"),
        }
    }

    #[test]
    fn test_try_parse_version_is_display_version() {
        match Cli::try_parse_from(["rtk", "--version"]) {
            Err(e) => assert_eq!(e.kind(), ErrorKind::DisplayVersion),
            Ok(_) => panic!("Expected DisplayVersion error"),
        }
    }

    #[test]
    fn test_try_parse_unknown_subcommand_is_error() {
        match Cli::try_parse_from(["rtk", "nonexistent-command"]) {
            Err(e) => assert!(!matches!(
                e.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            )),
            Ok(_) => panic!("Expected parse error for unknown subcommand"),
        }
    }

    #[test]
    fn test_try_parse_git_with_dash_c_succeeds() {
        let result = Cli::try_parse_from(["rtk", "git", "-C", "/path", "status"]);
        assert!(
            result.is_ok(),
            "git -C /path status should parse successfully"
        );
        if let Ok(cli) = result {
            match cli.command {
                Commands::Git { directory, .. } => {
                    assert_eq!(directory, vec!["/path"]);
                }
                _ => panic!("Expected Git command"),
            }
        }
    }

    #[test]
    fn test_gain_failures_flag_parses() {
        let result = Cli::try_parse_from(["rtk", "gain", "--failures"]);
        assert!(result.is_ok());
        if let Ok(cli) = result {
            match cli.command {
                Commands::Gain { failures, .. } => assert!(failures),
                _ => panic!("Expected Gain command"),
            }
        }
    }

    #[test]
    fn test_gain_failures_short_flag_parses() {
        let result = Cli::try_parse_from(["rtk", "gain", "-F"]);
        assert!(result.is_ok());
        if let Ok(cli) = result {
            match cli.command {
                Commands::Gain { failures, .. } => assert!(failures),
                _ => panic!("Expected Gain command"),
            }
        }
    }

    #[test]
    fn test_meta_commands_reject_bad_flags() {
        // CTXCRL meta-commands should produce parse errors (not fall through to raw execution).
        // Skip "proxy" because it uses trailing_var_arg (accepts any args by design).
        for cmd in CTXCRL_META_COMMANDS {
            if matches!(*cmd, "proxy" | "run" | "rewrite" | "session") {
                continue; // these use trailing_var_arg (accept any args by design)
            }
            let result = Cli::try_parse_from(["rtk", cmd, "--nonexistent-flag-xyz"]);
            assert!(
                result.is_err(),
                "Meta-command '{}' with bad flag should fail to parse",
                cmd
            );
        }
    }

    #[test]
    fn test_run_command_with_dash_c() {
        let cli = Cli::try_parse_from(["rtk", "run", "-c", "git status && echo done"]).unwrap();
        match cli.command {
            Commands::Run { command, args } => {
                assert_eq!(command, Some("git status && echo done".to_string()));
                assert!(args.is_empty());
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_command_positional_args() {
        let cli = Cli::try_parse_from(["rtk", "run", "echo", "hello"]).unwrap();
        match cli.command {
            Commands::Run { command, args } => {
                assert!(command.is_none());
                assert_eq!(args, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_hook_claude_parses() {
        let cli = Cli::try_parse_from(["rtk", "hook", "claude"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Hook {
                command: HookCommands::Claude
            }
        ));
    }

    #[test]
    fn test_hook_check_parses() {
        let cli = Cli::try_parse_from(["rtk", "hook", "check", "git", "status"]).unwrap();
        match cli.command {
            Commands::Hook {
                command: HookCommands::Check { agent, command },
            } => {
                assert_eq!(agent, "claude");
                assert_eq!(command, vec!["git", "status"]);
            }
            _ => panic!("Expected Hook Check command"),
        }
    }

    #[test]
    fn test_hook_check_with_agent() {
        let cli =
            Cli::try_parse_from(["rtk", "hook", "check", "--agent", "gemini", "cargo", "test"])
                .unwrap();
        match cli.command {
            Commands::Hook {
                command: HookCommands::Check { agent, command },
            } => {
                assert_eq!(agent, "gemini");
                assert_eq!(command, vec!["cargo", "test"]);
            }
            _ => panic!("Expected Hook Check command"),
        }
    }

    #[test]
    fn test_hook_check_preserves_double_dash_in_command() {
        let cli = Cli::try_parse_from([
            "rtk",
            "hook",
            "check",
            "shadowenv",
            "exec",
            "--",
            "git",
            "status",
        ])
        .unwrap();
        match cli.command {
            Commands::Hook {
                command: HookCommands::Check { agent, command },
            } => {
                assert_eq!(agent, "claude");
                assert_eq!(command, vec!["shadowenv", "exec", "--", "git", "status"]);
            }
            _ => panic!("Expected Hook Check command"),
        }
    }

    #[test]
    fn test_meta_command_list_is_complete() {
        // Verify all meta-commands are in the guard list by checking they parse with valid syntax
        let meta_cmds_that_parse = [
            vec!["rtk", "gain"],
            vec!["rtk", "discover"],
            vec!["rtk", "learn"],
            vec!["rtk", "init"],
            vec!["rtk", "config"],
            vec!["rtk", "proxy", "echo", "hi"],
            vec!["rtk", "run", "-c", "echo hi"],
            vec!["rtk", "hook-audit"],
            vec!["rtk", "cc-economics"],
        ];
        for args in &meta_cmds_that_parse {
            let result = Cli::try_parse_from(args.iter());
            assert!(
                result.is_ok(),
                "Meta-command {:?} should parse successfully",
                args
            );
        }
    }

    #[test]
    fn test_shell_split_simple() {
        assert_eq!(
            shell_split("head -50 file.php"),
            vec!["head", "-50", "file.php"]
        );
    }

    #[test]
    fn test_shell_split_double_quotes() {
        assert_eq!(
            shell_split(r#"git log --format="%H %s""#),
            vec!["git", "log", "--format=%H %s"]
        );
    }

    #[test]
    fn test_shell_split_single_quotes() {
        assert_eq!(
            shell_split("grep -r 'hello world' ."),
            vec!["grep", "-r", "hello world", "."]
        );
    }

    #[test]
    fn test_shell_split_single_word() {
        assert_eq!(shell_split("ls"), vec!["ls"]);
    }

    #[test]
    fn test_shell_split_empty() {
        let result: Vec<String> = shell_split("");
        assert!(result.is_empty());
    }

    // --- #100 G2 IMPORTANT 3: absolute-path bin basename normalisation ---

    #[test]
    fn test_bin_basename_absolute_path() {
        assert_eq!(bin_basename("/usr/bin/npm"), "npm");
        assert_eq!(bin_basename("/usr/local/bin/cargo"), "cargo");
        assert_eq!(bin_basename("./node_modules/.bin/pnpm"), "pnpm");
    }

    #[test]
    fn test_bin_basename_bare_name() {
        assert_eq!(bin_basename("npm"), "npm");
        assert_eq!(bin_basename("cargo"), "cargo");
    }

    /// `contextcrawler /usr/bin/npm --version` must resolve to a bin that
    /// is in `META_PASSTHROUGH_BINS` so it hits the hardened
    /// `run_simple_passthrough` path, not `run_fallback`.
    #[test]
    fn test_absolute_path_bin_matches_meta_passthrough() {
        let raw = "/usr/bin/npm";
        assert!(
            !META_PASSTHROUGH_BINS.contains(&raw),
            "raw absolute path must NOT match — that was the bug"
        );
        assert!(
            META_PASSTHROUGH_BINS.contains(&bin_basename(raw)),
            "basename-normalised bin must match META_PASSTHROUGH_BINS"
        );
    }

    // --- #100 G2 CRITICAL 2: proxy keeps whitespace-containing argv intact ---

    /// Without `--shell`, a binary path containing whitespace is a single
    /// argv[0] token — it must never be word-split. This is the OsString
    /// passthrough path: `args[0]` is the binary verbatim.
    #[test]
    fn test_proxy_default_does_not_split_whitespace_path() {
        use std::ffi::OsString;
        // Simulates `contextcrawler proxy "/opt/my tool/bin" arg1`.
        let args: Vec<OsString> = vec![OsString::from("/opt/my tool/bin"), OsString::from("arg1")];
        // Default (non-shell) path: argv[0] verbatim, argv[1..] verbatim.
        let (cmd_name, cmd_args) = (args[0].clone(), args[1..].to_vec());
        assert_eq!(cmd_name, OsString::from("/opt/my tool/bin"));
        assert_eq!(cmd_args, vec![OsString::from("arg1")]);
        // The path is a single token — shell_split WOULD have wrongly split it.
        assert!(shell_split(&cmd_name.to_string_lossy()).len() > 1);
    }

    #[test]
    fn test_rewrite_clap_multi_args() {
        // Originally reported (pre-rebrand) as `rewrite ls -al` failing because
        // Clap rejected `-al` as an unknown flag. With trailing_var_arg +
        // allow_hyphen_values, multiple args are accepted and joined into a
        // single command string. argv[0] in the test fixtures is the current
        // binary name — clap ignores it anyway.
        let cases = vec![
            vec!["contextcrawler", "rewrite", "ls", "-al"],
            vec!["contextcrawler", "rewrite", "git", "status"],
            vec!["contextcrawler", "rewrite", "npm", "exec"],
            vec!["contextcrawler", "rewrite", "cargo", "test"],
            vec!["contextcrawler", "rewrite", "du", "-sh", "."],
            vec!["contextcrawler", "rewrite", "head", "-50", "file.txt"],
        ];
        for args in &cases {
            let result = Cli::try_parse_from(args.iter());
            assert!(
                result.is_ok(),
                "contextcrawler rewrite {:?} should parse (was failing before trailing_var_arg fix)",
                &args[2..]
            );
            if let Ok(cli) = result {
                match cli.command {
                    Commands::Rewrite { ref args } => {
                        assert!(args.len() >= 2, "rewrite args should capture all tokens");
                    }
                    _ => panic!("expected Rewrite command"),
                }
            }
        }
    }

    #[test]
    fn test_rewrite_clap_quoted_single_arg() {
        // Quoted form: `contextcrawler rewrite "git status"` — single arg containing spaces
        let result = Cli::try_parse_from(["contextcrawler", "rewrite", "git status"]);
        assert!(result.is_ok());
        if let Ok(cli) = result {
            match cli.command {
                Commands::Rewrite { ref args } => {
                    assert_eq!(args.len(), 1);
                    assert_eq!(args[0], "git status");
                }
                _ => panic!("expected Rewrite command"),
            }
        }
    }

    #[test]
    fn test_merge_filters_with_no_args() {
        let filters = vec![];
        let args = vec!["--depth=0".to_string(), "--no-verbose".to_string()];
        let expected_args = vec!["--depth=0", "--no-verbose"];
        assert_eq!(merge_pnpm_args(&filters, &args), expected_args);
    }

    #[test]
    fn test_merge_filters_with_args() {
        let filters = vec!["@app1".to_string(), "@app2".to_string()];
        let args = vec![
            "--filter=@app3".to_string(),
            "--depth=0".to_string(),
            "--no-verbose".to_string(),
        ];
        let expected_args = vec![
            "--filter=@app1",
            "--filter=@app2",
            "--filter=@app3",
            "--depth=0",
            "--no-verbose",
        ];
        assert_eq!(merge_pnpm_args(&filters, &args), expected_args);
    }

    #[test]
    fn test_merge_filters_with_no_args_os() {
        let filters = vec![];
        let args = vec![OsString::from("--depth=0")];
        let expected_args = vec![OsString::from("--depth=0")];
        assert_eq!(merge_pnpm_args_os(&filters, &args), expected_args);
    }

    #[test]
    fn test_merge_filters_with_args_os() {
        let filters = vec!["@app1".to_string()];
        let args = vec![OsString::from("--depth=0")];
        let expected_args = vec![
            OsString::from("--filter=@app1"),
            OsString::from("--depth=0"),
        ];
        assert_eq!(merge_pnpm_args_os(&filters, &args), expected_args);
    }

    #[test]
    fn test_pnpm_subcommand_with_filter() {
        let cli = Cli::try_parse_from([
            "rtk", "pnpm", "--filter", "@app1", "--filter", "@app2", "list", "--filter", "@app3",
            "--filter", "@app4", "--prod",
        ])
        .unwrap();
        match cli.command {
            Commands::Pnpm {
                filter,
                command: PnpmCommands::List { depth, args },
            } => {
                assert_eq!(depth, 0);
                assert_eq!(filter, vec!["@app1", "@app2"]);
                assert_eq!(
                    args,
                    vec!["--filter", "@app3", "--filter", "@app4", "--prod"]
                );
            }
            _ => panic!("Expected Pnpm List command"),
        }
    }

    #[test]
    fn test_git_push_u_flag_passes_through() {
        let cli = Cli::try_parse_from(["rtk", "git", "push", "-u", "origin", "my-branch"]).unwrap();
        assert!(
            !cli.ultra_compact,
            "-u on git push must NOT be consumed as --ultra-compact"
        );
        match cli.command {
            Commands::Git {
                command: GitCommands::Push { args },
                ..
            } => {
                assert!(
                    args.contains(&"-u".to_string()),
                    "-u must be forwarded to git push, got: {:?}",
                    args
                );
            }
            _ => panic!("Expected Git Push command"),
        }
    }

    #[test]
    fn test_pnpm_subcommand_with_short_filter() {
        // -F is the short form of --filter in pnpm
        let cli =
            Cli::try_parse_from(["rtk", "pnpm", "-F", "@app1", "-F", "@app2", "list"]).unwrap();
        match cli.command {
            Commands::Pnpm { filter, .. } => {
                assert_eq!(filter, vec!["@app1", "@app2"]);
            }
            _ => panic!("Expected Pnpm command"),
        }
    }

    #[test]
    fn test_pnpm_typecheck_without_filters() {
        let cli = Cli::try_parse_from([
            "rtk",
            "pnpm",
            "typecheck",
            "--filter",
            "@app3",
            "--filter",
            "@app4",
        ])
        .unwrap();
        match cli.command {
            Commands::Pnpm { filter, command } => {
                let warning = validate_pnpm_filters(&filter, &command);

                assert!(filter.is_empty());
                assert!(warning.is_none())
            }
            _ => panic!("Expected Pnpm Build command"),
        }
    }

    #[test]
    fn test_pnpm_typecheck_with_filters() {
        let cli = Cli::try_parse_from([
            "rtk",
            "pnpm",
            "--filter",
            "@app1",
            "--filter",
            "@app2",
            "typecheck",
            "--filter",
            "@app3",
            "--filter",
            "@app4",
        ])
        .unwrap();
        match cli.command {
            Commands::Pnpm { filter, command } => {
                let warning = validate_pnpm_filters(&filter, &command).unwrap();

                assert_eq!(filter, vec!["@app1", "@app2"]);
                assert_eq!(warning, "[contextcrawler] warning: --filter is not yet supported for pnpm tsc, filters preceding the subcommand will be ignored")
            }
            _ => panic!("Expected Pnpm Build command"),
        }
    }

    #[test]
    fn test_ultra_compact_long_form_still_works() {
        let cli = Cli::try_parse_from(["rtk", "--ultra-compact", "git", "status"]).unwrap();
        assert!(
            cli.ultra_compact,
            "--ultra-compact long form must still enable ultra-compact mode"
        );
    }

    #[test]
    fn test_npx_unknown_tool_passthrough() {
        // The bug (rtk-ai/rtk#815) was that unknown tools under `rtk npx`
        // were dispatched to `npm` instead of `npx`. At the parse level, the
        // Npx variant must carry all args through unchanged so the dispatch
        // arm can forward them to npx.
        let cli = Cli::try_parse_from(["rtk", "npx", "cowsay", "hello"]).unwrap();
        match cli.command {
            Commands::Npx { args } => {
                assert_eq!(args, vec!["cowsay", "hello"]);
            }
            _ => panic!("Expected Commands::Npx for unknown tool"),
        }
    }
}
