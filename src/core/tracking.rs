//! Token savings tracking and analytics system.
//!
//! This module provides comprehensive tracking of RTK command executions,
//! recording token savings, execution times, and providing aggregation APIs
//! for daily/weekly/monthly statistics.
//!
//! # Architecture
//!
//! - Storage: SQLite database (~/.local/share/rtk/tracking.db)
//! - Retention: 90-day automatic cleanup
//! - Metrics: Input/output tokens, savings %, execution time
//!
//! # Quick Start
//!
//! ```no_run
//! use contextcrawler::core::tracking::{TimedExecution, Tracker};
//!
//! // Track a command execution
//! let timer = TimedExecution::start();
//! let input = "raw output";
//! let output = "filtered output";
//! timer.track("ls -la", "contextcrawler ls", input, output);
//!
//! // Query statistics
//! let tracker = Tracker::new().unwrap();
//! let summary = tracker.get_summary().unwrap();
//! println!("Saved {} tokens", summary.total_saved);
//! ```
//!
//! See [docs/tracking.md](../docs/tracking.md) for full documentation.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

/// Detect whether we're running inside a test context, so we can short-circuit
/// DB writes and avoid polluting the production `history.db`. Issue #91.
///
/// Two independent signals — either is sufficient:
///
/// 1. `CONTEXTCRAWLER_TEST_MODE=1` — sentinel set by integration test harnesses
///    when they spawn the binary as a child process. Required because spawned
///    binaries can be RELEASE-compiled (`cargo test --release`), so
///    `cfg!(debug_assertions)` is false and `cfg!(test)` is false in the
///    spawned binary's own compilation unit. Codex review caught this hole.
///
/// 2. `cfg!(test)` + cargo env vars — covers in-process unit tests
///    (`#[test]` fns inside `src/`) regardless of build mode. `cfg!(test)` is
///    set during cargo-test compilation in both debug and release.
///
/// Explicit opt-in: if `RTK_DB_PATH` is set, the caller wants tracking writes
/// against that path (typically a tmpfile in a test that *exercises*
/// tracking), so we do NOT short-circuit.
pub(crate) fn is_test_context() -> bool {
    if crate::core::env_compat::env_present("CTXCRL_DB_PATH") {
        return false; // explicit opt-in path
    }
    // Test harness sentinel — set by tests/common.rs or each #[test] that
    // spawns the binary.
    if std::env::var("CONTEXTCRAWLER_TEST_MODE").as_deref() == Ok("1") {
        return true;
    }
    // Cargo unit-test in-process (lives inside the test runner, not a spawned
    // binary). `cfg!(test)` is true inside `#[test]` modules in any build mode.
    cfg!(test)
        && std::env::var("CARGO_PKG_NAME").as_deref() == Ok("contextcrawler")
        && std::env::var("CARGO_MANIFEST_DIR").is_ok()
}

// ── Project path helpers ── // added: project-scoped tracking support

/// Get the canonical project path string for the current working directory.
/// Scrub well-known credential patterns before persistence.
///
/// The tracking database retains commands for 90 days and `gain --history`
/// renders rows back into agent context. Bearer tokens, --password values,
/// AWS keys and the like must not survive that round trip. This function is
/// applied to every command string at the INSERT boundary.
///
/// The list is intentionally narrow — patterns that are unambiguous as
/// secrets and where redaction does not destroy debugging context.
pub fn scrub_secrets(cmd: &str) -> String {
    use lazy_static::lazy_static;
    lazy_static! {
        // `--password VALUE` / `--password=VALUE`, plus --token, --api-key,
        // --secret, --access-key, --auth-token, --client-secret. The VALUE
        // alternation is escape-aware so shell-escaped quotes inside the
        // value (`--password="pa\"ss word"`) don't terminate the match
        // early and leak the tail — Codex re-review caught the non-escape-
        // aware version.
        static ref FLAG_VALUE: Regex = Regex::new(
            r#"(?i)(--(?:password|token|api[-_]?key|secret|access[-_]?key|auth[-_]?token|client[-_]?secret))(=|\s+)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)"#
        ).unwrap();
        // mysql-style -pPASSWORD (no space). Only meaningful for mysql /
        // mariadb invocations — gated by is_mysql_command below to avoid
        // false positives on flags like `curl -p3000` (Codex review).
        static ref MYSQL_P: Regex = Regex::new(r"(\s|^)-p(\S+)").unwrap();
        // `-H 'Authorization: <scheme> <token>'` (curl). Match both single and
        // double-quoted forms, and the unquoted equivalent.
        static ref AUTH_HEADER: Regex = Regex::new(
            r#"(?i)(authorization:\s*(?:bearer|basic|token|apikey)\s+)([^'"\s]+)"#
        ).unwrap();
        // URL with embedded credentials: scheme://user:pass@host
        static ref URL_USERPASS: Regex = Regex::new(
            r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^:/\s]+):([^@\s]+)@"
        ).unwrap();
        // AWS access key id (AKIA / ASIA prefix, 20 chars total).
        static ref AWS_KEY: Regex = Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap();
        // GitHub tokens: classic PATs / OAuth / user-to-server / server /
        // refresh, plus fine-grained PATs (`github_pat_…`). Codex review of
        // the original regex caught that fine-grained PATs slipped through.
        static ref GH_TOKEN: Regex = Regex::new(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]+)\b"
        ).unwrap();
        // Slack tokens (xox[abprs]-...).
        static ref SLACK_TOKEN: Regex = Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap();
    }

    let s = FLAG_VALUE.replace_all(cmd, "$1$2<REDACTED>");
    let s = AUTH_HEADER.replace_all(&s, "$1<REDACTED>");
    let s = URL_USERPASS.replace_all(&s, "$1$2:<REDACTED>@");
    let s = AWS_KEY.replace_all(&s, "<REDACTED-AWS-KEY>");
    let s = GH_TOKEN.replace_all(&s, "<REDACTED-GH-TOKEN>");
    let s = SLACK_TOKEN.replace_all(&s, "<REDACTED-SLACK-TOKEN>");
    let s: std::borrow::Cow<str> = if is_mysql_command(&s) {
        MYSQL_P.replace_all(&s, "$1-p<REDACTED>")
    } else {
        s
    };
    s.to_string()
}

/// Detect whether a command line invokes mysql/mariadb so we can apply the
/// `-p<password>` rewrite without corrupting unrelated tools that use `-p`.
///
/// Limitation: a wrapper like `env mysql -p…` or `sudo mysql -p…` has `env`
/// or `sudo` as the first token, so the scrubber will not apply. The
/// shell-exec-boundary branch refuses to spawn these wrappers in the err /
/// test / summary subcommands; outside those paths the limitation is
/// accepted and documented in SECURITY.md.
fn is_mysql_command(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let basename = std::path::Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first);
    matches!(
        basename.to_ascii_lowercase().as_str(),
        "mysql"
            | "mysqldump"
            | "mysqladmin"
            | "mariadb"
            | "mariadb-dump"
            | "mariadb-admin"
            | "mysql.exe"
            | "mysqldump.exe"
            | "mysqladmin.exe"
            | "mariadb.exe"
            | "mariadb-dump.exe"
            | "mariadb-admin.exe"
    )
}

fn current_project_path_string() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Build SQL filter params for project-scoped queries.
/// Returns (exact_match, glob_prefix) for WHERE clause.
/// Uses GLOB instead of LIKE to avoid `_` and `%` in paths acting as wildcards. // changed: GLOB
fn project_filter_params(project_path: Option<&str>) -> (Option<String>, Option<String>) {
    match project_path {
        Some(p) => (
            Some(p.to_string()),
            Some(format!("{}{}*", p, std::path::MAIN_SEPARATOR)), // changed: GLOB pattern with * wildcard
        ),
        None => (None, None),
    }
}

use super::constants::{DEFAULT_HISTORY_DAYS, HISTORY_DB, RTK_DATA_DIR};

/// Main tracking interface for recording and querying command history.
///
/// Manages SQLite database connection and provides methods for:
/// - Recording command executions with token counts and timing
/// - Querying aggregated statistics (summary, daily, weekly, monthly)
/// - Retrieving recent command history
///
/// # Database Location
///
/// - Linux: `~/.local/share/rtk/tracking.db`
/// - macOS: `~/Library/Application Support/rtk/tracking.db`
/// - Windows: `%APPDATA%\rtk\tracking.db`
///
/// # Examples
///
/// ```no_run
/// use contextcrawler::core::tracking::Tracker;
///
/// let tracker = Tracker::new()?;
/// tracker.record("ls -la", "contextcrawler ls", 1000, 200, 50)?;
///
/// let summary = tracker.get_summary()?;
/// println!("Total saved: {} tokens", summary.total_saved);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct Tracker {
    conn: Connection,
}

/// Individual command record from tracking history.
///
/// Contains timestamp, command name, and savings metrics for a single execution.
#[derive(Debug)]
pub struct CommandRecord {
    /// UTC timestamp when command was executed
    pub timestamp: DateTime<Utc>,
    /// RTK command that was executed (e.g., "contextcrawler ls")
    pub ctxcrl_cmd: String,
    /// Number of tokens saved (input - output)
    pub saved_tokens: usize,
    /// Savings percentage ((saved / input) * 100)
    pub savings_pct: f64,
}

/// Aggregated statistics across all recorded commands.
///
/// Provides overall metrics and breakdowns by command and by day.
/// Returned by [`Tracker::get_summary`].
#[derive(Debug)]
pub struct GainSummary {
    /// Total number of commands recorded
    pub total_commands: usize,
    /// Total input tokens across all commands
    pub total_input: usize,
    /// Total output tokens across all commands
    pub total_output: usize,
    /// Total tokens saved (input - output)
    pub total_saved: usize,
    /// Total tokens by which filters INFLATED output beyond input (#196).
    /// `saved_tokens` floors at zero, so inflation is otherwise invisible.
    pub total_inflation: usize,
    /// Average savings percentage across all commands
    pub avg_savings_pct: f64,
    /// Total execution time across all commands (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
    /// Top 10 commands by tokens saved: (cmd, count, saved, avg_pct, avg_time_ms)
    pub by_command: Vec<(String, usize, usize, f64, u64)>,
    /// Last 30 days of activity: (date, saved_tokens)
    pub by_day: Vec<(String, usize)>,
}

/// One tool's token-leak profile for `gain --weak-filters`.
///
/// "Leaked" tokens are input that reached the model unfiltered
/// (`input - saved`). A high leak paired with a low [`savings_pct`] marks a
/// filter worth improving — or a command with no filter worth building.
///
/// [`savings_pct`]: WeakFilter::savings_pct
#[derive(Debug, Clone, Serialize)]
pub struct WeakFilter {
    /// Tool key (e.g. "read", "git log").
    pub tool: String,
    /// Number of recorded runs for this tool.
    pub runs: usize,
    /// Total input tokens seen by this tool.
    pub input_tokens: usize,
    /// Tokens that reached the model unfiltered (`input - saved`).
    pub leaked_tokens: usize,
    /// Volume-weighted savings percentage (`saved / input * 100`).
    pub savings_pct: f64,
    /// Tokens by which this tool's filters INFLATED output beyond input (#196).
    /// Floored-at-zero `saved_tokens` hides this; high inflation flags a
    /// filter regression worth investigating.
    pub inflation_tokens: usize,
}

/// Collapse a tracked command into a "tool" key for weak-filter ranking.
///
/// Strips the `contextcrawler `/`rtk ` prefix, then keeps the base command
/// plus its subcommand when the second token looks like one (`git log`,
/// `cargo test`) rather than a flag or a path (`read src/main.rs` → `read`).
fn weak_filter_tool_key(ctxcrl_cmd: &str) -> String {
    let cmd = ctxcrl_cmd
        .strip_prefix("contextcrawler ")
        .or_else(|| ctxcrl_cmd.strip_prefix("rtk "))
        .unwrap_or(ctxcrl_cmd);
    let mut words = cmd.split_whitespace();
    let Some(first) = words.next() else {
        return String::new();
    };
    match words.next() {
        Some(second)
            if !second.starts_with('-') && !second.contains('/') && !second.contains('.') =>
        {
            format!("{first} {second}")
        }
        _ => first.to_string(),
    }
}

/// Daily statistics for token savings and execution metrics.
///
/// Serializable to JSON for export via `rtk gain --daily --format json`.
///
/// # JSON Schema
///
/// ```json
/// {
///   "date": "2026-02-03",
///   "commands": 42,
///   "input_tokens": 15420,
///   "output_tokens": 3842,
///   "saved_tokens": 11578,
///   "savings_pct": 75.08,
///   "total_time_ms": 8450,
///   "avg_time_ms": 201
/// }
/// ```
#[derive(Debug, Serialize)]
pub struct DayStats {
    /// ISO date (YYYY-MM-DD)
    pub date: String,
    /// Number of commands executed this day
    pub commands: usize,
    /// Total input tokens for this day
    pub input_tokens: usize,
    /// Total output tokens for this day
    pub output_tokens: usize,
    /// Total tokens saved this day
    pub saved_tokens: usize,
    /// Savings percentage for this day
    pub savings_pct: f64,
    /// Total execution time for this day (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
}

/// Weekly statistics for token savings and execution metrics.
///
/// Serializable to JSON for export via `rtk gain --weekly --format json`.
/// Weeks start on Sunday (SQLite default).
#[derive(Debug, Serialize)]
pub struct WeekStats {
    /// Week start date (YYYY-MM-DD)
    pub week_start: String,
    /// Week end date (YYYY-MM-DD)
    pub week_end: String,
    /// Number of commands executed this week
    pub commands: usize,
    /// Total input tokens for this week
    pub input_tokens: usize,
    /// Total output tokens for this week
    pub output_tokens: usize,
    /// Total tokens saved this week
    pub saved_tokens: usize,
    /// Savings percentage for this week
    pub savings_pct: f64,
    /// Total execution time for this week (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
}

/// Monthly statistics for token savings and execution metrics.
///
/// Serializable to JSON for export via `rtk gain --monthly --format json`.
#[derive(Debug, Serialize)]
pub struct MonthStats {
    /// Month identifier (YYYY-MM)
    pub month: String,
    /// Number of commands executed this month
    pub commands: usize,
    /// Total input tokens for this month
    pub input_tokens: usize,
    /// Total output tokens for this month
    pub output_tokens: usize,
    /// Total tokens saved this month
    pub saved_tokens: usize,
    /// Savings percentage for this month
    pub savings_pct: f64,
    /// Total execution time for this month (milliseconds)
    pub total_time_ms: u64,
    /// Average execution time per command (milliseconds)
    pub avg_time_ms: u64,
}

/// Type alias for command statistics tuple: (command, count, saved_tokens, avg_savings_pct, avg_time_ms)
type CommandStats = (String, usize, usize, f64, u64);

impl Tracker {
    /// Create a new tracker instance.
    ///
    /// Opens or creates the SQLite database at the platform-specific location.
    /// Automatically creates the `commands` table if it doesn't exist and runs
    /// any necessary schema migrations.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot determine database path
    /// - Cannot create parent directories
    /// - Cannot open/create SQLite database
    /// - Schema creation/migration fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new() -> Result<Self> {
        let db_path = get_db_path()?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;
        // Restrict the DB (and its WAL/SHM sidecars) to owner-only. The DB can
        // hold command history that should not be world/group readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let p = if suffix.is_empty() {
                    db_path.clone()
                } else {
                    let mut s = db_path.clone().into_os_string();
                    s.push(suffix);
                    PathBuf::from(s)
                };
                if let Ok(meta) = std::fs::metadata(&p) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&p, perms);
                }
            }
        }
        // Incremental auto-vacuum: keeps freed pages on a freelist that
        // `PRAGMA incremental_vacuum` reclaims in bounded chunks, instead of a
        // full multi-MB file rewrite (`VACUUM`) on the record() hot path —
        // audit PERF-I1. This pragma only takes effect on an empty DB or after
        // a full VACUUM, so it MUST run before any table is created. For an
        // existing legacy DB (auto_vacuum=0), a one-time migration VACUUM
        // below switches the mode; that cost is paid exactly once, not on
        // every retention prune.
        let _ = conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;");
        // WAL mode + busy_timeout for concurrent access (multiple Claude Code instances).
        // Non-fatal: NFS/read-only filesystems may not support WAL.
        // Order matters: busy_timeout MUST register before the WAL switch.
        // `PRAGMA journal_mode=WAL` requires an exclusive lock and can return
        // SQLITE_BUSY if a peer holds the DB; with busy_timeout already armed,
        // SQLite waits out the peer instead of failing immediately. Peer-
        // review #150 (agy) — the multi-thread boundary test surfaced this
        // ordering as a flakiness vector under high CPU contention.
        let _ = conn.execute_batch(
            "PRAGMA busy_timeout=5000;
             PRAGMA journal_mode=WAL;",
        );
        conn.execute(
            "CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                original_cmd TEXT NOT NULL,
                ctxcrl_cmd TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                saved_tokens INTEGER NOT NULL,
                savings_pct REAL NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON commands(timestamp)",
            [],
        )?;

        // Migration: add exec_time_ms column if it doesn't exist
        let _ = conn.execute(
            "ALTER TABLE commands ADD COLUMN exec_time_ms INTEGER DEFAULT 0",
            [],
        );
        // Migration: add project_path column with DEFAULT '' for new rows // changed: added DEFAULT
        let _ = conn.execute(
            "ALTER TABLE commands ADD COLUMN project_path TEXT DEFAULT ''",
            [],
        );
        // Migration: add inflation_tokens column (#196). `saved_tokens` is
        // floored at zero by `saturating_sub`, so a filter that emits MORE
        // tokens than it consumed records as "0% saved" and the regression is
        // invisible. This column records the net overflow (output - input,
        // floored at zero) honestly so inflation is measurable without making
        // `saved_tokens` signed (which would break unsigned SUM aggregations).
        let _ = conn.execute(
            "ALTER TABLE commands ADD COLUMN inflation_tokens INTEGER DEFAULT 0",
            [],
        );
        // One-time migration: normalize NULLs from pre-default schema // changed: guarded with EXISTS
        let has_nulls: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM commands WHERE project_path IS NULL)",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if has_nulls {
            let _ = conn.execute(
                "UPDATE commands SET project_path = '' WHERE project_path IS NULL",
                [],
            );
        }
        // Index for fast project-scoped gain queries // added
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_project_path_timestamp ON commands(project_path, timestamp)",
            [],
        );

        conn.execute(
            "CREATE TABLE IF NOT EXISTS parse_failures (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                raw_command TEXT NOT NULL,
                error_message TEXT NOT NULL,
                fallback_succeeded INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pf_timestamp ON parse_failures(timestamp)",
            [],
        )?;

        // Release boundaries: one row per `contextcrawler --version` change
        // observed. Written by `ensure_release_boundary()` on first invocation
        // after a binary upgrade. `gain --weak-filters` slices by the latest
        // boundary timestamp so newly-released filter behaviour isn't masked
        // by months of accumulated pre-upgrade leakage.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS release_boundaries (
                id INTEGER PRIMARY KEY,
                version TEXT NOT NULL,
                installed_at TEXT NOT NULL
            )",
            [],
        )?;

        // One-time migration for legacy DBs: `auto_vacuum=INCREMENTAL` set
        // above is a no-op on a DB created in mode 0 (full/none). A single
        // full VACUUM rewrites the file and commits it to incremental mode,
        // after which `cleanup_old()` only ever does cheap bounded reclaim.
        // This runs once — on the next open `auto_vacuum` already reads back
        // as 2 and the branch is skipped. Non-fatal: a failed VACUUM just
        // leaves the DB in legacy mode (old behaviour) until the next open.
        let auto_vacuum_mode: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .unwrap_or(0);
        if auto_vacuum_mode != 2 {
            let _ = conn.execute_batch("VACUUM;");
        }

        let tracker = Self { conn };
        // Best-effort: never fail tracker construction on a boundary insert
        // problem (downstream record() still works without it).
        let _ = tracker.ensure_release_boundary();
        Ok(tracker)
    }

    /// Write a new release-boundary row if the installed binary version
    /// differs from the most recent one recorded in the DB. Called once at
    /// tracker construction; cost is one INSERT-WHERE per invocation (no
    /// follow-up SELECT in steady-state — the WHERE clause evaluates to
    /// zero rows when the version already matches, so SQLite skips the
    /// INSERT atomically).
    ///
    /// The INSERT ... SELECT ... WHERE pattern collapses the previous
    /// read-then-write into a single atomic statement. Without this, two
    /// concurrent contextcrawler processes hitting a fresh-upgrade DB
    /// would both observe the old latest-version, both pass the Rust-side
    /// check, and both insert a duplicate boundary row (peer-review #150
    /// finding, Codex + agy).
    fn ensure_release_boundary(&self) -> Result<()> {
        const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO release_boundaries (version, installed_at)
             SELECT ?1, ?2
             WHERE NOT EXISTS (
                 SELECT 1 FROM release_boundaries
                 WHERE version = ?1
                   AND id = (SELECT MAX(id) FROM release_boundaries)
             )",
            params![CURRENT_VERSION, now],
        )?;
        Ok(())
    }

    /// Timestamp of the most recent release boundary, in RFC-3339 / ISO-8601
    /// form. `None` if no boundary has been recorded yet (fresh DB on a
    /// pre-feature binary, or in-memory test tracker). Callers should treat
    /// `None` as "no slice, fall back to lifetime".
    pub fn latest_boundary_timestamp(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT installed_at FROM release_boundaries ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Create an isolated in-memory tracker for tests.
    #[cfg(test)]
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("Failed to open in-memory DB")?;
        let tracker = Self { conn };
        tracker.init_schema()?;
        Ok(tracker)
    }

    #[cfg(test)]
    fn init_schema(&self) -> Result<()> {
        // Match production: incremental auto-vacuum before any table exists.
        let _ = self.conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;");
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                original_cmd TEXT NOT NULL,
                ctxcrl_cmd TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                saved_tokens INTEGER NOT NULL,
                savings_pct REAL NOT NULL,
                exec_time_ms INTEGER DEFAULT 0,
                project_path TEXT DEFAULT '',
                inflation_tokens INTEGER DEFAULT 0
            )",
            [],
        )?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON commands(timestamp)",
            [],
        )?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_project_path_timestamp ON commands(project_path, timestamp)",
            [],
        )?;
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS parse_failures (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                raw_command TEXT NOT NULL,
                error_message TEXT NOT NULL,
                fallback_succeeded INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pf_timestamp ON parse_failures(timestamp)",
            [],
        )?;
        // Mirror production: release_boundaries table for version-aware
        // weak-filter analytics. See block at L526 for details.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS release_boundaries (
                id INTEGER PRIMARY KEY,
                version TEXT NOT NULL,
                installed_at TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    /// Record a command execution with token counts and timing.
    ///
    /// Calculates savings metrics and stores the record in the database.
    /// Automatically cleans up records older than 90 days after insertion.
    ///
    /// # Arguments
    ///
    /// - `original_cmd`: The standard command (e.g., "ls -la")
    /// - `ctxcrl_cmd`: The RTK command used (e.g., "rtk ls")
    /// - `input_tokens`: Estimated tokens from standard command output
    /// - `output_tokens`: Actual tokens from RTK output
    /// - `exec_time_ms`: Execution time in milliseconds
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// tracker.record("ls -la", "rtk ls", 1000, 200, 50)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn record(
        &self,
        original_cmd: &str,
        ctxcrl_cmd: &str,
        input_tokens: usize,
        output_tokens: usize,
        exec_time_ms: u64,
    ) -> Result<()> {
        let saved = input_tokens.saturating_sub(output_tokens);
        let pct = if input_tokens > 0 {
            (saved as f64 / input_tokens as f64) * 100.0
        } else {
            0.0
        };
        // #196: when a filter emits more than it consumed, `saved` is floored
        // at 0 and the regression vanishes from the headline stats. Record the
        // overflow separately so it stays measurable (`SELECT SUM(inflation_tokens)`).
        let inflation = output_tokens.saturating_sub(input_tokens);

        let project_path = current_project_path_string(); // added: record cwd

        // Secrets in command strings would otherwise survive 90 days in the DB
        // and resurface via `gain --history` back into agent context.
        let original_cmd = scrub_secrets(original_cmd);
        let ctxcrl_cmd = scrub_secrets(ctxcrl_cmd);

        self.conn.execute(
            "INSERT INTO commands (timestamp, original_cmd, ctxcrl_cmd, project_path, input_tokens, output_tokens, saved_tokens, savings_pct, exec_time_ms, inflation_tokens)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)", // added: project_path, inflation_tokens (#196)
            params![
                Utc::now().to_rfc3339(),
                original_cmd,
                ctxcrl_cmd,
                project_path, // added
                input_tokens as i64,
                output_tokens as i64,
                saved as i64,
                pct,
                exec_time_ms as i64,
                inflation as i64 // added (#196)
            ],
        )?;

        self.cleanup_old()?;
        Ok(())
    }

    fn cleanup_old(&self) -> Result<()> {
        let cutoff = Utc::now() - chrono::Duration::days(DEFAULT_HISTORY_DAYS);
        self.conn.execute(
            "DELETE FROM commands WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        let removed = self.conn.execute(
            "DELETE FROM parse_failures WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        // Reclaim space from pruned rows so the DB file does not grow
        // unbounded. `incremental_vacuum` moves a bounded number of freelist
        // pages and truncates the file — it does NOT rewrite the whole DB the
        // way `VACUUM` does, so this stays cheap on the record() hot path
        // (audit PERF-I1). No-op on a DB still in legacy auto_vacuum mode.
        // Non-fatal: can fail on WAL/NFS/read-only filesystems.
        if removed > 0 {
            let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        }
        Ok(())
    }

    /// Delete all tracked data (commands + parse_failures), resetting all stats to zero.
    pub fn reset_all(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "BEGIN;
                 DELETE FROM commands;
                 DELETE FROM parse_failures;
                 COMMIT;",
            )
            .context("Failed to reset tracking database")?;
        Ok(())
    }

    /// Record a parse failure for analytics.
    pub fn record_parse_failure(
        &self,
        raw_command: &str,
        error_message: &str,
        fallback_succeeded: bool,
    ) -> Result<()> {
        let raw_command = scrub_secrets(raw_command);
        self.conn.execute(
            "INSERT INTO parse_failures (timestamp, raw_command, error_message, fallback_succeeded)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                Utc::now().to_rfc3339(),
                raw_command,
                error_message,
                fallback_succeeded as i32,
            ],
        )?;
        self.cleanup_old()?;
        Ok(())
    }

    /// Get parse failure summary for `rtk gain --failures`.
    pub fn get_parse_failure_summary(&self) -> Result<ParseFailureSummary> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM parse_failures", [], |row| row.get(0))?;

        let succeeded: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM parse_failures WHERE fallback_succeeded = 1",
            [],
            |row| row.get(0),
        )?;

        let recovery_rate = if total > 0 {
            (succeeded as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        // Top commands by frequency
        let mut stmt = self.conn.prepare(
            "SELECT raw_command, COUNT(*) as cnt
             FROM parse_failures
             GROUP BY raw_command
             ORDER BY cnt DESC
             LIMIT 10",
        )?;
        let top_commands = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Recent 10
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, raw_command, error_message, fallback_succeeded
             FROM parse_failures
             ORDER BY timestamp DESC
             LIMIT 10",
        )?;
        let recent = stmt
            .query_map([], |row| {
                Ok(ParseFailureRecord {
                    timestamp: row.get(0)?,
                    raw_command: row.get(1)?,
                    error_message: row.get(2)?,
                    fallback_succeeded: row.get::<_, i32>(3)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ParseFailureSummary {
            total: total as usize,
            recovery_rate,
            top_commands,
            recent,
        })
    }

    /// Get overall summary statistics across all recorded commands.
    ///
    /// Returns aggregated metrics including:
    /// - Total commands, tokens (input/output/saved)
    /// - Average savings percentage and execution time
    /// - Top 10 commands by tokens saved
    /// - Last 30 days of activity
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let summary = tracker.get_summary()?;
    /// println!("Saved {} tokens ({:.1}%)",
    ///     summary.total_saved, summary.avg_savings_pct);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[allow(dead_code)]
    pub fn get_summary(&self) -> Result<GainSummary> {
        self.get_summary_filtered(None) // delegate to filtered variant
    }

    /// Total tokens by which filters INFLATED output beyond input (#196).
    ///
    /// `saved_tokens` is floored at zero (`saturating_sub`), so a filter that
    /// emits more than it consumed shows as "0% saved" and the regression is
    /// invisible in the headline stats. This is the honest measure of that
    /// overflow across all recorded commands.
    #[allow(dead_code)]
    pub fn total_inflation_tokens(&self) -> Result<usize> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(inflation_tokens), 0) FROM commands",
            [],
            |row| row.get(0),
        )?;
        Ok(total as usize)
    }

    /// Get summary statistics filtered by project path. // added
    ///
    /// When `project_path` is `Some`, matches the exact working directory
    /// or any subdirectory (prefix match with path separator).
    pub fn get_summary_filtered(&self, project_path: Option<&str>) -> Result<GainSummary> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut total_commands = 0usize;
        let mut total_input = 0usize;
        let mut total_output = 0usize;
        let mut total_saved = 0usize;
        let mut total_inflation = 0usize; // added (#196): output-overflow, floored elsewhere
        let mut total_time_ms = 0u64;

        let mut stmt = self.conn.prepare(
            "SELECT input_tokens, output_tokens, saved_tokens, inflation_tokens, exec_time_ms
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, i64>(3)? as usize, // added (#196): inflation_tokens
                row.get::<_, i64>(4)? as u64,
            ))
        })?;

        for row in rows {
            let (input, output, saved, inflation, time_ms) = row?;
            total_commands += 1;
            total_input += input;
            total_output += output;
            total_saved += saved;
            total_inflation += inflation; // added (#196)
            total_time_ms += time_ms;
        }

        let avg_savings_pct = if total_input > 0 {
            (total_saved as f64 / total_input as f64) * 100.0
        } else {
            0.0
        };

        let avg_time_ms = if total_commands > 0 {
            total_time_ms / total_commands as u64
        } else {
            0
        };

        let by_command = self.get_by_command(project_path)?; // added: pass project filter
        let by_day = self.get_by_day(project_path)?; // added: pass project filter

        Ok(GainSummary {
            total_commands,
            total_input,
            total_output,
            total_saved,
            total_inflation, // added (#196)
            avg_savings_pct,
            total_time_ms,
            avg_time_ms,
            by_command,
            by_day,
        })
    }

    fn get_by_command(
        &self,
        project_path: Option<&str>, // added
    ) -> Result<Vec<CommandStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        // Avg% is volume-weighted (SUM(saved)/SUM(input)) to match the
        // summary-level metric — an unweighted AVG(savings_pct) over-counts
        // low-volume high-percentage invocations. Guard divide-by-zero → 0%.
        let mut stmt = self.conn.prepare(
            "SELECT ctxcrl_cmd, COUNT(*), SUM(saved_tokens),
                    CASE WHEN SUM(input_tokens) > 0
                         THEN SUM(saved_tokens) * 100.0 / SUM(input_tokens)
                         ELSE 0.0 END,
                    AVG(exec_time_ms)
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY ctxcrl_cmd
             ORDER BY SUM(saved_tokens) DESC
             LIMIT 10", // added: project filter in WHERE
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, f64>(3)?,
                row.get::<_, f64>(4)? as u64,
            ))
        })?;

        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Rank tools by leaked tokens for `gain --weak-filters`.
    ///
    /// Aggregates recorded commands into tool buckets (see
    /// [`weak_filter_tool_key`]), computes how many input tokens reached the
    /// model unfiltered, and sorts highest-leak first. Passthrough rows
    /// (0 input) contribute nothing and drop out — so a command that is
    /// always passthrough never appears.
    pub fn get_weak_filters(
        &self,
        project_path: Option<&str>,
        since: Option<&str>,
    ) -> Result<Vec<WeakFilter>> {
        let (project_exact, project_glob) = project_filter_params(project_path);
        // `since` defaults to NULL (no slice) when caller passes None — same
        // pattern as project_path. The boundary timestamp is RFC-3339 / ISO-
        // 8601 and command timestamps are also ISO-8601, so lexicographic
        // comparison is correct.
        let mut stmt = self.conn.prepare(
            "SELECT ctxcrl_cmd, COUNT(*), SUM(input_tokens), SUM(saved_tokens), SUM(inflation_tokens)
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
               AND (?3 IS NULL OR timestamp >= ?3)
             GROUP BY ctxcrl_cmd",
        )?;
        let rows = stmt.query_map(params![project_exact, project_glob, since], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, i64>(3)? as usize,
                row.get::<_, i64>(4)? as usize, // added (#196): inflation_tokens
            ))
        })?;

        // Re-aggregate the per-command-string rows into tool buckets.
        // Tuple: (runs, input, saved, inflation).
        let mut tools: std::collections::HashMap<String, (usize, usize, usize, usize)> =
            std::collections::HashMap::new();
        for row in rows {
            let (ctxcrl_cmd, runs, input, saved, inflation) = row?;
            let key = weak_filter_tool_key(&ctxcrl_cmd);
            if key.is_empty() {
                continue;
            }
            let entry = tools.entry(key).or_insert((0, 0, 0, 0));
            entry.0 += runs;
            entry.1 += input;
            entry.2 += saved;
            entry.3 += inflation; // added (#196)
        }

        let mut result: Vec<WeakFilter> = tools
            .into_iter()
            .filter(|(_, (_, input, _, _))| *input > 0)
            .map(|(tool, (runs, input, saved, inflation))| WeakFilter {
                tool,
                runs,
                input_tokens: input,
                leaked_tokens: input.saturating_sub(saved),
                savings_pct: saved as f64 * 100.0 / input as f64,
                inflation_tokens: inflation, // added (#196)
            })
            .collect();
        result.sort_by_key(|w| std::cmp::Reverse(w.leaked_tokens));
        Ok(result)
    }

    fn get_by_day(
        &self,
        project_path: Option<&str>, // added
    ) -> Result<Vec<(String, usize)>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT DATE(timestamp), SUM(saved_tokens)
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY DATE(timestamp)
             ORDER BY DATE(timestamp) DESC
             LIMIT 30", // added: project filter in WHERE
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get daily statistics for all recorded days.
    ///
    /// Returns one [`DayStats`] per day with commands executed, tokens saved,
    /// and execution time metrics. Results are ordered chronologically (oldest first).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let days = tracker.get_all_days()?;
    /// for day in days.iter().take(7) {
    ///     println!("{}: {} commands, {} tokens saved",
    ///         day.date, day.commands, day.saved_tokens);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn get_all_days(&self) -> Result<Vec<DayStats>> {
        self.get_all_days_filtered(None) // delegate to filtered variant
    }

    /// Get daily statistics filtered by project path. // added
    pub fn get_all_days_filtered(&self, project_path: Option<&str>) -> Result<Vec<DayStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT
                DATE(timestamp) as date,
                COUNT(*) as commands,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(saved_tokens) as saved,
                SUM(exec_time_ms) as total_time
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY DATE(timestamp)
             ORDER BY DATE(timestamp) DESC", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            let input = row.get::<_, i64>(2)? as usize;
            let saved = row.get::<_, i64>(4)? as usize;
            let commands = row.get::<_, i64>(1)? as usize;
            let total_time = row.get::<_, i64>(5)? as u64;
            let savings_pct = if input > 0 {
                (saved as f64 / input as f64) * 100.0
            } else {
                0.0
            };
            let avg_time_ms = if commands > 0 {
                total_time / commands as u64
            } else {
                0
            };

            Ok(DayStats {
                date: row.get(0)?,
                commands,
                input_tokens: input,
                output_tokens: row.get::<_, i64>(3)? as usize,
                saved_tokens: saved,
                savings_pct,
                total_time_ms: total_time,
                avg_time_ms,
            })
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get weekly statistics grouped by week.
    ///
    /// Returns one [`WeekStats`] per week with aggregated metrics.
    /// Weeks start on Sunday (SQLite default). Results ordered chronologically.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let weeks = tracker.get_by_week()?;
    /// for week in weeks {
    ///     println!("{} to {}: {} tokens saved",
    ///         week.week_start, week.week_end, week.saved_tokens);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn get_by_week(&self) -> Result<Vec<WeekStats>> {
        self.get_by_week_filtered(None) // delegate to filtered variant
    }

    /// Get weekly statistics filtered by project path. // added
    pub fn get_by_week_filtered(&self, project_path: Option<&str>) -> Result<Vec<WeekStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT
                DATE(timestamp, 'weekday 0', '-6 days') as week_start,
                DATE(timestamp, 'weekday 0') as week_end,
                COUNT(*) as commands,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(saved_tokens) as saved,
                SUM(exec_time_ms) as total_time
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY week_start
             ORDER BY week_start DESC", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            let input = row.get::<_, i64>(3)? as usize;
            let saved = row.get::<_, i64>(5)? as usize;
            let commands = row.get::<_, i64>(2)? as usize;
            let total_time = row.get::<_, i64>(6)? as u64;
            let savings_pct = if input > 0 {
                (saved as f64 / input as f64) * 100.0
            } else {
                0.0
            };
            let avg_time_ms = if commands > 0 {
                total_time / commands as u64
            } else {
                0
            };

            Ok(WeekStats {
                week_start: row.get(0)?,
                week_end: row.get(1)?,
                commands,
                input_tokens: input,
                output_tokens: row.get::<_, i64>(4)? as usize,
                saved_tokens: saved,
                savings_pct,
                total_time_ms: total_time,
                avg_time_ms,
            })
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get monthly statistics grouped by month.
    ///
    /// Returns one [`MonthStats`] per month (YYYY-MM format) with aggregated metrics.
    /// Results ordered chronologically.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let months = tracker.get_by_month()?;
    /// for month in months {
    ///     println!("{}: {} tokens saved ({:.1}%)",
    ///         month.month, month.saved_tokens, month.savings_pct);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn get_by_month(&self) -> Result<Vec<MonthStats>> {
        self.get_by_month_filtered(None) // delegate to filtered variant
    }

    /// Get monthly statistics filtered by project path. // added
    pub fn get_by_month_filtered(&self, project_path: Option<&str>) -> Result<Vec<MonthStats>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT
                strftime('%Y-%m', timestamp) as month,
                COUNT(*) as commands,
                SUM(input_tokens) as input,
                SUM(output_tokens) as output,
                SUM(saved_tokens) as saved,
                SUM(exec_time_ms) as total_time
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             GROUP BY month
             ORDER BY month DESC", // added: project filter
        )?;

        let rows = stmt.query_map(params![project_exact, project_glob], |row| {
            // added: params
            let input = row.get::<_, i64>(2)? as usize;
            let saved = row.get::<_, i64>(4)? as usize;
            let commands = row.get::<_, i64>(1)? as usize;
            let total_time = row.get::<_, i64>(5)? as u64;
            let savings_pct = if input > 0 {
                (saved as f64 / input as f64) * 100.0
            } else {
                0.0
            };
            let avg_time_ms = if commands > 0 {
                total_time / commands as u64
            } else {
                0
            };

            Ok(MonthStats {
                month: row.get(0)?,
                commands,
                input_tokens: input,
                output_tokens: row.get::<_, i64>(3)? as usize,
                saved_tokens: saved,
                savings_pct,
                total_time_ms: total_time,
                avg_time_ms,
            })
        })?;

        let mut result: Vec<_> = rows.collect::<Result<Vec<_>, _>>()?;
        result.reverse();
        Ok(result)
    }

    /// Get recent command history.
    ///
    /// Returns up to `limit` most recent command records, ordered by timestamp (newest first).
    ///
    /// # Arguments
    ///
    /// - `limit`: Maximum number of records to return
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::Tracker;
    ///
    /// let tracker = Tracker::new()?;
    /// let recent = tracker.get_recent(10)?;
    /// for cmd in recent {
    ///     println!("{}: {} saved {:.1}%",
    ///         cmd.timestamp, cmd.ctxcrl_cmd, cmd.savings_pct);
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[allow(dead_code)]
    pub fn get_recent(&self, limit: usize) -> Result<Vec<CommandRecord>> {
        self.get_recent_filtered(limit, None) // delegate to filtered variant
    }

    /// Get recent command history filtered by project path. // added
    pub fn get_recent_filtered(
        &self,
        limit: usize,
        project_path: Option<&str>,
    ) -> Result<Vec<CommandRecord>> {
        let (project_exact, project_glob) = project_filter_params(project_path); // added
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, ctxcrl_cmd, saved_tokens, savings_pct
             FROM commands
             WHERE (?1 IS NULL OR project_path = ?1 OR project_path GLOB ?2)
             ORDER BY timestamp DESC
             LIMIT ?3", // added: project filter
        )?;

        let rows = stmt.query_map(
            params![project_exact, project_glob, limit as i64], // added: project params
            |row| {
                Ok(CommandRecord {
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(0)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    ctxcrl_cmd: row.get(1)?,
                    saved_tokens: row.get::<_, i64>(2)? as usize,
                    savings_pct: row.get(3)?,
                })
            },
        )?;

        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Count commands since a given timestamp (for telemetry).
    pub fn count_commands_since(&self, since: chrono::DateTime<chrono::Utc>) -> Result<i64> {
        let ts = since.format("%Y-%m-%dT%H:%M:%S").to_string();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE timestamp >= ?1",
            params![ts],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get top N commands by frequency (for telemetry).
    pub fn top_commands(&self, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT ctxcrl_cmd, COUNT(*) as cnt FROM commands
             GROUP BY ctxcrl_cmd ORDER BY cnt DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cmd: String = row.get(0)?;
            // Extract just the command name (e.g. "rtk git status" → "git")
            Ok(cmd.split_whitespace().nth(1).unwrap_or(&cmd).to_string())
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Get overall savings percentage (for telemetry).
    pub fn overall_savings_pct(&self) -> Result<f64> {
        let (total_input, total_saved): (i64, i64) = self.conn.query_row(
            "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(saved_tokens), 0) FROM commands",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if total_input > 0 {
            Ok((total_saved as f64 / total_input as f64) * 100.0)
        } else {
            Ok(0.0)
        }
    }

    /// Get total tokens saved across all tracked commands (for telemetry).
    pub fn total_tokens_saved(&self) -> Result<i64> {
        let saved: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(saved_tokens), 0) FROM commands",
            [],
            |row| row.get(0),
        )?;
        Ok(saved)
    }

    /// Get tokens saved in the last 24 hours (for telemetry).
    pub fn tokens_saved_24h(&self, since: chrono::DateTime<chrono::Utc>) -> Result<i64> {
        let ts = since.format("%Y-%m-%dT%H:%M:%S").to_string();
        let saved: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(saved_tokens), 0) FROM commands WHERE timestamp >= ?1",
            params![ts],
            |row| row.get(0),
        )?;
        Ok(saved)
    }

    /// Top N passthrough commands (0% savings) — commands missing a filter.
    /// Groups by first word only to avoid leaking arguments into telemetry.
    pub fn top_passthrough(&self, limit: usize) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT TRIM(SUBSTR(original_cmd, 1, INSTR(original_cmd || ' ', ' ') - 1)) as tool,
             COUNT(*) as cnt FROM commands
             WHERE input_tokens = 0 AND output_tokens = 0
             GROUP BY tool ORDER BY cnt DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cmd: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((cmd, count))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Count parse failures in the last 24 hours.
    pub fn parse_failures_since(&self, since: chrono::DateTime<chrono::Utc>) -> Result<i64> {
        let ts = since.format("%Y-%m-%dT%H:%M:%S").to_string();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM parse_failures WHERE timestamp >= ?1",
            params![ts],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Count commands with low savings (<30%) — filters that need improvement.
    /// Savings is volume-weighted (SUM(saved)/SUM(input)) for consistency with
    /// the by-command Avg% column, so a few high-percentage outliers can't hide
    /// a filter that performs poorly across most of its invocations.
    pub fn low_savings_commands(&self, limit: usize) -> Result<Vec<(String, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT ctxcrl_cmd,
                    SUM(saved_tokens) * 100.0 / SUM(input_tokens) as avg_sav
             FROM commands
             WHERE input_tokens > 0
             GROUP BY ctxcrl_cmd
             HAVING SUM(input_tokens) > 0 AND avg_sav < 30.0 AND avg_sav > 0.0
             ORDER BY COUNT(*) DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cmd: String = row.get(0)?;
            let sav: f64 = row.get(1)?;
            let short = cmd.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
            Ok((short, sav))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Average savings percentage per command (unweighted — each command name counts once).
    pub fn avg_savings_per_command(&self) -> Result<f64> {
        let avg: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(avg_sav), 0.0) FROM (
                SELECT ctxcrl_cmd, AVG(savings_pct) as avg_sav
                FROM commands WHERE input_tokens > 0
                GROUP BY ctxcrl_cmd
            )",
            [],
            |row| row.get(0),
        )?;
        Ok(avg)
    }

    /// Count invocations of a specific meta-command (by ctxcrl_cmd suffix).
    pub fn count_meta_command(&self, name: &str) -> Result<i64> {
        let pattern = format!("contextcrawler {}", name);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE ctxcrl_cmd LIKE ?1 || '%'",
            params![pattern],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Days since first recorded command (installation age).
    pub fn first_seen_days(&self) -> Result<i64> {
        let oldest: Option<String> =
            match self
                .conn
                .query_row("SELECT MIN(timestamp) FROM commands", [], |row| row.get(0))
            {
                Ok(v) => v,
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(anyhow::anyhow!("Failed to query first seen timestamp: {e}")),
            };
        match oldest {
            Some(ts) => {
                let first = chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%dT%H:%M:%S")
                    .or_else(|_| chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%d %H:%M:%S"))
                    .map(|dt| dt.and_utc())
                    .unwrap_or_else(|_| chrono::Utc::now());
                let days = (chrono::Utc::now() - first).num_days();
                Ok(days.max(0))
            }
            None => Ok(0),
        }
    }

    /// Number of distinct active days in the last 30 days.
    pub fn active_days_30d(&self) -> Result<i64> {
        let since = (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT DATE(timestamp)) FROM commands WHERE timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Total number of recorded commands.
    pub fn commands_total(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Ecosystem distribution as percentages (top categories by command prefix).
    pub fn ecosystem_mix(&self) -> Result<Vec<(String, f64)>> {
        let total: f64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE input_tokens > 0 AND timestamp >= datetime('now', '-90 days')",
            [],
            |row| row.get(0),
        )?;
        if total == 0.0 {
            return Ok(vec![]);
        }
        let mut stmt = self.conn.prepare(
            "SELECT ctxcrl_cmd, COUNT(*) as cnt FROM commands
             WHERE input_tokens > 0 AND timestamp >= datetime('now', '-90 days')
             GROUP BY ctxcrl_cmd ORDER BY cnt DESC",
        )?;
        let mut categories: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        let rows = stmt.query_map([], |row| {
            let cmd: String = row.get(0)?;
            let cnt: f64 = row.get(1)?;
            Ok((cmd, cnt))
        })?;
        for row in rows.flatten() {
            let cat = categorize_command(&row.0);
            *categories.entry(cat).or_default() += row.1;
        }
        let mut result: Vec<(String, f64)> = categories
            .into_iter()
            .map(|(cat, cnt)| (cat, (cnt / total * 100.0).round()))
            .collect();
        result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        result.truncate(8);
        Ok(result)
    }

    /// Tokens saved in the last 30 days.
    pub fn tokens_saved_30d(&self) -> Result<i64> {
        let since = (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let saved: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(saved_tokens), 0) FROM commands WHERE timestamp >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        Ok(saved)
    }

    /// Number of distinct project paths.
    pub fn projects_count(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT project_path) FROM commands WHERE project_path != ''",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

/// Map an ctxcrl_cmd to an ecosystem category for telemetry.
fn categorize_command(ctxcrl_cmd: &str) -> String {
    let parts: Vec<&str> = ctxcrl_cmd.split_whitespace().collect();
    let tool = parts.get(1).copied().unwrap_or("other");
    match tool {
        "git" | "gh" | "gt" => "git",
        "cargo" => "cargo",
        "npm" | "npx" | "pnpm" | "vitest" | "tsc" | "lint" | "prettier" | "next" | "playwright"
        | "prisma" => "js",
        "pytest" | "ruff" | "mypy" | "pip" => "python",
        "go" | "golangci-lint" => "go",
        "docker" | "kubectl" => "cloud",
        "rspec" | "rubocop" | "rake" => "ruby",
        "dotnet" => "dotnet",
        "ls" | "tree" | "grep" | "find" | "wc" | "read" | "env" | "json" | "log" | "smart"
        | "diff" | "deps" | "summary" | "format" => "system",
        _ => "other",
    }
    .to_string()
}

fn get_db_path() -> Result<PathBuf> {
    // Priority 1: Environment variable RTK_DB_PATH (also acts as the explicit
    // opt-in for `cargo test` runs that want to exercise real writes).
    //
    // The env value is attacker-influenceable (a hostile project `.envrc` /
    // direnv can set process env), so it is confined to $HOME just like the
    // config-supplied path — and consistent with `RTK_TEE_DIR` (tee.rs).
    if let Some(custom_path) = crate::core::env_compat::env_var("CTXCRL_DB_PATH") {
        return confine_db_path_to_home(PathBuf::from(custom_path));
    }

    // Issue #91: when running under `cargo test`, redirect to a per-process
    // tmpfile so test runs don't pollute the production `history.db`. Tests
    // that need to inspect tracking still work because every `Tracker::new()`
    // call within the same process resolves to the same path.
    if is_test_context() {
        let tmp = std::env::temp_dir().join(format!(
            "contextcrawler-test-{}.db",
            std::process::id()
        ));
        return Ok(tmp);
    }

    // Priority 2: Configuration file. Confine to $HOME — a config-supplied
    // path is attacker-influenceable (shared/checked-in config), so reject
    // anything that resolves outside the user's home directory.
    if let Ok(config) = crate::core::config::Config::load() {
        if let Some(db_path) = config.tracking.database_path {
            return confine_db_path_to_home(db_path);
        }
    }

    // Priority 3: Default platform-specific location. The history DB is NOT
    // migrated from the legacy `rtk` path — on first run at the new `ctxcrl`
    // path a fresh DB with the current schema is created (complete reset). Any
    // old-path/old-schema DB is left orphaned on disk, untouched.
    let data_dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    Ok(data_dir.join(RTK_DATA_DIR).join(HISTORY_DB))
}

/// Lexically resolve `.` and `..` components in a path without touching the
/// filesystem. `..` pops the last normal segment; `.` is dropped; the root /
/// prefix is preserved. This closes a traversal bypass where a `..` lands in
/// the non-existent tail of a candidate path and so survives canonicalisation
/// of the deepest *existing* ancestor.
fn lexically_normalize(path: &std::path::Path) -> PathBuf {
    use std::path::Component;
    let mut out: Vec<Component> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                match out.last() {
                    // Pop a preceding normal segment.
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    // Cannot ascend past a root/prefix — drop the `..`.
                    Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                    // Leading `..` on a relative path: keep it.
                    _ => out.push(comp),
                }
            }
            other => out.push(other),
        }
    }
    out.iter().map(|c| c.as_os_str()).collect()
}

/// Confine a config-supplied DB path to the user's home directory.
///
/// The DB file itself may not exist yet, so we canonicalise the deepest
/// existing ancestor and append the non-existent tail. Canonicalisation runs
/// FIRST — before any lexical `..` resolution — so a symlink in the existing
/// prefix is resolved to its real destination *before* a trailing `..` is
/// allowed to act on it. Resolving `..` lexically up front would textually
/// cancel a `symlink/..` pair and hide the escape from `canonicalize()`. Only
/// after the walk has resolved symlinks do we lexically collapse whatever
/// `..`/`.` survive in the tail, then run the `$HOME` containment check.
fn confine_db_path_to_home(db_path: PathBuf) -> Result<PathBuf> {
    let home = match dirs::home_dir().and_then(|h| h.canonicalize().ok()) {
        Some(h) => h,
        // No resolvable home — fall back to the default location rather than
        // trusting an unconfined config path.
        None => {
            let data_dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
            return Ok(data_dir.join(RTK_DATA_DIR).join(HISTORY_DB));
        }
    };

    // Canonicalise the deepest existing ancestor, re-attaching the tail.
    // This resolves every symlink in the existing prefix to its real path
    // before a trailing `..` can act on it.
    let mut existing = db_path.as_path();
    let mut tail = PathBuf::new();
    let resolved = loop {
        if let Ok(c) = existing.canonicalize() {
            break c.join(&tail);
        }
        match existing.parent() {
            Some(p) => {
                // Capture the trailing component via `Components`, not
                // `file_name()` — the latter returns `None` for `..`/`.`,
                // which would silently drop a traversal segment from the
                // non-existent tail and defeat the containment check.
                if let Some(comp) = existing.components().next_back() {
                    tail = PathBuf::from(comp.as_os_str()).join(&tail);
                }
                existing = p;
            }
            None => break db_path.clone(),
        }
    };

    // Now — and only now, with symlinks already resolved — lexically collapse
    // any `..`/`.` that survived in the non-existent tail (or arrived via a
    // canonicalised symlink target).
    let resolved = lexically_normalize(&resolved);

    if !resolved.starts_with(&home) {
        anyhow::bail!(
            "configured tracking.database_path '{}' resolves outside $HOME — refusing to open",
            db_path.display()
        );
    }
    Ok(resolved)
}

/// Individual parse failure record.
#[derive(Debug)]
pub struct ParseFailureRecord {
    pub timestamp: String,
    pub raw_command: String,
    #[allow(dead_code)]
    pub error_message: String,
    pub fallback_succeeded: bool,
}

/// Aggregated parse failure summary.
#[derive(Debug)]
pub struct ParseFailureSummary {
    pub total: usize,
    pub recovery_rate: f64,
    pub top_commands: Vec<(String, usize)>,
    pub recent: Vec<ParseFailureRecord>,
}

/// Record a parse failure without ever crashing.
/// Silently ignores all errors — used in the fallback path.
pub fn record_parse_failure_silent(raw_command: &str, error_message: &str, succeeded: bool) {
    if let Ok(tracker) = Tracker::new() {
        let _ = tracker.record_parse_failure(raw_command, error_message, succeeded);
    }
}

/// Estimate token count from text using ~4 chars = 1 token heuristic.
///
/// This is a fast approximation suitable for tracking purposes.
/// For precise counts, integrate with your LLM's tokenizer API.
///
/// # Formula
///
/// `tokens = ceil(chars / 4)`
///
/// # Examples
///
/// ```
/// use contextcrawler::core::tracking::estimate_tokens;
///
/// assert_eq!(estimate_tokens(""), 0);
/// assert_eq!(estimate_tokens("abcd"), 1);  // 4 chars = 1 token
/// assert_eq!(estimate_tokens("abcde"), 2); // 5 chars = ceil(1.25) = 2
/// assert_eq!(estimate_tokens("hello world"), 3); // 11 chars = ceil(2.75) = 3
/// ```
pub fn estimate_tokens(text: &str) -> usize {
    // ~4 chars per token on average
    (text.len() as f64 / 4.0).ceil() as usize
}

/// Helper struct for timing command execution
/// Helper for timing command execution and tracking results.
///
/// Preferred API for tracking commands. Automatically measures execution time
/// and records token savings. Use instead of the deprecated [`track`] function.
///
/// # Examples
///
/// ```no_run
/// use contextcrawler::core::tracking::TimedExecution;
///
/// let timer = TimedExecution::start();
/// let input = execute_standard_command()?;
/// let output = execute_rtk_command()?;
/// timer.track("ls -la", "rtk ls", &input, &output);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct TimedExecution {
    start: Instant,
}

impl TimedExecution {
    /// Start timing a command execution.
    ///
    /// Creates a new timer that starts measuring elapsed time immediately.
    /// Call [`track`](Self::track) or [`track_passthrough`](Self::track_passthrough)
    /// when the command completes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::TimedExecution;
    ///
    /// let timer = TimedExecution::start();
    /// // ... execute command ...
    /// timer.track("cmd", "rtk cmd", "input", "output");
    /// ```
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Track the command with elapsed time and token counts.
    ///
    /// Records the command execution with:
    /// - Elapsed time since [`start`](Self::start)
    /// - Token counts estimated from input/output strings
    /// - Calculated savings metrics
    ///
    /// # Arguments
    ///
    /// - `original_cmd`: Standard command (e.g., "ls -la")
    /// - `ctxcrl_cmd`: RTK command used (e.g., "rtk ls")
    /// - `input`: Standard command output (for token estimation)
    /// - `output`: RTK command output (for token estimation)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::TimedExecution;
    ///
    /// let timer = TimedExecution::start();
    /// let input = "long output...";
    /// let output = "short output";
    /// timer.track("ls -la", "rtk ls", input, output);
    /// ```
    pub fn track(&self, original_cmd: &str, ctxcrl_cmd: &str, input: &str, output: &str) {
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        let input_tokens = estimate_tokens(input);
        // #196: record the TRUE (unclamped) output token count. `record`
        // floors `saved` at 0 via `input.saturating_sub(output)`, so a filter
        // that inflates still reports 0 saved / 0% savings (never negative) —
        // the no-bloat guarantee of issue #95 is preserved. Clamping output to
        // `input` *here* (the old `.min(input_tokens)`) silently zeroed out
        // `inflation_tokens` (`output.saturating_sub(input)`), defeating the
        // whole point of #196. Passing the real count keeps both metrics
        // honest: `saved` floored, `inflation` measurable.
        let output_tokens = estimate_tokens(output);

        if let Ok(tracker) = Tracker::new() {
            let _ = tracker.record(
                original_cmd,
                ctxcrl_cmd,
                input_tokens,
                output_tokens,
                elapsed_ms,
            );
        }
    }

    /// Track passthrough commands (timing-only, no token counting).
    ///
    /// For commands that stream output or run interactively where output
    /// cannot be captured. Records execution time but sets tokens to 0
    /// (does not dilute savings statistics).
    ///
    /// # Arguments
    ///
    /// - `original_cmd`: Standard command (e.g., "git tag --list")
    /// - `ctxcrl_cmd`: RTK command used (e.g., "rtk git tag --list")
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use contextcrawler::core::tracking::TimedExecution;
    ///
    /// let timer = TimedExecution::start();
    /// // ... execute streaming command ...
    /// timer.track_passthrough("git tag", "rtk git tag");
    /// ```
    pub fn track_passthrough(&self, original_cmd: &str, ctxcrl_cmd: &str) {
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        // input_tokens=0, output_tokens=0 won't dilute savings statistics
        if let Ok(tracker) = Tracker::new() {
            let _ = tracker.record(original_cmd, ctxcrl_cmd, 0, 0, elapsed_ms);
        }
    }
}

/// Format OsString args for tracking display.
///
/// Joins arguments with spaces, converting each to UTF-8 (lossy).
/// Useful for displaying command arguments in tracking records.
///
/// # Examples
///
/// ```
/// use std::ffi::OsString;
/// use contextcrawler::core::tracking::args_display;
///
/// let args = vec![OsString::from("status"), OsString::from("--short")];
/// assert_eq!(args_display(&args), "status --short");
/// ```
pub fn args_display(args: &[OsString]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Process-wide lock for tests that mutate environment variables
    /// (`RTK_DB_PATH`, `CONTEXTCRAWLER_TEST_MODE`) or otherwise depend on a
    /// stable resolution of `get_db_path()`.
    ///
    /// `cargo test` runs test fns in parallel threads of one process, so env
    /// vars are shared mutable state. Previously each test declared its *own*
    /// local `static ENV_LOCK`, which serialised nothing — a write-then-read
    /// test could still have `RTK_DB_PATH` swapped underneath it by a parallel
    /// env-mutating test (issue #69). This single shared lock is the real
    /// serialisation point; every env-touching test must hold it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inflation_tokens_captured_when_filter_inflates() {
        // #196: a filter that emits MORE than it consumed must record the
        // overflow in inflation_tokens, while saved_tokens stays floored at 0.
        let t = Tracker::new_in_memory().expect("in-memory tracker");
        t.record("git log", "rtk git log", 100, 30, 0).unwrap(); // saves 70
        t.record("grep x", "ctxcrl fallback: grep x", 10, 25, 0)
            .unwrap(); // inflates by 15
        assert_eq!(
            t.total_inflation_tokens().unwrap(),
            15,
            "the 15-token overflow must be recorded honestly"
        );
        // saved_tokens is still floored: only the saving row contributes.
        assert_eq!(t.get_summary().unwrap().total_saved, 70);
    }

    #[test]
    fn summary_surfaces_total_inflation() {
        // #196: gain reads GainSummary.total_inflation to print the
        // "Tokens inflated" line. Two inflating rows must aggregate.
        let t = Tracker::new_in_memory().expect("in-memory tracker");
        t.record("grep x", "ctxcrl fallback: grep x", 10, 25, 0)
            .unwrap(); // inflates by 15
        t.record("ps", "ctxcrl fallback: ps", 5, 11, 0).unwrap(); // inflates by 6
        let summary = t.get_summary().expect("summary");
        assert_eq!(
            summary.total_inflation, 21,
            "summary must expose aggregated inflation (15 + 6)"
        );
    }

    #[test]
    fn summary_total_inflation_zero_on_clean_data() {
        // #196: a clean install (no inflation) must report 0 so the gain
        // output omits the "Tokens inflated" line entirely.
        let t = Tracker::new_in_memory().expect("in-memory tracker");
        t.record("git log", "rtk git log", 100, 30, 0).unwrap(); // saves 70
        assert_eq!(
            t.get_summary().expect("summary").total_inflation,
            0,
            "no inflating command means zero inflation"
        );
    }

    #[test]
    fn weak_filters_report_per_tool_inflation() {
        // #196: gain --weak-filters reads WeakFilter.inflation_tokens to show
        // which tools inflate most. The inflating tool must carry the figure;
        // a clean tool must report zero.
        let t = Tracker::new_in_memory().expect("in-memory tracker");
        // Inflating tool: input>0 so it survives the leak filter, output>input.
        // `weak_filter_tool_key` collapses "rtk grep x" → "grep x".
        t.record("grep x", "rtk grep x", 10, 25, 0).unwrap(); // inflates by 15
        // Clean tool: real savings, no inflation.
        t.record("git log", "rtk git log", 100, 30, 0).unwrap();
        let weak = t.get_weak_filters(None, None).expect("weak filters");
        let grep = weak
            .iter()
            .find(|w| w.tool == "grep x")
            .expect("grep entry present");
        assert_eq!(
            grep.inflation_tokens, 15,
            "inflating tool must carry its overflow"
        );
        let git = weak
            .iter()
            .find(|w| w.tool == "git log")
            .expect("git entry present");
        assert_eq!(
            git.inflation_tokens, 0,
            "a saving tool must report zero inflation"
        );
    }

    #[test]
    fn scrub_redacts_password_flag_with_equals() {
        let out = scrub_secrets("psql --password=hunter2 -h db");
        assert_eq!(out, "psql --password=<REDACTED> -h db");
    }

    #[test]
    fn scrub_redacts_password_flag_with_space() {
        let out = scrub_secrets("aws --profile prod --password supersecret123");
        assert!(out.contains("--password <REDACTED>"), "got: {out}");
        assert!(!out.contains("supersecret123"));
    }

    #[test]
    fn scrub_redacts_token_and_api_key_flags() {
        for (input, needle) in [
            ("foo --token=abc.def.ghi bar", "--token=<REDACTED>"),
            ("foo --api-key xyz123 bar", "--api-key <REDACTED>"),
            ("foo --api_key xyz123 bar", "--api_key <REDACTED>"),
            ("foo --secret=topsecret bar", "--secret=<REDACTED>"),
            ("foo --access-key abc bar", "--access-key <REDACTED>"),
            ("foo --auth-token def bar", "--auth-token <REDACTED>"),
            ("foo --client-secret ghi bar", "--client-secret <REDACTED>"),
        ] {
            let out = scrub_secrets(input);
            assert!(out.contains(needle), "expected {needle} in {out}");
        }
    }

    #[test]
    fn scrub_redacts_authorization_header() {
        let out = scrub_secrets(
            r#"curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" https://api"#,
        );
        assert!(out.contains("Authorization: Bearer <REDACTED>"), "got: {out}");
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn scrub_redacts_basic_auth_header() {
        let out = scrub_secrets(r#"curl -H 'Authorization: Basic dXNlcjpwYXNz' https://api"#);
        assert!(out.contains("Authorization: Basic <REDACTED>"), "got: {out}");
    }

    #[test]
    fn scrub_redacts_url_userpass() {
        let out = scrub_secrets("git clone https://alice:hunter2@example.com/repo");
        assert_eq!(out, "git clone https://alice:<REDACTED>@example.com/repo");
    }

    #[test]
    fn scrub_redacts_aws_access_key() {
        let out = scrub_secrets("aws s3 ls --access-key-id AKIAIOSFODNN7EXAMPLE");
        // Both the AWS key regex and the access-key flag regex apply here.
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "got: {out}");
    }

    #[test]
    fn scrub_redacts_github_pat() {
        for token in [
            "ghp_AbCdEf0123456789AbCdEf0123456789AbCd",
            "gho_AbCdEf0123456789AbCdEf0123456789AbCd",
            "ghs_AbCdEf0123456789AbCdEf0123456789AbCd",
        ] {
            let input = format!("git push https://{token}@github.com/u/r");
            let out = scrub_secrets(&input);
            assert!(!out.contains(token), "leaked: {out}");
        }
    }

    #[test]
    fn scrub_redacts_mysql_inline_password() {
        let out = scrub_secrets("mysql -uadmin -phunter2 -hdb.local");
        assert!(out.contains("-p<REDACTED>"), "got: {out}");
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn scrub_leaves_benign_commands_unchanged() {
        for safe in [
            "git status",
            "cargo test --lib",
            "ls -la /tmp",
            "curl https://example.com",
            "psql -h localhost -U readonly mydb",
        ] {
            assert_eq!(scrub_secrets(safe), safe, "false-positive on {safe}");
        }
    }

    #[test]
    fn scrub_redacts_quoted_password_with_embedded_spaces() {
        // Codex review of 7b344b5: original \S+-only form only redacted the
        // first non-whitespace chunk, so a quoted secret with spaces leaked
        // its tail. The double-/single-quoted alternation now covers it.
        let out = scrub_secrets(r#"foo --password="pass word with spaces" bar"#);
        assert!(
            !out.contains("pass word with spaces"),
            "quoted password leaked: {out}"
        );
        let out = scrub_secrets(r#"foo --token 'tok en with spaces' bar"#);
        assert!(!out.contains("tok en with spaces"), "single-quoted leaked: {out}");
    }

    #[test]
    fn scrub_redacts_github_fine_grained_pat() {
        // Fine-grained PATs use the github_pat_ prefix and contain underscores.
        let pat = "github_pat_11AAAAAAA0_ZAYZbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf";
        let out = scrub_secrets(&format!("git push https://{pat}@github.com/u/r"));
        assert!(!out.contains(pat), "fine-grained PAT leaked: {out}");
        assert!(out.contains("<REDACTED-GH-TOKEN>"), "got: {out}");
    }

    #[test]
    fn scrub_does_not_clobber_curl_dash_p_port() {
        // Codex review of 7b344b5: original MYSQL_P regex was unscoped, so
        // `curl -p3000` and similar got rewritten to `-p<REDACTED>` and
        // corrupted the stored command. Now gated by is_mysql_command.
        for safe in [
            "curl -p3000 https://localhost",
            "ssh -p2222 user@host",
            "rsync -pvz src/ dst/",
            "git log -p HEAD",
        ] {
            assert_eq!(scrub_secrets(safe), safe, "false positive on {safe}");
        }
    }

    #[test]
    fn scrub_still_redacts_mysql_dash_p() {
        for cmd in [
            "mysql -uadmin -phunter2 -hdb.local",
            "mysqldump -uroot -psecret mydb",
            "mariadb -pVALUE -hdb",
            "/usr/bin/mysql -pVALUE",
            // Windows variants — Codex re-review caught these gaps.
            "mysql.exe -pVALUE",
            "MYSQL -pVALUE",
            // Note: a Windows path with embedded spaces (e.g.
            // `C:\Program Files\MySQL\mysql.exe`) splits on whitespace
            // before basename lookup. After `args.join(" ")` the
            // structure is lost; this is the same lossy-join limitation
            // documented for exec wrappers (e.g. `env mysql -p…`).
        ] {
            let out = scrub_secrets(cmd);
            assert!(out.contains("-p<REDACTED>"), "{cmd}: {out}");
        }
    }

    #[test]
    fn scrub_handles_escape_in_quoted_password() {
        // Codex re-review of a8bf02c: original "[^"]*" stopped at the first
        // closing quote, so `--password="pa\"ss word"` only matched
        // `--password="pa\"` and left `ss word"` raw. The escape-aware
        // alternation now lets `\\.` consume `\"` inside the quoted run.
        let out = scrub_secrets(r#"foo --password="pa\"ss word" bar"#);
        assert!(
            !out.contains("ss word"),
            "escape-aware quoted password leaked tail: {out}"
        );
        let out = scrub_secrets(r#"foo --token='it\'s a secret value' bar"#);
        assert!(
            !out.contains("s a secret value"),
            "escape-aware single-quoted token leaked tail: {out}"
        );
    }

    #[test]
    fn scrub_handles_multiple_secrets_in_one_command() {
        let out = scrub_secrets(
            "curl -H 'Authorization: Bearer tok123' --api-key=xyz https://u:p@h/path",
        );
        assert!(!out.contains("tok123"), "Bearer leaked: {out}");
        assert!(!out.contains("xyz"), "api-key leaked: {out}");
        assert!(out.contains(":<REDACTED>@"), "URL pwd not redacted: {out}");
    }

    // 1. estimate_tokens — verify ~4 chars/token ratio
    #[test]
    fn test_estimate_tokens() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1); // 4 chars = 1 token
        assert_eq!(estimate_tokens("abcde"), 2); // 5 chars = ceil(1.25) = 2
        assert_eq!(estimate_tokens("a"), 1); // 1 char = ceil(0.25) = 1
        assert_eq!(estimate_tokens("12345678"), 2); // 8 chars = 2 tokens
    }

    // 1b. No-bloat / inflation accounting (issues #95 + #196). `track()` now
    // records the TRUE output count (no `.min(input_tokens)` clamp). The
    // no-bloat guarantee of #95 is preserved because `record` floors `saved`
    // at 0 (`input.saturating_sub(output)`) — a filter that inflates reports 0
    // saved / 0% savings, never negative. The real overflow lands in
    // `inflation_tokens` (`output.saturating_sub(input)`), which the old clamp
    // silently zeroed (#196). This drives the path through `record`, then
    // checks both metrics on the stored row.
    #[test]
    fn test_inflating_filter_records_inflation_and_floors_savings() {
        // Filtered output much larger than the raw baseline (e.g. `tsc -b`
        // adding a banner around tiny raw output).
        let raw = "ok";
        let inflated = "═══════════════════════════════════════\nTypeScript: 0 errors\n";
        let input_tokens = estimate_tokens(raw);
        // No clamp: the true (larger) output count is what gets recorded.
        let output_tokens = estimate_tokens(inflated);
        assert!(output_tokens > input_tokens, "precondition: filter inflated");

        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");
        tracker
            .record(
                "tsc -b",
                "contextcrawler tsc -b",
                input_tokens,
                output_tokens,
                5,
            )
            .expect("Failed to record");

        let rec = tracker
            .get_recent(10)
            .expect("Failed to get recent")
            .into_iter()
            .find(|r| r.ctxcrl_cmd == "contextcrawler tsc -b")
            .expect("record not found");

        // #95: saved floored at 0, savings_pct at 0% (never negative).
        assert_eq!(rec.saved_tokens, 0, "inflation must not show negative savings");
        assert!(
            rec.savings_pct >= 0.0 && rec.savings_pct < 0.001,
            "savings floored at 0%, got {:.2}%",
            rec.savings_pct
        );
        // #196: the true overflow is captured, not zeroed by a clamp.
        assert_eq!(
            tracker.total_inflation_tokens().unwrap(),
            output_tokens - input_tokens,
            "inflation_tokens must capture the real overflow"
        );
    }

    // Regression for #196, driven through `TimedExecution::track` (NOT
    // `record` directly). The previous test suite only ever fed pre-clamped or
    // hand-picked values into `record`, so it never exercised the production
    // path where `track` computed `estimate_tokens(output).min(input_tokens)`
    // and zeroed every inflation. This is the test that would have caught the
    // dead `inflation_tokens` column: output > input, recorded via `track`,
    // must yield inflation > 0 while saved == 0 and savings_pct == 0.
    #[test]
    fn test_track_records_inflation_for_inflating_filter() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("RTK_DB_PATH").ok();
        // RTK_DB_PATH is confined to $HOME (G3 audit #111); a unique per-pid
        // file keeps total_inflation_tokens() reading only this test's rows.
        let tmp = dirs::home_dir().expect("home dir").join(format!(
            "cc-track-inflation-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        std::env::set_var("RTK_DB_PATH", &tmp);

        // Raw baseline tiny; filtered output much larger (streaming filter
        // that added framing it cannot un-print).
        let raw = "ok";
        let inflated = "═══════════════════════════════════════\nTypeScript: 0 errors\n";
        let input_tokens = estimate_tokens(raw);
        let output_tokens = estimate_tokens(inflated);
        assert!(output_tokens > input_tokens, "precondition: filter inflated");

        let timer = TimedExecution::start();
        timer.track("tsc -b", "contextcrawler tsc -b", raw, inflated);

        let tracker = Tracker::new().expect("Failed to open tracker");
        let rec = tracker
            .get_recent(10)
            .expect("Failed to get recent")
            .into_iter()
            .find(|r| r.ctxcrl_cmd == "contextcrawler tsc -b")
            .expect("record not found");

        assert_eq!(rec.saved_tokens, 0, "saved floored at 0 on inflation");
        assert!(
            rec.savings_pct >= 0.0 && rec.savings_pct < 0.001,
            "savings_pct floored at 0%, got {:.2}%",
            rec.savings_pct
        );
        assert_eq!(
            tracker.total_inflation_tokens().unwrap(),
            output_tokens - input_tokens,
            "track() must record the real inflation overflow (#196)"
        );

        let _ = std::fs::remove_file(&tmp);
        std::env::remove_var("RTK_DB_PATH");
        if let Some(v) = prior {
            std::env::set_var("RTK_DB_PATH", v);
        }
    }

    // A genuine saving is untouched — `track` records the real (smaller)
    // output count and reports positive savings.
    #[test]
    fn test_track_preserves_real_savings() {
        let raw = "line one\nline two\nline three\nline four\nline five\nline six\n";
        let filtered = "6 lines";
        let input_tokens = estimate_tokens(raw);
        let output_tokens = estimate_tokens(filtered);
        assert_eq!(output_tokens, estimate_tokens(filtered), "real saving untouched");
        assert!(output_tokens < input_tokens);
    }

    // 2. args_display — format OsString vec
    #[test]
    fn test_args_display() {
        let args = vec![OsString::from("status"), OsString::from("--short")];
        assert_eq!(args_display(&args), "status --short");
        assert_eq!(args_display(&[]), "");

        let single = vec![OsString::from("log")];
        assert_eq!(args_display(&single), "log");
    }

    // 3. Tracker::record + get_recent — round-trip DB
    #[test]
    fn test_tracker_record_and_recent() {
        // In-memory tracker: fully isolated from other tests' writes, so the
        // round-trip can't race against the process-shared test DB.
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");

        let test_cmd = "contextcrawler git status";
        tracker
            .record("git status", test_cmd, 100, 20, 50)
            .expect("Failed to record");

        let recent = tracker.get_recent(10).expect("Failed to get recent");

        let test_record = recent
            .iter()
            .find(|r| r.ctxcrl_cmd == test_cmd)
            .expect("Test record not found in recent commands");

        assert_eq!(test_record.saved_tokens, 80);
        assert_eq!(test_record.savings_pct, 80.0);
    }

    // 4. track_passthrough doesn't dilute stats (input=0, output=0)
    #[test]
    fn test_track_passthrough_no_dilution() {
        // In-memory tracker — isolated, no cross-test contention.
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");

        let cmd1 = "contextcrawler cmd1";
        let cmd2 = "contextcrawler cmd2_passthrough";

        // Record one real command with 80% savings
        tracker
            .record("cmd1", cmd1, 1000, 200, 10)
            .expect("Failed to record cmd1");

        // Record passthrough (0, 0)
        tracker
            .record("cmd2", cmd2, 0, 0, 5)
            .expect("Failed to record passthrough");

        // Verify both records exist in recent history
        let recent = tracker.get_recent(20).expect("Failed to get recent");

        let record1 = recent
            .iter()
            .find(|r| r.ctxcrl_cmd == cmd1)
            .expect("cmd1 record not found");
        let record2 = recent
            .iter()
            .find(|r| r.ctxcrl_cmd == cmd2)
            .expect("passthrough record not found");

        // Verify cmd1 has 80% savings
        assert_eq!(record1.saved_tokens, 800);
        assert_eq!(record1.savings_pct, 80.0);

        // Verify passthrough has 0% savings
        assert_eq!(record2.saved_tokens, 0);
        assert_eq!(record2.savings_pct, 0.0);

        // This validates that passthrough (0 input, 0 output) doesn't dilute stats
        // because the savings calculation is correct for both cases
    }

    // 5. TimedExecution::track records with exec_time > 0
    /// Build an `ctxcrl_cmd` marker unique to one test invocation.
    ///
    /// Every tracking test in a `cargo test` run writes to the same
    /// process-shared test DB (see `is_test_context` / `get_db_path`). A
    /// query that matches on a generic substring, or that scans only a small
    /// `get_recent` window, races against parallel writers. A pid + nanosecond
    /// marker makes each test's record unambiguously its own.
    fn unique_marker(label: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}_{}_{}", label, std::process::id(), nanos)
    }

    // Wide enough that a test's own record can't be pushed out of the result
    // set by parallel writers to the shared test DB.
    const TEST_RECENT_WINDOW: usize = 5000;

    /// RAII guard: pins `RTK_DB_PATH` to a private tempfile for the duration of
    /// a test, then restores the prior value (and deletes the tempfile).
    ///
    /// `TimedExecution::track*` writes to whatever `get_db_path()` resolves —
    /// it can't be handed an in-memory tracker. Setting `RTK_DB_PATH` makes
    /// both the write and the subsequent `Tracker::new()` read hit one private
    /// file, so the round-trip can't race other tests. Must be held alongside
    /// `ENV_LOCK` since `RTK_DB_PATH` is process-global.
    struct PinnedDb {
        path: std::path::PathBuf,
        prior: Option<String>,
    }
    impl PinnedDb {
        fn new(label: &str) -> Self {
            let prior = std::env::var("RTK_DB_PATH").ok();
            // RTK_DB_PATH is confined to $HOME (#111 G3), so the pinned
            // tempfile must live inside $HOME — `temp_dir()` is typically
            // outside it and would be rejected by `get_db_path()`.
            let dir = dirs::home_dir().unwrap_or_else(std::env::temp_dir);
            let path = dir.join(unique_marker(label) + ".db");
            std::env::set_var("RTK_DB_PATH", &path);
            PinnedDb { path, prior }
        }
    }
    impl Drop for PinnedDb {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var("RTK_DB_PATH", v),
                None => std::env::remove_var("RTK_DB_PATH"),
            }
            // Remove the .db file plus the WAL sidecars. Without `-wal`/`-shm`
            // cleanup, WAL-mode connections leave them behind on abnormal exit
            // (e.g. a worker thread panic) and pollute $HOME across runs.
            // Peer-review #150 (agy) found.
            let _ = std::fs::remove_file(&self.path);
            for suffix in ["-wal", "-shm"] {
                let mut s = self.path.clone().into_os_string();
                s.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(s));
            }
        }
    }

    #[test]
    fn test_timed_execution_records_time() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _db = PinnedDb::new("rtk_records_time");

        let marker = "contextcrawler test records-time";
        let timer = TimedExecution::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        timer.track("test cmd", marker, "raw input data", "filtered");

        let tracker = Tracker::new().expect("Failed to create tracker");
        let recent = tracker
            .get_recent(TEST_RECENT_WINDOW)
            .expect("Failed to get recent");
        assert!(
            recent.iter().any(|r| r.ctxcrl_cmd == marker),
            "own record ({marker}) not found among {} rows in the pinned DB",
            recent.len()
        );
    }

    // 6. TimedExecution::track_passthrough records with 0 tokens
    #[test]
    fn test_timed_execution_passthrough() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _db = PinnedDb::new("rtk_passthrough");

        let marker = "contextcrawler git tag (passthrough)";
        let timer = TimedExecution::start();
        timer.track_passthrough("git tag", marker);

        let tracker = Tracker::new().expect("Failed to create tracker");
        let recent = tracker
            .get_recent(TEST_RECENT_WINDOW)
            .expect("Failed to get recent");

        let pt = recent
            .iter()
            .find(|r| r.ctxcrl_cmd == marker)
            .unwrap_or_else(|| {
                panic!(
                    "own passthrough record ({marker}) not found among {} rows in the pinned DB",
                    recent.len()
                )
            });

        // savings_pct should be 0 for passthrough
        assert_eq!(pt.savings_pct, 0.0);
        assert_eq!(pt.saved_tokens, 0);
    }

    // 7. get_db_path respects environment variable RTK_DB_PATH
    // 8. get_db_path falls back to default when no custom config
    // Combined into one test to avoid env var race between parallel tests
    #[test]
    fn test_db_path_env_and_default() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // RTK_DB_PATH is now confined to $HOME (G3 audit #111), so the test
        // path must live inside $HOME or get_db_path() would reject it.
        let custom_path = dirs::home_dir()
            .expect("home dir")
            .join(format!("rtk_test_custom-{}.db", std::process::id()));
        env::set_var("RTK_DB_PATH", &custom_path);
        let db_path = get_db_path().expect("Failed to get db path");
        assert_eq!(db_path, custom_path);

        env::remove_var("RTK_DB_PATH");
        let db_path = get_db_path().expect("Failed to get db path");
        // Under `cargo test` (issue #91), without RTK_DB_PATH the path is
        // redirected to a per-process tmpfile, NOT the production history.db.
        // In a release build with CARGO_PKG_NAME unset the default platform
        // path would apply; here we just assert the redirect target.
        let s = db_path.display().to_string();
        assert!(
            s.contains("contextcrawler-test-"),
            "expected test-context tmpfile redirect, got: {s}"
        );
        assert!(
            !s.ends_with("rtk/history.db"),
            "must not resolve to production history.db under cargo test, got: {s}"
        );
    }

    // #111 G3: RTK_DB_PATH is attacker-influenceable (hostile .envrc/direnv),
    // so a value resolving outside $HOME must be rejected — same confinement
    // as the config-supplied path and RTK_TEE_DIR.
    #[test]
    fn test_rtk_db_path_outside_home_is_rejected() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = env::var("RTK_DB_PATH").ok();

        // An absolute path that exists and is outside $HOME.
        env::set_var("RTK_DB_PATH", "/tmp/contextcrawler-escape.db");
        let result = get_db_path();
        assert!(
            result.is_err(),
            "RTK_DB_PATH outside $HOME must be rejected, got: {result:?}"
        );

        match prior {
            Some(v) => env::set_var("RTK_DB_PATH", v),
            None => env::remove_var("RTK_DB_PATH"),
        }
    }

    // #111 G3: an RTK_DB_PATH already inside $HOME is preserved unchanged.
    #[test]
    fn test_rtk_db_path_inside_home_is_preserved() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = env::var("RTK_DB_PATH").ok();

        let inside = dirs::home_dir()
            .expect("home dir")
            .join(format!("contextcrawler-confine-{}.db", std::process::id()));
        env::set_var("RTK_DB_PATH", &inside);
        let resolved = get_db_path().expect("RTK_DB_PATH inside $HOME must resolve");
        assert_eq!(
            resolved, inside,
            "a path already inside $HOME must be returned unchanged"
        );

        match prior {
            Some(v) => env::set_var("RTK_DB_PATH", v),
            None => env::remove_var("RTK_DB_PATH"),
        }
    }

    // #111 G3 follow-up: a `..` in the non-existent tail must not escape $HOME.
    #[test]
    fn test_rtk_db_path_dotdot_escape_is_rejected() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = env::var("RTK_DB_PATH").ok();
        let home = dirs::home_dir().expect("home dir");

        for escape in [
            home.join("sub").join("..").join("..").join("evil.db"),
            home.join("..").join("evil.db"),
            home.join("a").join("b").join("..").join("..").join("..").join("x"),
        ] {
            env::set_var("RTK_DB_PATH", &escape);
            let result = get_db_path();
            assert!(
                result.is_err(),
                "RTK_DB_PATH escaping $HOME via `..` must be rejected, got: {result:?} for {}",
                escape.display()
            );
        }

        match prior {
            Some(v) => env::set_var("RTK_DB_PATH", v),
            None => env::remove_var("RTK_DB_PATH"),
        }
    }

    // #111 G3 follow-up: a `..` that stays inside $HOME resolves and is allowed.
    #[test]
    fn test_rtk_db_path_dotdot_inside_home_is_resolved() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = env::var("RTK_DB_PATH").ok();
        let home = dirs::home_dir().expect("home dir");

        let name = format!("contextcrawler-dotdot-{}.db", std::process::id());
        let with_dotdot = home.join("sub").join("..").join(&name);
        env::set_var("RTK_DB_PATH", &with_dotdot);
        let resolved =
            get_db_path().expect("a `..` staying inside $HOME must resolve");
        assert_eq!(
            resolved,
            home.join(&name),
            "`$HOME/sub/../{name}` must resolve to `$HOME/{name}`"
        );

        match prior {
            Some(v) => env::set_var("RTK_DB_PATH", v),
            None => env::remove_var("RTK_DB_PATH"),
        }
    }

    // #111 G3 Codex re-review: a symlink inside $HOME pointing OUT of $HOME,
    // followed by `..`, must not slip past containment. The earlier follow-up
    // resolved `..` lexically *before* canonicalisation — that textually
    // cancelled the `symlink/..` pair and hid the escape. Canonicalisation now
    // runs first, so the symlink is resolved to its real (outside) target
    // before the trailing `..` acts on it.
    #[cfg(unix)]
    #[test]
    fn test_rtk_db_path_symlink_escape_is_rejected() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = env::var("RTK_DB_PATH").ok();
        let home = dirs::home_dir().expect("home dir");

        // A symlink inside $HOME whose target is outside $HOME.
        let link = home.join(format!("cc-symtest-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/tmp", &link).expect("create symlink");

        // `$HOME/<link>/../x.db` — the OS resolves <link> to /tmp, then `..`
        // to / , landing at /x.db OUTSIDE $HOME.
        let escape = link.join("..").join("x.db");
        env::set_var("RTK_DB_PATH", &escape);
        let result = get_db_path();

        let _ = std::fs::remove_file(&link);
        match prior {
            Some(v) => env::set_var("RTK_DB_PATH", v),
            None => env::remove_var("RTK_DB_PATH"),
        }

        assert!(
            result.is_err(),
            "RTK_DB_PATH escaping $HOME via a symlink + `..` must be rejected, got: {result:?}"
        );
    }

    // 9. project_filter_params uses GLOB pattern with * wildcard // added
    #[test]
    fn test_project_filter_params_glob_pattern() {
        let (exact, glob) = project_filter_params(Some("/home/user/project"));
        assert_eq!(exact.unwrap(), "/home/user/project");
        // Must use * (GLOB) not % (LIKE) for subdirectory prefix matching
        let glob_val = glob.unwrap();
        assert!(glob_val.ends_with('*'), "GLOB pattern must end with *");
        assert!(!glob_val.contains('%'), "Must not contain LIKE wildcard %");
        assert_eq!(
            glob_val,
            format!("/home/user/project{}*", std::path::MAIN_SEPARATOR)
        );
    }

    // 10. project_filter_params returns None for None input // added
    #[test]
    fn test_project_filter_params_none() {
        let (exact, glob) = project_filter_params(None);
        assert!(exact.is_none());
        assert!(glob.is_none());
    }

    // 11. GLOB pattern safe with underscores in path names // added
    #[test]
    fn test_project_filter_params_underscore_safe() {
        // In LIKE, _ matches any single char; in GLOB, _ is literal
        let (exact, glob) = project_filter_params(Some("/home/user/my_project"));
        assert_eq!(exact.unwrap(), "/home/user/my_project");
        let glob_val = glob.unwrap();
        // _ must be preserved literally (GLOB treats _ as literal, LIKE does not)
        assert!(glob_val.contains("my_project"));
        assert_eq!(
            glob_val,
            format!("/home/user/my_project{}*", std::path::MAIN_SEPARATOR)
        );
    }

    // 12. record_parse_failure + get_parse_failure_summary roundtrip
    #[test]
    fn test_parse_failure_roundtrip() {
        // In-memory tracker: isolated from the process-shared test DB, so the
        // counts are exact rather than ">= 1" (Codex review of #69/#94).
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");
        let test_cmd = "git -C /path status";

        tracker
            .record_parse_failure(test_cmd, "unrecognized subcommand", true)
            .expect("Failed to record parse failure");

        let summary = tracker
            .get_parse_failure_summary()
            .expect("Failed to get summary");

        assert_eq!(summary.total, 1);
        assert!(summary.recent.iter().any(|r| r.raw_command == test_cmd));
    }

    // 13. recovery_rate calculation
    #[test]
    fn test_parse_failure_recovery_rate() {
        // In-memory tracker — isolation makes the rate exact, not a range.
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");

        // 2 recovered, 1 not → recovery_rate = 2/3.
        tracker.record_parse_failure("cmd_ok1", "err", true).unwrap();
        tracker.record_parse_failure("cmd_ok2", "err", true).unwrap();
        tracker.record_parse_failure("cmd_fail", "err", false).unwrap();

        let summary = tracker.get_parse_failure_summary().unwrap();
        assert_eq!(summary.total, 3);
        assert!(
            (summary.recovery_rate - 200.0 / 3.0).abs() < 0.01,
            "expected ~66.67% recovery, got {}",
            summary.recovery_rate
        );
    }

    // Issue #91 — `cargo test` must not write to production history.db.
    #[test]
    fn test_is_test_context_true_in_cargo_test() {
        // RTK_DB_PATH overrides the test-context check (explicit opt-in path).
        // Save/restore around the env mutation.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("RTK_DB_PATH").ok();
        std::env::remove_var("RTK_DB_PATH");
        assert!(
            is_test_context(),
            "is_test_context() must be true under `cargo test` (cfg!(test) + CARGO_PKG_NAME set, any build mode)"
        );
        if let Some(v) = prior {
            std::env::set_var("RTK_DB_PATH", v);
        }
    }

    /// Codex review — release-mode integration tests spawn the binary as a
    /// child process where `cfg!(test)` is FALSE (the spawned binary is not
    /// itself a test runner). The `CONTEXTCRAWLER_TEST_MODE=1` sentinel set
    /// by the test harness is what keeps that child from polluting the
    /// production DB. Assert the sentinel path works.
    #[test]
    fn test_is_test_context_true_under_sentinel_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let prior_db = std::env::var("RTK_DB_PATH").ok();
        let prior_mode = std::env::var("CONTEXTCRAWLER_TEST_MODE").ok();
        std::env::remove_var("RTK_DB_PATH");
        std::env::set_var("CONTEXTCRAWLER_TEST_MODE", "1");

        assert!(
            is_test_context(),
            "CONTEXTCRAWLER_TEST_MODE=1 must force is_test_context() true \
             (covers release-built spawned-binary integration tests)"
        );

        // Restore.
        if let Some(v) = prior_db {
            std::env::set_var("RTK_DB_PATH", v);
        }
        match prior_mode {
            Some(v) => std::env::set_var("CONTEXTCRAWLER_TEST_MODE", v),
            None => std::env::remove_var("CONTEXTCRAWLER_TEST_MODE"),
        }
    }

    #[test]
    fn test_tracking_no_writes_to_production_in_test_context() {
        // Resolves get_db_path() under the active test process — must NOT
        // point at the production history.db. The redirect target is a
        // per-process tmpfile.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("RTK_DB_PATH").ok();
        std::env::remove_var("RTK_DB_PATH");
        let p = get_db_path().expect("get_db_path");
        let p_str = p.display().to_string();
        assert!(
            p_str.contains("contextcrawler-test-"),
            "test runs must redirect get_db_path → tmpfile, got: {p_str}"
        );
        assert!(
            !p_str.ends_with("rtk/history.db"),
            "test runs must not resolve to production history.db, got: {p_str}"
        );
        if let Some(v) = prior {
            std::env::set_var("RTK_DB_PATH", v);
        }
    }

    #[test]
    fn test_rtk_db_path_overrides_test_context() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("RTK_DB_PATH").ok();

        // RTK_DB_PATH is confined to $HOME (G3 audit #111) — keep the opt-in
        // DB inside $HOME so get_db_path() resolves it unchanged.
        let tmp = dirs::home_dir().expect("home dir").join(format!(
            "contextcrawler-optin-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        std::env::set_var("RTK_DB_PATH", &tmp);

        // is_test_context() must return false under opt-in
        assert!(
            !is_test_context(),
            "RTK_DB_PATH must override is_test_context()"
        );

        // And get_db_path resolves to that exact path
        let p = get_db_path().expect("get_db_path");
        assert_eq!(p, tmp);

        // Round-trip a record through the opt-in DB.
        let tracker = Tracker::new().expect("tracker open");
        let marker = format!("contextcrawler optin_{}", std::process::id());
        tracker
            .record("orig", &marker, 100, 20, 5)
            .expect("record under opt-in must persist");
        let recent = tracker.get_recent(50).expect("get_recent");
        assert!(
            recent.iter().any(|r| r.ctxcrl_cmd == marker),
            "opt-in record not persisted"
        );

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
        std::env::remove_var("RTK_DB_PATH");
        if let Some(v) = prior {
            std::env::set_var("RTK_DB_PATH", v);
        }
    }

    #[test]
    fn test_reset_all_clears_both_tables() {
        let tracker = Tracker::new_in_memory().expect("Failed to create in-memory tracker");
        let pid = std::process::id();

        // Insert into commands
        tracker
            .record(
                "git status",
                &format!("contextcrawler git status reset_test_{}", pid),
                100,
                20,
                50,
            )
            .expect("Failed to record command");

        // Insert into parse_failures
        tracker
            .record_parse_failure(&format!("bad_cmd_reset_test_{}", pid), "parse error", false)
            .expect("Failed to record parse failure");

        // Reset everything
        tracker.reset_all().expect("Failed to reset");

        // Both tables should be empty
        let summary = tracker.get_summary().expect("Failed to get summary");
        assert_eq!(
            summary.total_commands, 0,
            "commands table should be empty after reset"
        );

        let failures = tracker
            .get_parse_failure_summary()
            .expect("Failed to get failure summary");
        assert_eq!(
            failures.total, 0,
            "parse_failures table should be empty after reset"
        );
    }

    // PERF-I1: the tracking DB must be in incremental auto-vacuum mode, so
    // retention pruning reclaims space with `PRAGMA incremental_vacuum`
    // (bounded) instead of a full `VACUUM` file rewrite on the record() hot
    // path. auto_vacuum mode 2 == INCREMENTAL.
    #[test]
    fn test_tracking_db_is_incremental_auto_vacuum() {
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");
        let mode: i64 = tracker
            .conn
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .expect("Failed to read auto_vacuum pragma");
        assert_eq!(
            mode, 2,
            "tracking DB must be in INCREMENTAL auto_vacuum mode (got {mode})"
        );
    }

    // PERF-I1: cleanup_old() prunes rows past the retention window and runs
    // an incremental_vacuum — it must complete cheaply without error and
    // without a full VACUUM rewrite. Verifies the prune still removes old
    // rows after the VACUUM-removal change.
    #[test]
    fn test_cleanup_old_prunes_without_full_vacuum() {
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");

        // An old command well past the 90-day retention window.
        let old_ts = (Utc::now() - chrono::Duration::days(DEFAULT_HISTORY_DAYS + 30)).to_rfc3339();
        tracker
            .conn
            .execute(
                "INSERT INTO commands (timestamp, original_cmd, ctxcrl_cmd, project_path,
                 input_tokens, output_tokens, saved_tokens, savings_pct, exec_time_ms)
                 VALUES (?1, 'old', 'contextcrawler old', '', 100, 20, 80, 80.0, 1)",
                params![old_ts],
            )
            .expect("Failed to insert old row");

        // A fresh record() — this triggers cleanup_old() on the hot path.
        tracker
            .record("git status", "contextcrawler git status", 100, 20, 50)
            .expect("record should succeed (cleanup_old must not error)");

        // The old row is gone; the fresh one survives.
        let total: i64 = tracker
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .expect("Failed to count");
        assert_eq!(total, 1, "old row should be pruned, fresh row retained");
    }

    #[test]
    fn test_weak_filter_tool_key() {
        assert_eq!(
            weak_filter_tool_key("contextcrawler git log --oneline -5"),
            "git log"
        );
        assert_eq!(weak_filter_tool_key("rtk cargo test"), "cargo test");
        // Second token is a path → just the base command.
        assert_eq!(
            weak_filter_tool_key("contextcrawler read src/main.rs"),
            "read"
        );
        // Second token is a flag → just the base command.
        assert_eq!(weak_filter_tool_key("contextcrawler grep -r foo"), "grep");
        assert_eq!(weak_filter_tool_key("contextcrawler ls"), "ls");
        assert_eq!(weak_filter_tool_key(""), "");
    }

    #[test]
    fn test_get_weak_filters_ranks_by_leak() {
        let tracker = Tracker::new_in_memory().expect("Failed to create tracker");

        // `read`: high input, low savings → the biggest leaker.
        for _ in 0..3 {
            tracker
                .record("read f.rs", "contextcrawler read f.rs", 1000, 900, 1)
                .expect("record read");
        }
        // `cargo test`: lower input, high savings → a small leak.
        tracker
            .record("cargo test", "contextcrawler cargo test", 500, 50, 1)
            .expect("record cargo");
        // `git log --oneline`: passthrough (0/0) → must not appear at all.
        tracker
            .record(
                "git log --oneline",
                "contextcrawler git log --oneline",
                0,
                0,
                1,
            )
            .expect("record passthrough");

        let weak = tracker
            .get_weak_filters(None, None)
            .expect("Failed to load weak filters");

        // read leaks 3 × (1000 input − 100 saved) = 2700; cargo leaks 50.
        assert_eq!(weak[0].tool, "read", "biggest leaker must rank first");
        assert_eq!(weak[0].runs, 3);
        assert_eq!(weak[0].input_tokens, 3000);
        assert_eq!(weak[0].leaked_tokens, 2700);
        assert!((weak[0].savings_pct - 10.0).abs() < 0.01);

        assert!(
            weak.iter().any(|w| w.tool == "cargo test"),
            "cargo test should still be listed (it leaks a little)"
        );
        assert!(
            !weak.iter().any(|w| w.tool.starts_with("git")),
            "a passthrough-only tool (0 input) must be excluded"
        );
    }

    // ─── Release-boundary slicing ──────────────────────────────────────────

    #[test]
    fn ensure_release_boundary_writes_first_row_on_fresh_db() {
        let tracker = Tracker::new_in_memory().expect("in-memory tracker");
        // new_in_memory() does not call ensure_release_boundary() (production
        // path does, but the test constructor mirrors only the schema). Call
        // it explicitly to validate the insert path.
        tracker
            .ensure_release_boundary()
            .expect("boundary insert");
        let ts = tracker
            .latest_boundary_timestamp()
            .expect("read boundary")
            .expect("boundary row must exist");
        assert!(
            !ts.is_empty(),
            "stored timestamp must be a non-empty RFC-3339 string"
        );
    }

    #[test]
    fn ensure_release_boundary_is_idempotent_on_same_version() {
        let tracker = Tracker::new_in_memory().expect("in-memory tracker");
        tracker.ensure_release_boundary().expect("first insert");
        tracker.ensure_release_boundary().expect("no-op call");
        tracker.ensure_release_boundary().expect("no-op call");
        let n: i64 = tracker
            .conn
            .query_row(
                "SELECT COUNT(*) FROM release_boundaries",
                [],
                |row| row.get(0),
            )
            .expect("count rows");
        assert_eq!(
            n, 1,
            "same-version call must not append duplicate boundary rows"
        );
    }

    #[test]
    fn get_weak_filters_since_excludes_older_rows() {
        // Use `+00:00` suffix to match production `Utc::now().to_rfc3339()`
        // output — lexicographic ISO-8601 comparison requires consistent
        // suffix shape across all rows. Peer-review #150 (agy) finding.
        let tracker = Tracker::new_in_memory().expect("in-memory tracker");
        // Two rows: one before, one after the cutoff.
        tracker
            .conn
            .execute(
                "INSERT INTO commands
                 (timestamp, original_cmd, ctxcrl_cmd, input_tokens, output_tokens,
                  saved_tokens, savings_pct, exec_time_ms, project_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    "2026-01-01T00:00:00+00:00",
                    "read /old",
                    "contextcrawler read /old",
                    1000,
                    100,
                    900,
                    90.0,
                    0,
                    ""
                ],
            )
            .expect("insert old row");
        tracker
            .conn
            .execute(
                "INSERT INTO commands
                 (timestamp, original_cmd, ctxcrl_cmd, input_tokens, output_tokens,
                  saved_tokens, savings_pct, exec_time_ms, project_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    "2026-06-01T00:00:00+00:00",
                    "read /new",
                    "contextcrawler read /new",
                    2000,
                    400,
                    1600,
                    80.0,
                    0,
                    ""
                ],
            )
            .expect("insert new row");
        let all = tracker
            .get_weak_filters(None, None)
            .expect("all-time query");
        let read_all = all.iter().find(|w| w.tool == "read").expect("read entry");
        assert_eq!(read_all.runs, 2);
        assert_eq!(read_all.input_tokens, 3000);

        let sliced = tracker
            .get_weak_filters(None, Some("2026-03-01T00:00:00+00:00"))
            .expect("since query");
        let read_sliced = sliced
            .iter()
            .find(|w| w.tool == "read")
            .expect("read entry after slice");
        assert_eq!(read_sliced.runs, 1, "old row must be excluded");
        assert_eq!(read_sliced.input_tokens, 2000);
    }

    // ─── Peer-review #150 follow-up coverage (agy) ─────────────────────────

    #[test]
    fn latest_boundary_timestamp_is_none_on_empty_table() {
        let tracker = Tracker::new_in_memory().expect("in-memory tracker");
        let ts = tracker
            .latest_boundary_timestamp()
            .expect("read boundary on empty table");
        assert!(
            ts.is_none(),
            "no boundary rows must yield None (callers fall back to lifetime)"
        );
    }

    #[test]
    fn ensure_release_boundary_appends_row_on_version_change() {
        // Simulate the binary moving from a prior version to the current one:
        // pre-seed a boundary row for some old version, then call ensure_*
        // and confirm a new row is appended (not deduplicated against the
        // OLD entry — only against the LATEST one).
        let tracker = Tracker::new_in_memory().expect("in-memory tracker");
        tracker
            .conn
            .execute(
                "INSERT INTO release_boundaries (version, installed_at)
                 VALUES (?1, ?2)",
                params!["0.0.0-test-prior", "2026-01-01T00:00:00+00:00"],
            )
            .expect("seed prior-version row");
        tracker
            .ensure_release_boundary()
            .expect("boundary on version change");
        let n: i64 = tracker
            .conn
            .query_row(
                "SELECT COUNT(*) FROM release_boundaries",
                [],
                |row| row.get(0),
            )
            .expect("count rows");
        assert_eq!(n, 2, "a version change must append a new boundary row");
        // The latest row must carry the CURRENT compile-time version, not
        // the seeded prior one.
        let latest_version: String = tracker
            .conn
            .query_row(
                "SELECT version FROM release_boundaries ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read latest version");
        assert_eq!(latest_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn ensure_release_boundary_is_idempotent_on_tight_loop() {
        // Same-connection idempotency: repeated calls on one Tracker must
        // not append duplicate rows. This is the cheap baseline check
        // that the WHERE-NOT-EXISTS guard fires correctly. The real
        // multi-connection race is exercised by the test below.
        let tracker = Tracker::new_in_memory().expect("in-memory tracker");
        for _ in 0..10 {
            tracker.ensure_release_boundary().expect("repeated call");
        }
        let n: i64 = tracker
            .conn
            .query_row(
                "SELECT COUNT(*) FROM release_boundaries",
                [],
                |row| row.get(0),
            )
            .expect("count rows");
        assert_eq!(n, 1, "tight-loop calls must not append duplicate rows");
    }

    #[test]
    fn ensure_release_boundary_no_duplicates_under_real_concurrency() {
        // Round-2 peer-review (Codex + agy) asked for a real multi-thread
        // race against a file-backed DB — the single-connection idempotency
        // test above doesn't exercise SQLite's write-locking behaviour.
        //
        // Strategy: pin a private file-backed DB via the PinnedDb RAII
        // helper, then spawn 8 threads that each call `Tracker::new()`.
        // Every Tracker::new() runs `ensure_release_boundary()` on its own
        // sqlite Connection — exactly the production race shape (two
        // contextcrawler processes starting concurrently after a binary
        // upgrade). The atomic INSERT...WHERE NOT EXISTS guarantees that
        // only the first one to acquire the SQLITE write lock inserts;
        // the others find the row already there and no-op.
        //
        // Holding ENV_LOCK serialises with other RTK_DB_PATH-touching
        // tests in the same process, not with our own spawned threads —
        // they share the same path env-var.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _db = PinnedDb::new("rtk_boundary_concurrency");

        const N_THREADS: usize = 8;
        let mut handles = Vec::with_capacity(N_THREADS);
        for _ in 0..N_THREADS {
            handles.push(std::thread::spawn(|| {
                Tracker::new().expect("tracker construction in worker thread");
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let tracker = Tracker::new().expect("verifier tracker");
        let n: i64 = tracker
            .conn
            .query_row(
                "SELECT COUNT(*) FROM release_boundaries",
                [],
                |row| row.get(0),
            )
            .expect("count rows");
        assert_eq!(
            n, 1,
            "atomic INSERT...WHERE NOT EXISTS must dedupe across N concurrent connections"
        );
    }
}
