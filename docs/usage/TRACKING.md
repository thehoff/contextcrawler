# contextcrawler Tracking API Documentation

Comprehensive documentation for contextcrawler's token savings tracking system.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Public API](#public-api)
- [Usage Examples](#usage-examples)
- [Data Formats](#data-formats)
- [Integration Examples](#integration-examples)
- [Database Schema](#database-schema)

## Overview

contextcrawler's tracking system records every command execution to provide analytics on token savings. The system:
- Stores command history in SQLite (`~/.local/share/ctxcrl/history.db` on Linux)
- Tracks input/output tokens, savings percentage, execution time, project path, and output inflation
- Automatically cleans up records older than 90 days
- Provides aggregation APIs (daily/weekly/monthly)
- Exports to JSON/CSV for external integrations

The database filename is `history.db` (constant `HISTORY_DB` in `src/core/constants.rs`), inside the `ctxcrl` data directory (constant `RTK_DATA_DIR`). Some inline Rust doc comments in `src/core/tracking.rs` still say `tracking.db`; the constant is the source of truth and resolves to `history.db`.

## Architecture

### Data Flow

```
contextcrawler command execution
  ↓
TimedExecution::start()
  ↓
[command runs]
  ↓
TimedExecution::track(original_cmd, ctxcrl_cmd, input, output)
  ↓
Tracker::record(original_cmd, ctxcrl_cmd, input_tokens, output_tokens, exec_time_ms)
  ↓
SQLite database (~/.local/share/ctxcrl/history.db)
  ↓
Aggregation APIs (get_summary, get_all_days, etc.)
  ↓
CLI output (contextcrawler gain) or JSON/CSV export
```

### Storage Location

The path is `dirs::data_local_dir()` joined with `ctxcrl/history.db`:

- **Linux**: `~/.local/share/ctxcrl/history.db`
- **macOS**: `~/Library/Application Support/ctxcrl/history.db`
- **Windows**: `%APPDATA%\ctxcrl\history.db`

**Override**: set `CTXCRL_DB_PATH` to point tracking writes at a specific file (used by tests that exercise tracking against a tmpfile). When that variable is set, the test-context short-circuit is disabled and writes go to the named path.

### Data Retention

Records older than **90 days** are automatically deleted on each write operation to prevent unbounded database growth.

## What the CLI reads from this data

The tracking database is the data source for two analytics commands.

### `contextcrawler gain`

Reads the `commands` table and aggregates it. Defaults to a total summary; flags
select the view:

- `--daily` / `--weekly` / `--monthly` / `--all`: time-bucketed breakdowns.
- `--history` (`-H`): recent rows with per-command savings.
- `--project` (`-p`): scope every figure to the current working directory
  (via the `project_path` column).
- `--graph` (`-g`): ASCII graph of daily savings.
- `--quota --tier <pro|5x|20x>`: estimate savings against a subscription tier.
- `--failures` (`-F`): read the `parse_failures` table instead.
- `--weak-filters` (`-W`): rank tools by leaked tokens (output inflation plus
  low savings), sliced from the latest `release_boundaries` row unless
  `--all-time` is given.
- `--format <text|json|csv>`: export.
- `--reset [--yes]`: wipe all tracked data.

### `contextcrawler discover`

Does **not** read this database. It scans Claude Code session history (and, with
`--codex`, Codex CLI job logs) to find commands that ran *without* contextcrawler
and estimates the savings that were missed, using the `estimated_savings_pct`
figures from the rule set. Use `gain` for what you saved and `discover` for what
you could still save.

## Public API

### Core Types

#### `Tracker`

Main tracking interface for recording and querying command history.

```rust
pub struct Tracker {
    conn: Connection, // SQLite connection
}

impl Tracker {
    /// Create new tracker instance (opens/creates database)
    pub fn new() -> Result<Self>;

    /// Record a command execution
    pub fn record(
        &self,
        original_cmd: &str,      // Standard command (e.g., "ls -la")
        ctxcrl_cmd: &str,         // contextcrawler command (e.g., "contextcrawler ls")
        input_tokens: usize,      // Estimated input tokens
        output_tokens: usize,     // Actual output tokens
        exec_time_ms: u64,        // Execution time in milliseconds
    ) -> Result<()>;

    /// Get overall summary statistics
    pub fn get_summary(&self) -> Result<GainSummary>;

    /// Get daily statistics (all days)
    pub fn get_all_days(&self) -> Result<Vec<DayStats>>;

    /// Get weekly statistics (grouped by week)
    pub fn get_by_week(&self) -> Result<Vec<WeekStats>>;

    /// Get monthly statistics (grouped by month)
    pub fn get_by_month(&self) -> Result<Vec<MonthStats>>;

    /// Get recent command history (limit = max records)
    pub fn get_recent(&self, limit: usize) -> Result<Vec<CommandRecord>>;
}
```

#### `GainSummary`

Aggregated statistics across all recorded commands.

```rust
pub struct GainSummary {
    pub total_commands: usize,              // Total commands recorded
    pub total_input: usize,                 // Total input tokens
    pub total_output: usize,                // Total output tokens
    pub total_saved: usize,                 // Total tokens saved (floored at 0)
    pub total_inflation: usize,             // Tokens by which filters INFLATED output beyond input (#196)
    pub avg_savings_pct: f64,               // Average savings percentage
    pub total_time_ms: u64,                 // Total execution time (ms)
    pub avg_time_ms: u64,                   // Average execution time (ms)
    pub by_command: Vec<(String, usize, usize, f64, u64)>, // Top 10 commands
    pub by_day: Vec<(String, usize)>,       // Last 30 days
}
```

#### `DayStats`

Daily statistics (Serializable for JSON export).

```rust
#[derive(Debug, Serialize)]
pub struct DayStats {
    pub date: String,            // ISO date (YYYY-MM-DD)
    pub commands: usize,         // Commands executed this day
    pub input_tokens: usize,     // Total input tokens
    pub output_tokens: usize,    // Total output tokens
    pub saved_tokens: usize,     // Total tokens saved
    pub savings_pct: f64,        // Savings percentage
    pub total_time_ms: u64,      // Total execution time (ms)
    pub avg_time_ms: u64,        // Average execution time (ms)
}
```

#### `WeekStats`

Weekly statistics (Serializable for JSON export).

```rust
#[derive(Debug, Serialize)]
pub struct WeekStats {
    pub week_start: String,      // ISO date (YYYY-MM-DD)
    pub week_end: String,        // ISO date (YYYY-MM-DD)
    pub commands: usize,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub saved_tokens: usize,
    pub savings_pct: f64,
    pub total_time_ms: u64,
    pub avg_time_ms: u64,
}
```

#### `MonthStats`

Monthly statistics (Serializable for JSON export).

```rust
#[derive(Debug, Serialize)]
pub struct MonthStats {
    pub month: String,           // YYYY-MM format
    pub commands: usize,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub saved_tokens: usize,
    pub savings_pct: f64,
    pub total_time_ms: u64,
    pub avg_time_ms: u64,
}
```

#### `CommandRecord`

Individual command record from history.

```rust
pub struct CommandRecord {
    pub timestamp: DateTime<Utc>,  // UTC timestamp
    pub ctxcrl_cmd: String,        // contextcrawler command used
    pub saved_tokens: usize,       // Tokens saved
    pub savings_pct: f64,          // Savings percentage
}
```

#### `TimedExecution`

Helper for timing command execution (preferred API).

```rust
pub struct TimedExecution {
    start: Instant,
}

impl TimedExecution {
    /// Start timing a command execution
    pub fn start() -> Self;

    /// Track command with elapsed time
    pub fn track(&self, original_cmd: &str, ctxcrl_cmd: &str, input: &str, output: &str);

    /// Track passthrough commands (timing-only, no token counting)
    pub fn track_passthrough(&self, original_cmd: &str, ctxcrl_cmd: &str);
}
```

### Utility Functions

```rust
/// Estimate token count (~4 chars = 1 token)
pub fn estimate_tokens(text: &str) -> usize;

/// Format OsString args for display
pub fn args_display(args: &[OsString]) -> String;

/// Legacy tracking function (deprecated, use TimedExecution)
#[deprecated(note = "Use TimedExecution instead")]
pub fn track(original_cmd: &str, ctxcrl_cmd: &str, input: &str, output: &str);
```

## Usage Examples

### Basic Tracking

```rust
use contextcrawler::tracking::{TimedExecution, Tracker};

fn main() -> anyhow::Result<()> {
    // Start timer
    let timer = TimedExecution::start();

    // Execute command
    let input = execute_original_command()?;
    let output = execute_rtk_command()?;

    // Track execution
    timer.track("ls -la", "contextcrawler ls", &input, &output);

    Ok(())
}
```

### Querying Statistics

```rust
use contextcrawler::tracking::Tracker;

fn main() -> anyhow::Result<()> {
    let tracker = Tracker::new()?;

    // Get overall summary
    let summary = tracker.get_summary()?;
    println!("Total commands: {}", summary.total_commands);
    println!("Total saved: {} tokens", summary.total_saved);
    println!("Average savings: {:.1}%", summary.avg_savings_pct);

    // Get daily breakdown
    let days = tracker.get_all_days()?;
    for day in days.iter().take(7) {
        println!("{}: {} commands, {} tokens saved",
            day.date, day.commands, day.saved_tokens);
    }

    // Get recent history
    let recent = tracker.get_recent(10)?;
    for cmd in recent {
        println!("{}: {} saved {:.1}%",
            cmd.timestamp, cmd.ctxcrl_cmd, cmd.savings_pct);
    }

    Ok(())
}
```

### Passthrough Commands

For commands that stream output or run interactively (no output capture):

```rust
use contextcrawler::tracking::TimedExecution;

fn main() -> anyhow::Result<()> {
    let timer = TimedExecution::start();

    // Execute streaming command (e.g., git tag --list)
    execute_streaming_command()?;

    // Track timing only (input_tokens=0, output_tokens=0)
    timer.track_passthrough("git tag --list", "contextcrawler git tag --list");

    Ok(())
}
```

## Data Formats

### JSON Export Schema

#### DayStats JSON

```json
{
  "date": "2026-02-03",
  "commands": 42,
  "input_tokens": 15420,
  "output_tokens": 3842,
  "saved_tokens": 11578,
  "savings_pct": 75.08,
  "total_time_ms": 8450,
  "avg_time_ms": 201
}
```

#### WeekStats JSON

```json
{
  "week_start": "2026-01-27",
  "week_end": "2026-02-02",
  "commands": 284,
  "input_tokens": 98234,
  "output_tokens": 19847,
  "saved_tokens": 78387,
  "savings_pct": 79.80,
  "total_time_ms": 56780,
  "avg_time_ms": 200
}
```

#### MonthStats JSON

```json
{
  "month": "2026-02",
  "commands": 1247,
  "input_tokens": 456789,
  "output_tokens": 91358,
  "saved_tokens": 365431,
  "savings_pct": 80.00,
  "total_time_ms": 249560,
  "avg_time_ms": 200
}
```

### CSV Export Schema

```csv
date,commands,input_tokens,output_tokens,saved_tokens,savings_pct,total_time_ms,avg_time_ms
2026-02-03,42,15420,3842,11578,75.08,8450,201
2026-02-02,38,14230,3557,10673,75.00,7600,200
2026-02-01,45,16890,4223,12667,75.00,9000,200
```

## Integration Examples

### GitHub Actions - Track Savings in CI

```yaml
# .github/workflows/track-ctxcrl-savings.yml
name: Track contextcrawler Savings

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  track-savings:
    runs-on: ubuntu-latest
    steps:
      - name: Install contextcrawler
        run: cargo install --git https://github.com/rtk-ai/rtk

      - name: Export weekly stats
        run: |
          contextcrawler gain --weekly --format json > ctxcrl-weekly.json
          cat ctxcrl-weekly.json

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: ctxcrl-metrics
          path: ctxcrl-weekly.json

      - name: Post to Slack
        if: success()
        env:
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
        run: |
          SAVINGS=$(jq -r '.[0].saved_tokens' ctxcrl-weekly.json)
          PCT=$(jq -r '.[0].savings_pct' ctxcrl-weekly.json)
          curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"📊 contextcrawler Weekly: ${SAVINGS} tokens saved (${PCT}%)\"}" \
            $SLACK_WEBHOOK
```

### Custom Dashboard Script

```python
#!/usr/bin/env python3
"""
Export contextcrawler metrics to Grafana/Datadog/etc.
"""
import json
import subprocess
from datetime import datetime

def get_ctxcrl_metrics():
    """Fetch contextcrawler metrics as JSON."""
    result = subprocess.run(
        ["contextcrawler", "gain", "--all", "--format", "json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def export_to_datadog(metrics):
    """Send metrics to Datadog."""
    import datadog

    datadog.initialize(api_key="YOUR_API_KEY")

    for day in metrics.get("daily", []):
        datadog.api.Metric.send(
            metric="contextcrawler.tokens_saved",
            points=[(datetime.now().timestamp(), day["saved_tokens"])],
            tags=[f"date:{day['date']}"]
        )

        datadog.api.Metric.send(
            metric="contextcrawler.savings_pct",
            points=[(datetime.now().timestamp(), day["savings_pct"])],
            tags=[f"date:{day['date']}"]
        )

if __name__ == "__main__":
    metrics = get_ctxcrl_metrics()
    export_to_datadog(metrics)
    print(f"Exported {len(metrics.get('daily', []))} days to Datadog")
```

### Rust Integration (Using contextcrawler as Library)

```rust
// In your Cargo.toml
// [dependencies]
// contextcrawler = { git = "https://github.com/rtk-ai/rtk" }

use contextcrawler::tracking::{Tracker, TimedExecution};
use anyhow::Result;

fn main() -> Result<()> {
    // Track your own commands
    let timer = TimedExecution::start();

    let input = run_expensive_operation()?;
    let output = run_optimized_operation()?;

    timer.track(
        "expensive_operation",
        "optimized_operation",
        &input,
        &output
    );

    // Query aggregated stats
    let tracker = Tracker::new()?;
    let summary = tracker.get_summary()?;

    println!("Total savings: {} tokens ({:.1}%)",
        summary.total_saved,
        summary.avg_savings_pct
    );

    // Export to JSON for external tools
    let days = tracker.get_all_days()?;
    let json = serde_json::to_string_pretty(&days)?;
    std::fs::write("metrics.json", json)?;

    Ok(())
}
```

## Database Schema

The database holds three tables: `commands` (the savings ledger),
`parse_failures` (commands contextcrawler could not handle and fell back to raw
execution), and `release_boundaries` (one row per binary version upgrade, used
by `gain --weak-filters` to slice from the latest release).

### Table: `commands`

The base table is created with the columns below; `exec_time_ms`,
`project_path`, and `inflation_tokens` are added by idempotent `ALTER TABLE`
migrations on `Tracker::new()`, so an established database has all of them.

```sql
CREATE TABLE commands (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,           -- RFC3339 UTC timestamp
    original_cmd TEXT NOT NULL,        -- Original command (e.g., "ls -la"), secret-scrubbed
    ctxcrl_cmd TEXT NOT NULL,          -- contextcrawler command (e.g., "contextcrawler ls")
    input_tokens INTEGER NOT NULL,     -- Estimated input tokens
    output_tokens INTEGER NOT NULL,    -- Actual output tokens
    saved_tokens INTEGER NOT NULL,     -- max(input - output, 0); floored at zero
    savings_pct REAL NOT NULL,         -- (saved/input) * 100
    exec_time_ms INTEGER DEFAULT 0,    -- Execution time in milliseconds (migration)
    project_path TEXT DEFAULT '',      -- Canonical cwd at execution (migration)
    inflation_tokens INTEGER DEFAULT 0 -- max(output - input, 0); #196 (migration)
);

CREATE INDEX idx_timestamp ON commands(timestamp);
CREATE INDEX idx_project_path_timestamp ON commands(project_path, timestamp);
```

Both `original_cmd` and `ctxcrl_cmd` are passed through `scrub_secrets()` at the
INSERT boundary, so passwords, bearer tokens, AWS keys, GitHub/Slack tokens and
URL-embedded credentials are redacted before they hit disk (they would
otherwise survive 90 days and resurface via `gain --history`).

### Inflation accounting (#196)

`saved_tokens` uses a saturating subtraction, so a filter that emits **more**
tokens than it consumed records as `0` saved, not a negative number, and the
regression vanishes from the headline stats. `inflation_tokens` records the
overflow (`max(output - input, 0)`) honestly so it stays measurable without
making `saved_tokens` signed (which would break the unsigned `SUM`
aggregations). To see output-inflation that the floored `savings_pct` hides:

```sql
SELECT ctxcrl_cmd, SUM(inflation_tokens) AS inflated
FROM commands GROUP BY ctxcrl_cmd
HAVING inflated > 0 ORDER BY inflated DESC;
```

`contextcrawler gain --weak-filters` surfaces the same signal ranked by tool.

### Table: `parse_failures`

```sql
CREATE TABLE parse_failures (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    raw_command TEXT NOT NULL,
    error_message TEXT NOT NULL,
    fallback_succeeded INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_pf_timestamp ON parse_failures(timestamp);
```

Rows here are commands contextcrawler could not parse, so they ran raw and saved
nothing. View them with `contextcrawler gain --failures`.

### Table: `release_boundaries`

```sql
CREATE TABLE release_boundaries (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    installed_at TEXT NOT NULL
);
```

One row is written (atomically, via `INSERT ... SELECT ... WHERE`) the first
time a new binary version runs. `gain --weak-filters` slices from the latest
boundary so newly released filter behaviour is not masked by months of
pre-upgrade leakage; pass `--all-time` to include older rows.

### Automatic Cleanup

On every write operation (`Tracker::record`), records older than 90 days are deleted:

```rust
fn cleanup_old(&self) -> Result<()> {
    let cutoff = Utc::now() - chrono::Duration::days(90);
    self.conn.execute(
        "DELETE FROM commands WHERE timestamp < ?1",
        params![cutoff.to_rfc3339()],
    )?;
    Ok(())
}
```

### Migration Support

The system automatically adds new columns if they don't exist (e.g., `exec_time_ms` was added later):

```rust
// Safe migration on Tracker::new()
let _ = conn.execute(
    "ALTER TABLE commands ADD COLUMN exec_time_ms INTEGER DEFAULT 0",
    [],
);
```

## Performance Considerations

- **SQLite WAL mode**: Enabled (`PRAGMA journal_mode=WAL`) with a 5s busy timeout for concurrent writes
- **auto_vacuum**: Incremental, with a one-time full `VACUUM` migration to convert legacy databases
- **Index on timestamp**: Enables fast date-range queries (plus a `(project_path, timestamp)` index for project-scoped queries)
- **Automatic cleanup**: Prevents database from growing unbounded
- **Token estimation**: ~4 chars = 1 token (simple, fast approximation)
- **Aggregation queries**: Use SQL GROUP BY for efficient aggregation

## Security & Privacy

- **Local storage only**: Tracking database never leaves the machine
- **Telemetry requires consent**: contextcrawler can send a daily anonymous usage ping (version, OS, command counts, token savings). Disabled by default, requires explicit consent via `contextcrawler init` or `contextcrawler telemetry enable`. Manage with `contextcrawler telemetry status/disable/forget`. Override: `CTXCRL_TELEMETRY_DISABLED=1`
- **User control**: Users can delete `~/.local/share/ctxcrl/history.db` anytime
- **90-day retention**: Old data automatically purged

## Troubleshooting

### Database locked error

If you see "database is locked" errors:
- Ensure only one contextcrawler process writes at a time
- Check file permissions on `~/.local/share/ctxcrl/history.db`
- Delete and recreate: `rm ~/.local/share/ctxcrl/history.db && contextcrawler gain`

### Missing exec_time_ms column

Older databases may not have the `exec_time_ms` column. contextcrawler automatically migrates on first use, but you can force it:

```bash
sqlite3 ~/.local/share/ctxcrl/history.db \
  "ALTER TABLE commands ADD COLUMN exec_time_ms INTEGER DEFAULT 0"
```

### Incorrect token counts

Token estimation uses `~4 chars = 1 token`. This is approximate. For precise counts, integrate with your LLM's tokenizer API.

## Future Enhancements

Planned improvements (contributions welcome):

- [ ] Export to Prometheus/OpenMetrics format
- [ ] Support for custom retention periods (not just 90 days)
- [ ] Integration with Claude API for precise token counts
- [ ] Web dashboard (localhost) for visualizing trends

(WAL mode and project-scoped tracking, listed here in earlier revisions, are now
implemented; see Performance Considerations and the `project_path` column.)

## See Also

- [Command & Filter Reference](../guide/commands.md) - every command contextcrawler handles and its savings
- [Rust docs](https://docs.rs/) - Run `cargo doc --open` for API docs
