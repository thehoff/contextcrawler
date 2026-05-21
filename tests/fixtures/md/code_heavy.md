# ContextCrawler — Code Reference

This document collects key code examples from the ContextCrawler codebase,
covering the public tracking API, filter implementation patterns, and
hook integration snippets.

## Tracker Public API

The `Tracker` struct is the main interface for recording and querying
command execution history.

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
        original_cmd: &str,
        rtk_cmd: &str,
        input_tokens: usize,
        output_tokens: usize,
        exec_time_ms: u64,
    ) -> Result<()>;

    /// Get overall summary statistics
    pub fn get_summary(&self) -> Result<GainSummary>;

    /// Get recent command history (limit = max records)
    pub fn get_recent(&self, limit: usize) -> Result<Vec<CommandRecord>>;
}
```

## Basic Tracking Usage

```rust
use contextcrawler::tracking::{TimedExecution, Tracker};

fn main() -> anyhow::Result<()> {
    let timer = TimedExecution::start();

    let input = execute_original_command()?;
    let output = execute_rtk_command()?;

    timer.track("ls -la", "contextcrawler ls", &input, &output);

    Ok(())
}
```

## Filter Implementation Pattern

Every command module follows this structure. The fallback on error is
mandatory — the user must never be left without output.

```rust
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref ERROR_RE: Regex = Regex::new(r"^error\[").unwrap();
    static ref HASH_RE: Regex = Regex::new(r"^[0-9a-f]{7,40}").unwrap();
}

pub fn run(args: MyArgs) -> Result<()> {
    let output = execute_command("mycmd", &args.to_cmd_args())
        .context("Failed to execute mycmd")?;

    let filtered = filter_output(&output.stdout)
        .unwrap_or_else(|e| {
            eprintln!("contextcrawler: filter warning: {}", e);
            output.stdout.clone()
        });

    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }
    print!("{}", filtered);
    Ok(())
}

fn filter_output(input: &str) -> Result<String> {
    let lines: Vec<&str> = input.lines()
        .filter(|l| ERROR_RE.is_match(l) || HASH_RE.is_match(l))
        .collect();
    Ok(lines.join("\n"))
}
```

## Token Savings Test Pattern

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;

    fn count_tokens(text: &str) -> usize {
        text.split_whitespace().count()
    }

    #[test]
    fn test_output_format() {
        let input = include_str!("../tests/fixtures/mycmd_raw.txt");
        let output = filter_output(input).unwrap();
        assert_snapshot!(output);
    }

    #[test]
    fn test_token_savings() {
        let input = include_str!("../tests/fixtures/mycmd_raw.txt");
        let output = filter_output(input).unwrap();
        let savings = 100.0
            - (count_tokens(&output) as f64 / count_tokens(input) as f64 * 100.0);
        assert!(savings >= 60.0, "Expected >=60% savings, got {:.1}%", savings);
    }
}
```

## Hook Pre-Tool Script (Bash)

```bash
#!/usr/bin/env bash
# .claude/hooks/pre-tool-use.sh
set -euo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [[ "$TOOL" != "Bash" ]] || [[ -z "$CMD" ]]; then
    echo "$INPUT"
    exit 0
fi

REWRITTEN=$(contextcrawler rewrite "$CMD" 2>/dev/null || echo "$CMD")

if [[ "$REWRITTEN" != "$CMD" ]]; then
    echo "$INPUT" | jq --arg cmd "$REWRITTEN" \
        '.tool_input.command = $cmd'
else
    echo "$INPUT"
fi
```

## TOML Filter Example

```toml
# .rtk/filters/shellcheck.toml
[[rules]]
name = "shellcheck_summary"
match = "^In .* line \\d+"
action = "keep"
max_lines = 50

[[rules]]
name = "shellcheck_noise"
match = "^\\s*\\^"
action = "drop"

[[rules]]
name = "shellcheck_note"
match = "^note:"
action = "drop"
```

## JSON Export Schema

The tracking database exports statistics in this format:

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

## CI Pre-Commit Gate

```bash
#!/usr/bin/env bash
# Must pass before any PR is merged
set -euo pipefail

cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

## Python Passthrough Tracking

```python
import subprocess
import time

def run_with_tracking(cmd: list[str]) -> subprocess.CompletedProcess:
    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    # Token estimation: ~4 chars per token
    input_tokens = len(result.stdout) // 4
    print(f"[contextcrawler] {' '.join(cmd)}: {input_tokens} tokens in {elapsed_ms}ms",
          file=sys.stderr)
    return result
```
