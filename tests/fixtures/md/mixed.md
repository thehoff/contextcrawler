# ContextCrawler — Comprehensive Reference

**ContextCrawler** is a token-optimised CLI proxy that sits between your
coding agent and system commands. It saves 60-90% of LLM tokens on common
development operations by filtering and compressing command output before
it reaches your agent's context window.

<!-- This comment should be stripped at tier 1 -->

## Overview

The tool rewrites commands transparently via hooks. When an agent runs
`git status`, the hook silently rewrites it to `contextcrawler git status`.
The filtered output is _functionally equivalent_ but **dramatically shorter**.

> The goal is not to hide information but to remove noise. Every token
> saved is a token that can carry real payload.

For installation and initial setup, see the [quick-start guide](docs/guide/getting-started/QUICKSTART.md).
For the full command reference, visit [the features page](docs/usage/FEATURES.md).

---

## Token Savings by Category

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget, web | 65-70% |

### Filter Decision Matrix

| Use TOML filter when | Use Rust module when |
|----------------------|----------------------|
| Plain text with predictable line structure | Structured output (JSON, NDJSON) |
| Regex achieves 60%+ savings | Needs state machine parsing |
| No CLI flag injection needed | Needs to inject flags like `--format json` |
| No cross-command routing | Routes to other commands |

---

## Design Principles

The four non-negotiable principles are:

1. **Correctness first** — when a user requests verbose output, honour it.
   Flags like `--nocapture`, `-v`, and `-la` are explicit requests that
   override the default compression.

2. **Transparency** — filtered output must look like a shorter version of
   real command output. Never add proxy-specific headers or markers.

3. **Never block** — if filtering fails for any reason, pass through the
   raw output unchanged. An unhelpful filter is worse than no filter.

4. **Zero overhead** — startup must stay under 10 ms. No async runtime,
   no network calls, no disk I/O on the critical path.

---

## Implementation Reference

### Rust Filter Pattern

Every command module follows this mandatory structure:

```rust
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref ERROR_RE: Regex = Regex::new(r"^error\[E\d{4}\]").unwrap();
}

pub fn run(args: MyArgs) -> Result<()> {
    let output = execute_command("cmd", &args.to_cmd_args())
        .context("Failed to execute cmd")?;

    // Fallback is mandatory — never return Err here
    let filtered = filter_output(&output.stdout)
        .unwrap_or_else(|e| {
            eprintln!("contextcrawler: filter warning: {}", e);
            output.stdout.clone()
        });

    print!("{}", filtered);

    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }
    Ok(())
}
```

### TOML Filter DSL

For plain-text commands without state, TOML filters are faster to write:

```toml
[[rules]]
name = "keep_errors"
match = "^error:"
action = "keep"
max_lines = 50

[[rules]]
name = "drop_noise"
match = "^\\s*$"
action = "drop"
```

### Hook Script (Bash)

```bash
#!/usr/bin/env bash
set -euo pipefail
INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
REWRITTEN=$(contextcrawler rewrite "$CMD" 2>/dev/null || echo "$CMD")
echo "$INPUT" | jq --arg cmd "$REWRITTEN" '.tool_input.command = $cmd'
```

---

## Command Reference

### File System

- `contextcrawler ls` — compact directory listing
   - Supports all native `ls` flags (`-l`, `-a`, `-h`, `-R`)
   - Groups output by directory when recursing
   - Shows file sizes and modification times inline

- `contextcrawler read` — file reading with symmetric 80/80 head/tail cap
   - Provides escape hatch marker for full content recovery
   - Passthrough extensions: `.svelte`, `.astro`

### Version Control

- `contextcrawler git status` — compact status with change counts
   - Groups staged, unstaged, and untracked separately
   - Shows branch and upstream tracking status

- `contextcrawler git log` — condensed commit history
   - One line per commit: hash, message, author, date
   - Merge commits preserved

- `contextcrawler git diff` — compact diff at 80% savings
   - All changed lines preserved verbatim
   - Unchanged context hunk headers removed

### Testing

- `contextcrawler cargo test` — 90%+ savings
   1. Strips all passing test lines
   2. Preserves full failure messages with line numbers
   3. Preserves panic backtraces on failure

- `contextcrawler pytest` — failures only
   1. Strips collection output
   2. Groups failures by module
   3. Preserves assertion diffs

- `contextcrawler vitest` — 99.5% savings
   1. Removes ANSI progress animations
   2. Keeps failing test paths and error messages
   3. Preserves trimmed stack traces

---

## Analytics

The `gain` command reports aggregate token savings across all recorded
sessions. Data is stored in SQLite at the platform-default path.

| Platform | Database Path |
|----------|---------------|
| Linux | `~/.local/share/rtk/tracking.db` |
| macOS | `~/Library/Application Support/rtk/tracking.db` |
| Windows | `%APPDATA%\rtk\tracking.db` |

Records older than **90 days** are automatically purged on each write
to prevent unbounded database growth.

Use `contextcrawler gain` for the overall summary and
`contextcrawler gain --history` for the per-command breakdown.
The `contextcrawler discover` command analyses your Claude Code session
transcripts and identifies commands that were run without the proxy
prefix, reporting the potential savings you missed.

---

## Changelog Highlights

The following improvements landed in recent releases:

- **Read filter** — symmetric 80/80 head/tail cap (was 80/20). Closes #12.
- **Grep pre-clap intercept** — format flags `-c`, `-L`, `-o`, `-Z` now
  route directly through `rg` before clap can reject them. Closes #13.
- **Slim-instructions filename fix** — `RTK.md` constant corrected to
  `CONTEXTCRAWLER.md` throughout. Closes #19.
- **`--version` output** — now prints `contextcrawler X.Y.Z` correctly.
  Previously printed `rtk 0.39.0`. Closes #22.
- **Branding lint** — new test in `tests/branding_lint.rs` prevents
  upstream rebase from silently reverting the rebrand. Closes #20.
