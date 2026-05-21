# ContextCrawler — Reference Tables

This document collects the key reference tables from the ContextCrawler
documentation so they can be consulted at a glance.

## Token Savings by Command Category

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

## Commit Type Reference

| Type | Semver Impact | When to Use |
|------|---------------|-------------|
| `feat` | Minor | New features, new filters, new command support |
| `fix` | Patch | Bug fixes, corrections |
| `perf` | Patch | Performance improvements |
| `refactor` | — | Code restructuring (no changelog entry) |
| `docs` | — | Documentation only |
| `chore` | — | Maintenance, CI, deps |
| `feat!` / `fix!` | Major | Breaking changes (add `!` after type) |

## Branch Naming Prefixes

| Prefix | When to Use |
|--------|-------------|
| `fix/` | Bug fixes, corrections, minor adjustments |
| `feat/` | New features, new filters, new command support |
| `chore/` | CI/CD, deps, maintenance, breaking changes |

## TOML vs Rust Filter Decision Matrix

| Use TOML filter when | Use Rust module when |
|----------------------|----------------------|
| Output is plain text with predictable line structure | Output is structured (JSON, NDJSON) |
| Regex line filtering achieves 60%+ savings | Needs state machine parsing (e.g., pytest phases) |
| No need to inject CLI flags | Needs to inject flags like `--format json` |
| No cross-command routing | Routes to other commands (lint → ruff/mypy) |
| Examples: brew, df, shellcheck, rsync, ping | Examples: vitest, pytest, golangci-lint, gh |

## Documentation Update Reference

| What you changed | Update these docs |
|------------------|-------------------|
| New Rust filter (`src/cmds/`) | Ecosystem README.md, top-level README command list |
| New TOML filter (`src/filters/`) | `src/filters/README.md` if naming conventions change |
| New rewrite pattern | `src/discover/rules.rs` |
| Core infrastructure (`src/core/`) | `src/core/README.md`, `docs/contributing/TECHNICAL.md` |
| Hook system (`src/hooks/`) | `src/hooks/README.md`, `hooks/README.md` |
| Architecture or design change | `ARCHITECTURE.md`, `docs/contributing/TECHNICAL.md` |

## Contribution Type Examples

| Type | Examples |
|------|----------|
| **Report** | File a clear issue with steps to reproduce, expected vs actual behavior |
| **Fix** | Bug fixes, broken filter repairs |
| **Build** | New filters, new command support, new features |
| **Review** | Review open PRs, test changes locally, leave constructive feedback |
| **Document** | Improve docs, clarify existing content |

## Test Type Reference

| Type | Where | Run With |
|------|-------|----------|
| **Unit tests** | `#[cfg(test)] mod tests` in each module | `cargo test` |
| **Snapshot tests** | `assert_snapshot!()` via `insta` crate | `cargo test` + `cargo insta review` |
| **Smoke tests** | `scripts/test-all.sh` (69 assertions) | `bash scripts/test-all.sh` |
| **Integration tests** | `#[ignore]` tests requiring installed binary | `cargo test --ignored` |

## Performance Targets

| Metric | Target | Verification Method |
|--------|--------|---------------------|
| Startup time | < 10 ms | `hyperfine 'contextcrawler <cmd>'` |
| Memory usage | < 5 MB | `/usr/bin/time -l contextcrawler <cmd>` |
| Binary size | < 5 MB | `ls -lh target/release/contextcrawler` |
| Token savings | >= 60% per filter | Assertion in unit tests |

## Tracking Database Schema

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment row identifier |
| `timestamp` | TEXT | ISO 8601 UTC timestamp of execution |
| `original_cmd` | TEXT | Standard command (e.g., `ls -la`) |
| `rtk_cmd` | TEXT | Proxy command (e.g., `contextcrawler ls`) |
| `input_tokens` | INTEGER | Estimated tokens in unfiltered output |
| `output_tokens` | INTEGER | Actual tokens in filtered output |
| `saved_tokens` | INTEGER | Difference: input minus output |
| `savings_pct` | REAL | Savings as percentage of input |
| `exec_time_ms` | INTEGER | Wall-clock execution time in milliseconds |
