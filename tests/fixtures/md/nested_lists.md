# ContextCrawler — Nested Feature Reference

This document describes ContextCrawler's features in nested list format,
covering commands, configuration, and hook integration.

## Command Categories

- **File system commands**
   - `ls` — compact directory listing, tree format output
      1. Supports all native `ls` flags (`-l`, `-a`, `-h`, `-R`)
      2. Groups output by directory when recursing
      3. Shows file sizes and modification dates inline
   - `tree` — proxy to native `tree` with filtered output
      1. Removes decorative box-drawing characters in compact mode
      2. Preserves depth indicators for navigation context
      3. Strips empty directories from output
   - `read` — file reading with symmetric head/tail cap
      1. Default cap: 80 lines head, 80 lines tail
      2. Provides a two-line marker with an escape hatch
      3. Passthrough extensions: `.svelte`, `.astro`, and similar

- **Git commands**
   - `git status` — compact status with change counts
      1. Groups staged, unstaged, and untracked files
      2. Omits repetitive boilerplate headers
      3. Shows branch name and upstream tracking status
   - `git log` — condensed commit history
      1. One line per commit: hash, message, author, date
      2. Merge commits preserved to avoid context loss
      3. Supports all native `git log` flags transparently
   - `git diff` — compact diff with 80% token reduction
      1. Preserves all changed lines verbatim
      2. Removes unchanged context hunk headers
      3. Collapses binary diff lines to single summary

- **Test runners**
   - `cargo test` — failures only (90%+ savings)
      1. Strips passing test lines
      2. Preserves full failure messages with line numbers
      3. Preserves panic backtraces in failure mode
   - `pytest` — failures only with structured output
      1. Strips collection output for passing tests
      2. Groups failures by module
      3. Preserves diff output from `assert` comparisons
   - `vitest` — failures only (99.5% savings)
      1. Removes ANSI progress animations
      2. Keeps failing test file paths and error messages
      3. Preserves stack traces trimmed to project root

## Hook Integration

1. Claude Code hooks
   1. Pre-tool hook intercepts bash commands
      - Checks command against rewrite registry
      - Rewrites matched commands with `contextcrawler` prefix
      - Passes unrecognised commands through unchanged
   2. Post-tool hook records analytics
      - Writes token counts to SQLite database
      - Updates running savings totals
      - Triggers cleanup of records older than 90 days
   3. Stop hook reports session summary
      - Calculates session-level savings percentage
      - Prints compact one-line summary to stderr
      - Skips output when savings are below threshold

2. Codex CLI hooks
   1. Awareness template instructs model to use `contextcrawler` prefix
      - Includes WRONG/RIGHT example pairs
      - Adds self-check instruction at end of template
      - Empirical compliance improved from 0% to 80% after rollout
   2. Gate hook blocks dangerous command patterns
      - Blocks `curl | bash` and similar pipe-to-interpreter shapes
      - Checks entropy of environment variable values for secrets
      - Allows override via `tirith trust add` for known-safe hosts

3. Gemini CLI hooks
   - Pre-execution hook validates command safety
   - Rewrite hook applies `contextcrawler` prefix
   - No post-execution hook yet (planned)

## Configuration Hierarchy

- Global configuration (`~/.config/rtk/config.toml`)
   - `tracking.database_path` — override default SQLite path
   - `tracking.retention_days` — override 90-day default
   - `filter.strip_ansi` — control ANSI stripping globally
- Project-local configuration (`.rtk/config.toml`)
   - Overrides global configuration for the current project
   - Committed to the repository for team-wide consistency
- TOML filter files
   - Global filters: `~/.config/rtk/filters/*.toml`
   - Project-local filters: `.rtk/filters/*.toml`
      1. Loaded in alphabetical order
      2. Project-local rules override global rules with same name
      3. Rules specify: match pattern, action, max lines, deduplicate

## Tracking Analytics

- `contextcrawler gain` — overall savings summary
   - Total commands recorded since installation
   - Total tokens saved in absolute numbers
   - Average savings percentage across all commands
   - Top 10 commands by token savings
- `contextcrawler gain --history` — per-command breakdown
   - Grouped by command name
   - Shows median and p90 savings per command
   - Flags commands with savings below 60% threshold
- `contextcrawler discover` — missed opportunity analysis
   - Reads Claude Code session transcripts
   - Identifies commands that were run without `contextcrawler` prefix
   - Reports potential savings if the prefix had been used
