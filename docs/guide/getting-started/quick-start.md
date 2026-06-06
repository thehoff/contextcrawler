---
title: Quick Start
description: Get contextcrawler running in 5 minutes and see your first token savings
sidebar:
  order: 2
---

# Quick Start

This guide walks you through your first contextcrawler commands after installation.

## Prerequisites

contextcrawler is installed and verified:

```bash
contextcrawler --version   # contextcrawler x.y.z
contextcrawler gain        # shows token savings dashboard
```

If not, see [Installation](./installation.md).

## Step 1: Initialize for your AI assistant

```bash
# For Claude Code (global — applies to all projects)
contextcrawler init --global

# For a single project only
cd /your/project && contextcrawler init
```

This installs the hook that automatically rewrites commands. Restart your AI assistant after this step.

### Preview without writing: `--dry-run`

To see exactly what `init` would change before it touches anything, add `--dry-run`:

```bash
contextcrawler init --global --dry-run
```

Every would-be file create/update/patch is printed with a `[dry-run] would ...` prefix, then a `[dry-run] Nothing written.` footer. Nothing on disk is modified, no settings.json is patched, and the telemetry consent prompt is skipped. Combine with `-v` to also print the full content contextcrawler would write:

```bash
contextcrawler init --global --dry-run -v
```

`--dry-run` works for every init flavour (`--agent cursor`, `--gemini`, `--codex`, `--copilot`, `--uninstall`, ...). It cannot be combined with `--show`.

## Step 2: Use your tools normally

Once the hook is installed, nothing changes in how you work. Your AI assistant runs commands as usual — the hook intercepts them transparently and rewrites them before execution.

For example, when Claude Code runs `cargo test`, the hook rewrites it to `contextcrawler cargo test` before it executes. The LLM receives filtered output with only the failures — not 500 lines of passing tests. You never see or type `contextcrawler`.

contextcrawler covers all major ecosystems — Git, Cargo/Rust, JavaScript, Python, Go, Ruby, .NET, Docker/Kubernetes, and more. See [What contextcrawler Optimizes](../resources/what-rtk-covers.md) for the full list.

## Step 3: Check your savings

After a few commands, see how much was saved:

```bash
contextcrawler gain
```

```
Total commands : 12
Input tokens   : 45,230
Output tokens  : 4,890
Saved          : 40,340  (89.2%)
```

## Step 4: Unsupported commands

Commands contextcrawler doesn't recognize run through passthrough — output is unchanged, usage is tracked:

```bash
contextcrawler proxy make install
```

## Next steps

- [What contextcrawler Optimizes](../resources/what-rtk-covers.md) — all supported commands and savings by ecosystem
- [Supported agents](./supported-agents.md) — Claude Code, Cursor, Copilot, and more
- [Configuration](./configuration.md) — customize contextcrawler behavior
