---
title: Installation
description: Install contextcrawler from source with Cargo, wire up the Claude Code hook, and verify it works
sidebar:
  order: 1
---

# Installation

contextcrawler is a single-maintainer downstream fork. **There are no
pre-built binaries and no published crate** — you build it from source
with a Rust toolchain. Installation is always through Cargo, never by
copying a binary into a directory by hand.

## Requirements

- Rust toolchain via [`rustup`](https://rustup.rs), stable channel, **1.80
  or newer** (older toolchains fail to compile).
- A Unix shell for full hook support (macOS / Linux, or WSL on Windows).

## Check before installing

If contextcrawler is already on your `PATH`, these both succeed:

```bash
contextcrawler --version   # e.g. contextcrawler 0.4.0
contextcrawler gain        # token-savings dashboard (not "command not found")
```

If they work, skip to [Wire up the Claude Code hook](#wire-up-the-claude-code-hook).

## Install from source

### From a clone (recommended — read the diff first)

```bash
git clone https://github.com/thehoff/contextcrawler.git
cd contextcrawler
git checkout v0.4.0          # pin to the latest tagged release
cargo install --path .       # builds and installs to ~/.cargo/bin/
```

### Straight from git

```bash
cargo install --git https://github.com/thehoff/contextcrawler --tag v0.4.0 --locked
```

Bump the `--tag` value when newer releases ship; see the
[releases page](https://github.com/thehoff/contextcrawler/releases).

### Bleeding edge

Unreleased fixes on `develop` (expect churn):

```bash
cargo install --git https://github.com/thehoff/contextcrawler --branch develop --locked
```

Either way the binary lands in `~/.cargo/bin/contextcrawler`. Make sure
`~/.cargo/bin` is on your `PATH`.

> A path-remapped build is available via `scripts/build-release.sh` (it sets
> `--remap-path-prefix` so the binary doesn't embed your `$HOME` /
> `$CARGO_HOME` / workspace paths in backtrace metadata). For a normal
> install, prefer `cargo install --path .`.

## Migrating from upstream rtk or contextzip

If you previously ran upstream `rtk` or `jee599/contextzip`, old hook
entries may still point at the old binary or `~/.claude/hooks/rtk-rewrite.sh`
and will silently fail-open once contextcrawler takes over. Clean them out
first:

```bash
# If you still have the old binary, use its own uninstall.
rtk init -g --uninstall 2>/dev/null || true

# Then check (and remove leftovers manually) in:
#   ~/.claude/settings.json        — PreToolUse hook entry
#   ~/.claude/hooks/rtk-rewrite.sh — leftover hook script
#   ~/.cursor/hooks.json           — Cursor hook entry
```

Legacy `RTK_*` environment variables are still honoured via a shim, so an
existing `RTK_DISABLED=1` keeps working after the switch.

## Wire up the Claude Code hook

`init -g` registers the hook for one agent per invocation. For Claude Code:

```bash
contextcrawler init -g       # global: patches ~/.claude/settings.json
```

For a single project only (writes project-local config instead of global):

```bash
cd /your/project && contextcrawler init
```

Restart Claude Code afterwards. To preview what `init` would change without
touching anything, add `--dry-run` (combine with `-v` to print the content
it would write):

```bash
contextcrawler init -g --dry-run -v
```

### What the hook entry looks like

`init -g` adds a `PreToolUse` hook to `~/.claude/settings.json` whose
command is `contextcrawler hook claude`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "contextcrawler hook claude" }
        ]
      }
    ]
  }
}
```

The hook reads the Claude Code tool payload from stdin, decides whether to
rewrite the command to its filtered equivalent, and runs the optional
gates. If contextcrawler is missing or errors, the hook fails open and the
raw command runs unchanged.

Other agents are wired the same way with a different flag (`--gemini`,
`--copilot`, `--codex`, `--opencode`, or `--agent <name>`). See
[Supported agents](./supported-agents.md).

## Config and data locations

| What | Path (Linux; macOS uses the platform equivalent) |
|---|---|
| Core config | `~/.config/ctxcrl/config.toml`, `~/.config/ctxcrl/filters.toml` |
| Savings history (SQLite) | `~/.local/share/ctxcrl/history.db` |
| Tee'd raw output (on failure) | `~/.local/share/ctxcrl/tee/` |
| Supply-chain config (opt-in) | `~/.config/contextcrawler/supply-chain.toml` |
| Tirith downgrade log | `~/.local/share/contextcrawler/downgrades.jsonl` |

Environment variables use the `CTXCRL_*` prefix (for example
`CTXCRL_DISABLED=1`, `CTXCRL_TEE_DIR`, `CTXCRL_TELEMETRY_DISABLED=1`). The
legacy `RTK_*` names are still honoured. See [Configuration](./configuration.md)
for the full list.

## Verify

```bash
contextcrawler --version   # contextcrawler 0.4.0
contextcrawler gain        # token-savings dashboard
contextcrawler init --show # shows what's currently registered
which contextcrawler       # should resolve to ~/.cargo/bin/contextcrawler
```

## Uninstall

```bash
contextcrawler init -g --uninstall   # remove the hook + settings.json entry
cargo uninstall contextcrawler        # remove the binary
```
