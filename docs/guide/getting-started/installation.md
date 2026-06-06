---
title: Installation
description: Install contextcrawler via curl, Homebrew, Cargo, or from source, and verify the correct version
sidebar:
  order: 1
---

# Installation

## Name collision warning

Two unrelated projects share the name `contextcrawler`. Make sure you install the right one:

- **Rust Token Killer** (`rtk-ai/rtk`) — this project, a token-saving CLI proxy
- **Rust Type Kit** (`reachingforthejack/rtk`) — a different tool for generating Rust types

The easiest way to verify you have the correct one: run `contextcrawler gain`. It should display token savings stats. If it returns "command not found", you either have the wrong package or contextcrawler is not installed.

## Check before installing

```bash
contextcrawler --version   # should print: contextcrawler x.y.z
contextcrawler gain        # should show token savings stats
```

If both commands work, contextcrawler is already installed. Skip to [Project initialization](#project-initialization).

## Quick install (Linux and macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/master/install.sh | sh
```

## Homebrew (macOS and Linux)

```bash
brew install rtk-ai/tap/contextcrawler
```

## Cargo

:::caution[Name collision risk]
`cargo install contextcrawler` may install **Rust Type Kit** instead of Rust Token Killer — two unrelated projects share the same crate name. Use the explicit Git URL to guarantee the correct package:
:::

```bash
cargo install --git https://github.com/rtk-ai/rtk contextcrawler
```

## Pre-built binaries (Windows, Linux, macOS)

Download from [GitHub releases](https://github.com/rtk-ai/rtk/releases):

- macOS: `ctxcrl-x86_64-apple-darwin.tar.gz` / `ctxcrl-aarch64-apple-darwin.tar.gz`
- Linux: `ctxcrl-x86_64-unknown-linux-musl.tar.gz` / `ctxcrl-aarch64-unknown-linux-gnu.tar.gz`
- Windows: `ctxcrl-x86_64-pc-windows-msvc.zip`

**Windows users**: Extract the zip and place `ctxcrl.exe` in a directory on your PATH. Run contextcrawler from Command Prompt, PowerShell, or Windows Terminal — do not double-click the `.exe` (it prints usage and exits immediately). For full hook support, use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) instead.

## Verify installation

```bash
contextcrawler --version   # contextcrawler x.y.z
contextcrawler gain        # token savings dashboard
```

If `contextcrawler gain` fails but `contextcrawler --version` succeeds, you installed Rust Type Kit by mistake. Uninstall it first:

```bash
cargo uninstall contextcrawler
```

Then reinstall using one of the methods above.

## Project initialization

Run once per project to enable the Claude Code hook:

```bash
contextcrawler init
```

For a global install that patches `settings.json` automatically:

```bash
contextcrawler init --global
```

## Uninstall

```bash
contextcrawler init -g --uninstall    # remove hook, contextcrawler.md, and settings.json entry
cargo uninstall contextcrawler         # remove binary (if installed via Cargo)
brew uninstall contextcrawler          # remove binary (if installed via Homebrew)
```
