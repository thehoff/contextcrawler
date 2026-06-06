---
title: Troubleshooting
description: Common contextcrawler issues and how to fix them
sidebar:
  order: 2
---

# Troubleshooting

## `contextcrawler gain` says "not a contextcrawler command"

**Symptom:**
```bash
$ contextcrawler gain
contextcrawler: 'gain' is not a contextcrawler command. See 'contextcrawler --help'.
```

**Cause:** You installed **Rust Type Kit** (`reachingforthejack/rtk`) instead of **Rust Token Killer** (`rtk-ai/rtk`). They share the same binary name.

**Fix:**
```bash
cargo uninstall contextcrawler
curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/master/install.sh | sh
contextcrawler gain    # should now show token savings stats
```

## How to tell which contextcrawler you have

| If `contextcrawler gain`... | You have |
|------------------|----------|
| Shows token savings dashboard | Rust Token Killer ✅ |
| Returns "not a contextcrawler command" | Rust Type Kit ❌ |

## AI assistant not using contextcrawler

**Symptom:** Claude Code (or another agent) runs `cargo test` instead of `contextcrawler cargo test`.

**Checklist:**

1. Verify contextcrawler is installed:
   ```bash
   contextcrawler --version
   contextcrawler gain
   ```

2. Initialize the hook:
   ```bash
   contextcrawler init --global    # Claude Code
   contextcrawler init --global --cursor    # Cursor
   contextcrawler init --global --opencode  # OpenCode
   ```

3. Restart your AI assistant.

4. Verify hook status:
   ```bash
   contextcrawler init --show
   ```

5. Check `settings.json` has the hook registered (Claude Code):
   ```bash
   cat ~/.claude/settings.json | grep contextcrawler
   ```

## contextcrawler not found after `cargo install`

**Symptom:**
```bash
$ contextcrawler --version
zsh: command not found: contextcrawler
```

**Cause:** `~/.cargo/bin` is not in your PATH.

**Fix:**

For bash (`~/.bashrc`) or zsh (`~/.zshrc`):
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

For fish (`~/.config/fish/config.fish`):
```fish
set -gx PATH $HOME/.cargo/bin $PATH
```

Then reload:
```bash
source ~/.zshrc    # or ~/.bashrc
contextcrawler --version
```

## contextcrawler on Windows

### Double-clicking ctxcrl.exe does nothing

**Symptom:** You double-click `ctxcrl.exe`, a terminal flashes and closes instantly.

**Cause:** contextcrawler is a command-line tool. With no arguments, it prints usage and exits. The console window opens and closes before you can read anything.

**Fix:** Open a terminal first, then run contextcrawler from there:
- Press `Win+R`, type `cmd`, press Enter
- Or open PowerShell or Windows Terminal
- Then run: `contextcrawler --version`

### Hook not working (no auto-rewrite)

**Symptom:** `contextcrawler init -g` shows "Falling back to --claude-md mode" on Windows.

**Cause:** The auto-rewrite hook (`rtk-rewrite.sh`) requires a Unix shell. Native Windows doesn't have one.

**Fix:** Use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) for full hook support:
```bash
# Inside WSL
curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh
contextcrawler init -g    # full hook mode works in WSL
```

On native Windows, contextcrawler falls back to CLAUDE.md injection. Your AI assistant gets contextcrawler instructions but won't auto-rewrite commands. It can still use contextcrawler manually: `contextcrawler cargo test`, `contextcrawler git status`, etc.

### Node.js tools not found

**Symptom:**
```
rtk vitest --run
Error: program not found
```

**Cause:** On Windows, Node.js tools are installed as `.CMD`/`.BAT` wrappers. Older rtk versions couldn't find them.

**Fix:** Update to rtk v0.23.1+:
```bash
cargo install --git https://github.com/rtk-ai/rtk
rtk --version    # should be 0.23.1+
```

## Compilation error during installation

```bash
rustup update stable
rustup default stable
cargo clean
cargo build --release
cargo install --path . --force
```

Minimum required Rust version: 1.70+.

## OpenCode not using contextcrawler

```bash
contextcrawler init --global --opencode
# restart OpenCode
contextcrawler init --show    # should show "OpenCode: plugin installed"
```

## `cargo install contextcrawler` installs the wrong package

If Rust Type Kit is published to crates.io under the name `contextcrawler`, `cargo install contextcrawler` may install the wrong one.

Always use the explicit URL:

```bash
cargo install --git https://github.com/rtk-ai/rtk
```

## Run the diagnostic script

From the contextcrawler repository root:

```bash
bash scripts/check-installation.sh
```

Checks:
- contextcrawler installed and in PATH
- Correct version (Token Killer, not Type Kit)
- Available features
- Claude Code integration
- Hook status

## Still stuck?

Open an issue: https://github.com/rtk-ai/rtk/issues
