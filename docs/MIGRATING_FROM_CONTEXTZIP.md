# Migrating from jee599/contextzip to ContextCrawler

If you've been using [jee599/contextzip](https://github.com/jee599/contextzip)
and want to move to ContextCrawler, this is the guide.

## TL;DR

| | jee599/contextzip 0.2.0 | ContextCrawler 0.1.0 |
|---|---|---|
| Upstream base | rtk 0.30.1 | rtk 0.39.0 |
| Behind upstream | 9 minor versions | current |
| Binary name | `contextzip` | `contextcrawler` (single binary) |
| Session compactor | `contextzip compact <id>` | `contextcrawler sessions compact <id>` |
| Stacktrace compression | yes | yes (ported) |
| HTML/web extraction | yes | yes (ported as `contextcrawler web`) |
| Build-error grouping | yes (generic regex post-processor) | dropped — subsumed by rtk 0.39's per-language modules |
| Tirith integration | no | optional, opt-in defense-in-depth gate |
| Auto-allow gate behavior | rtk 0.30.x default-allow | rtk 0.39.x verdict system: default-ask, only allow on explicit rules |
| Telemetry | scaffolded, off | none |
| Self-update | yes (unsigned) | none — install via `cargo install` or rebuild |

## What you keep

Everything contextzip already did continues to work — under the unified
`contextcrawler` binary:

- **Session JSONL compaction** is now `contextcrawler sessions compact <id>`
  (was `contextzip compact <id>`). The compactor module itself is the same
  proven implementation.
- **Multi-language stacktrace compression** is now a post-processor inside
  the runner pipeline (no user-visible command — fires automatically on
  failed-test output etc.).
- **HTML content extraction** is now `contextcrawler web <url>` (was
  `contextzip web <url>`).
- **Everything rtk does** — git, cargo, npm, pnpm, vitest, playwright,
  docker, kubectl, etc. — also available as subcommands. ContextCrawler is
  a full rtk distribution under a different name.

## What's new

- **9 minor versions of upstream rtk improvements**, including:
  - permission verdict system (deny / ask / allow / default), with default = ask
  - lexer-based compound-command splitter (better quoting / heredoc handling)
  - new per-language modules: vitest, playwright, prisma, rake, rspec, rubocop,
    and more
  - additional agent hook integrations: codex, cursor, copilot VS Code, opencode,
    hermes, kilocode, antigravity, windsurf
  - 60+ TOML filter configs for misc tools (stat, ps, df, gcloud, sops,
    terraform, rsync, fail2ban, iptables, ...)
- **Tirith pre-execution gate** at the auto-allow boundary, when
  [`tirith`](https://tirith.sh) is installed. Subprocess invocation only —
  no statically-linked AGPL code.
- **`contextcrawler security`** subcommand — surfaces Tirith audit stats and
  the ContextCrawler gate state. `--log` tails the downgrade-event log.

## What's gone

- **`build_cmd` post-processor** — contextzip 0.2.0's generic build-error
  grouper. Subsumed by rtk 0.39's per-language modules. See
  [`notes/decision-skip-build_cmd.md`](notes/decision-skip-build_cmd.md).
- **Telemetry scaffolding.** ContextCrawler does not phone home.
- **Self-update command.** Update via `cargo install` or rebuild from source.

## Migration steps

### 1. Uninstall existing contextzip (and/or rtk)

If you also ran upstream `rtk` at any point, do the same cleanup for
its hook artifacts — otherwise stale `PreToolUse` entries pointing at
the old `rtk` binary will silently fail-open once `contextcrawler`
takes over.

```sh
# Old contextzip binary + hook
rm -f ~/.local/bin/contextzip
rm -f ~/.claude/hooks/contextzip-rewrite.sh
rm -f ~/.claude/hooks/.contextzip-hook.sha256

# Old rtk binary + hook (skip if you never used it)
rtk init -g --uninstall 2>/dev/null || true
rm -f ~/.local/bin/rtk
rm -f ~/.claude/hooks/rtk-rewrite.sh
rm -f ~/.claude/RTK.md

# Clean the settings.json hook entries: edit ~/.claude/settings.json
# and remove any hooks.PreToolUse entry referencing
# contextzip-rewrite.sh, rtk-rewrite.sh, or the `rtk` binary directly.
# Repeat for ~/.cursor/hooks.json if you used Cursor, and any other
# agent configs (codex, windsurf, cline, kilocode, antigravity).
```

### 2. Build ContextCrawler

```sh
git clone https://github.com/thehoff/contextcrawler.git
cd contextcrawler
git checkout v0.1.2          # pin to the latest tagged release
cargo build --release
cp target/release/contextcrawler ~/.local/bin/contextcrawler
```

Or, if you prefer the one-liner:

```sh
cargo install --git https://github.com/thehoff/contextcrawler --tag v0.1.2 --locked
```

Bump the tag for newer releases — see
[github.com/thehoff/contextcrawler/releases](https://github.com/thehoff/contextcrawler/releases).

### 3. Install the hook

```sh
contextcrawler init -g
```

This drops `~/.claude/CONTEXTCRAWLER.md` and an `@CONTEXTCRAWLER.md`
reference into your `~/.claude/CLAUDE.md` (an old `RTK.md` from a previous
rtk install is cleaned up automatically). To wire the Claude Code
PreToolUse hook, add this to
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{ "type": "command", "command": "contextcrawler hook claude" }]
    }]
  }
}
```

Then restart Claude Code.

### 4. (Optional) Install Tirith for the defense-in-depth gate

```sh
cargo install tirith   # binary on PATH is all the gate needs
# Optional separately: have Tirith vet your interactive shell commands too.
# eval "$(tirith init --shell zsh)"   # or bash / fish
```

ContextCrawler invokes `tirith` as a subprocess from the agent path —
no shell preexec hook required. The gate is fail-open by default: no
Tirith means no gate, but nothing breaks.

### 5. Verify

```sh
contextcrawler --version
# contextcrawler ContextCrawler 0.1.0 (downstream of rtk 0.39.0)

contextcrawler security
# Shows Tirith integration status, gate mode, and audit stats if Tirith is installed.

contextcrawler gain
# Your existing token-savings DB at ~/Library/Application Support/contextzip/history.db
# is preserved and continues to accumulate.

contextcrawler sessions compact --all-sessions --dry-run
# Preview session-log compaction across all your Claude projects.
```

## Things to know

### Your tracking database is preserved

The SQLite DB at `~/Library/Application Support/contextzip/history.db` is
read by ContextCrawler unchanged. `contextcrawler gain` will continue to
show your historical savings stats from contextzip days.

### New log location

The Tirith gate downgrade log writes to
`~/Library/Application Support/contextcrawler/downgrades.jsonl` (separate
from contextzip's data directory). The two don't interfere.

### Hook compatibility

ContextCrawler's hook is a built-in subcommand (`contextcrawler hook claude`)
rather than a separate shell script. The hook script file the upstream rtk
ships (`hooks/claude/rtk-rewrite.sh`) is also patched to call `contextcrawler`
if you prefer the shell-script approach.

## Reporting issues

Issues specific to ContextCrawler: please file them in the ContextCrawler
repo (see the README for the URL).

For issues that look like an upstream rtk concern, please consider also
opening one with [rtk-ai/rtk](https://github.com/rtk-ai/rtk) — they're
actively maintained and most rtk-level bugs benefit everyone if fixed there.
