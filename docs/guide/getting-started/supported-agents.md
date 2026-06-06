---
title: Supported Agents
description: How to integrate contextcrawler with Claude Code, Cursor, Copilot, Cline, Windsurf, Codex, OpenCode, Hermes, Kilo Code, and Antigravity
sidebar:
  order: 3
---

# Supported Agents

contextcrawler supports all major AI coding agents across 3 integration tiers. Mistral Vibe support is planned.

## How it works

Each agent integration intercepts CLI commands before execution and rewrites them to their contextcrawler equivalent. The agent runs `contextcrawler cargo test` instead of `cargo test`, sees filtered output, and uses up to 90% fewer tokens — without any change to your workflow.

All rewrite logic lives in the contextcrawler binary (`contextcrawler rewrite`). Agent hooks are thin delegates that parse the agent-specific JSON format and call `contextcrawler rewrite` for the actual decision.

```
Agent runs "cargo test"
  -> Hook intercepts (PreToolUse / plugin event)
  -> Calls contextcrawler rewrite "cargo test"
  -> Returns "contextcrawler cargo test"
  -> Agent executes filtered command
  -> LLM sees 90% fewer tokens
```

## Supported agents

| Agent | Integration tier | Can rewrite transparently? |
|-------|-----------------|---------------------------|
| Claude Code | Shell hook (`PreToolUse`) | Yes |
| VS Code Copilot Chat | Shell hook (`PreToolUse`) | Yes |
| GitHub Copilot CLI | Shell hook (deny-with-suggestion) | No (agent retries) |
| Cursor | Shell hook (`preToolUse`) | Yes |
| Gemini CLI | Rust binary (`BeforeTool`) | Yes |
| OpenCode | TypeScript plugin (`tool.execute.before`) | Yes |
| Hermes | Python plugin (`terminal` command mutation) | Yes |
| Cline / Roo Code | Rules file (prompt-level) | N/A |
| Windsurf | Rules file (prompt-level) | N/A |
| Codex CLI | AGENTS.md instructions | N/A |
| Kilo Code | Rules file (prompt-level) | N/A |
| Google Antigravity | Rules file (prompt-level) | N/A |
| Mistral Vibe | Planned ([#800](https://github.com/rtk-ai/rtk/issues/800)) | Pending upstream |

## Installation by agent

### Claude Code

```bash
contextcrawler init --global    # installs hook + patches settings.json
```

Restart Claude Code. Verify:

```bash
contextcrawler init --show    # shows hook status
```

### Cursor

```bash
contextcrawler init --global --cursor
```

Restart Cursor. The hook uses `preToolUse` with Cursor's `updated_input` format.

### VS Code Copilot Chat

```bash
contextcrawler init --global --copilot
```

### Gemini CLI

```bash
contextcrawler init --global --gemini
```

### OpenCode

```bash
contextcrawler init --global --opencode
```

Creates `~/.config/opencode/plugins/rtk.ts`. Uses the `tool.execute.before` hook.

### Hermes

```bash
contextcrawler init --agent hermes
```

Creates `~/.hermes/plugins/rtk-rewrite/` and enables it through `plugins.enabled` in the Hermes config. Hermes loads Python plugins, so the plugin entrypoint is Python, but it is only a thin adapter. It mutates the Hermes `terminal` tool `command` before execution and delegates all rewrite decisions to Rust through `contextcrawler rewrite`. The repository source and tests for that adapter live in `hooks/hermes/`; only installed runtime files use the `~/.hermes/plugins/rtk-rewrite/` path.

The plugin fails open. If `contextcrawler` is missing at load time, the hook is not registered. If `contextcrawler rewrite` errors, the tool is not `terminal`, the payload has no string `command`, or the plugin raises an exception, Hermes runs the original command unchanged. The same `contextcrawler rewrite` limitations apply: already-prefixed `contextcrawler` commands, compound shell commands, heredocs, and commands without filters are not rewritten.

### Cline / Roo Code

```bash
contextcrawler init --cline    # creates .clinerules in current project
```

Cline reads `.clinerules` as custom instructions. contextcrawler adds guidance telling Cline to prefer `contextcrawler <cmd>` over raw commands.

### Windsurf

```bash
contextcrawler init --windsurf    # creates .windsurfrules in current project
```

### Codex CLI

```bash
contextcrawler init --codex    # creates AGENTS.md or patches existing one
```

### Kilo Code

```bash
contextcrawler init --agent kilocode    # creates .kilocode/rules/ctxcrl-rules.md in current project
```

Kilo Code reads `.kilocode/rules/` as custom instructions. contextcrawler adds guidance telling Kilo Code to prefer `contextcrawler <cmd>` over raw commands.

### Google Antigravity

```bash
contextcrawler init --agent antigravity    # creates .agents/rules/antigravity-ctxcrl-rules.md in current project
```

Antigravity reads `.agents/rules/` as custom instructions. contextcrawler adds guidance telling Antigravity to prefer `contextcrawler <cmd>` over raw commands.

### Mistral Vibe (planned)

Support is blocked on upstream `BeforeToolCallback` ([mistral-vibe#531](https://github.com/mistralai/mistral-vibe/issues/531)). Tracked in [#800](https://github.com/rtk-ai/rtk/issues/800).

## Integration tiers explained

| Tier | Mechanism | How rewrites work |
|------|-----------|------------------|
| **Full hook** | Shell script or Rust binary, intercepts via agent API | Transparent — agent never sees the raw command |
| **Plugin** | TypeScript, JavaScript, or Python in agent's plugin system | Transparent, in-place mutation when the agent allows it |
| **Rules file** | Prompt-level instructions | Guidance only — agent is told to prefer `contextcrawler <cmd>` |

Rules file integrations (Cline, Windsurf, Codex, Kilo Code, Antigravity) rely on the model following instructions. Full hook integrations (Claude Code, Cursor, Gemini) are guaranteed — the command is rewritten before the agent sees it.

## Windows support

The shell hook (`rtk-rewrite.sh`) requires a Unix shell. On native Windows:

- `contextcrawler init -g` automatically falls back to **CLAUDE.md injection mode** (prompt-level instructions)
- Filters work normally (`contextcrawler cargo test`, `contextcrawler git status`)
- Auto-rewrite does not work — the AI assistant is instructed to use contextcrawler but commands are not intercepted

For full hook support on Windows, use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install). Inside WSL, all agents with shell hook integration (Claude Code, Cursor, Gemini) work identically to Linux.

## Graceful degradation

Hooks never block command execution. If contextcrawler is missing, the hook exits cleanly and the raw command runs unchanged:

- contextcrawler binary not found: warning to stderr, exit 0
- Invalid JSON input: pass through unchanged
- contextcrawler version too old: warning to stderr, exit 0
- Filter logic error: fallback to raw command output

## Override: disable contextcrawler for one command

```bash
CTXCRL_DISABLED=1 git status    # runs raw git status, no rewrite
```

Or exclude commands permanently in `~/.config/ctxcrl/config.toml`:

```toml
[hooks]
exclude_commands = ["git rebase", "git cherry-pick"]
```
