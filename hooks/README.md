# LLM Agent Hooks

## Scope

**Deployed hook artifacts** — the files installed on user machines by `contextcrawler init`. These are shell scripts, TypeScript plugins, and rules files that run outside the Rust binary. They are **thin delegates**: parse agent-specific JSON, ask the binary for a decision, format the agent-specific response. Zero filtering logic lives here.

> [!IMPORTANT]
> **Two decision entrypoints exist; only one is installed by default.**
>
> - **`contextcrawler hook <agent>`** — the live path. The binary reads the
>   agent's JSON on stdin and emits the agent's response format directly.
>   This is what `contextcrawler init` writes into `settings.json` today.
> - **`contextcrawler rewrite <cmd>`** — the legacy path. Returns a rewritten
>   command string for a shell delegate to wrap. Still supported and still
>   shipped (`hooks/claude/rtk-rewrite.sh`, `hooks/cursor/rtk-rewrite.sh`),
>   but no longer what a fresh install uses.
>
> Both run the Tirith and supply-chain gates on the **raw** command before
> deciding rewritability. The `rtk-`prefixed filenames are pre-rebrand and
> are kept as-is deliberately: renaming them changes install paths and
> integrity hashes.

Owns: per-agent hook scripts and configuration files. `contextcrawler init` targets Claude Code, Cursor, Windsurf, Cline, Kilo Code, Antigravity, Hermes and Pi; the binary additionally serves Copilot and Gemini through `contextcrawler hook`.

Does **not** own: hook installation/uninstallation (that's `src/hooks/init.rs`), the rewrite pattern registry (that's `discover/registry`), or integrity verification (that's `src/hooks/integrity.rs`).

Relationship to `src/hooks/`: that component **creates** these files; this directory **contains** them.

## Purpose

LLM agent integrations that intercept CLI commands and route them through ContextCrawler for token optimisation. Each hook transparently rewrites raw commands (e.g., `git status`) to their proxied equivalents (e.g., `contextcrawler git status`), delivering 60-90% token savings without requiring the agent or user to change their workflow.

## How It Works

```
Agent runs command (e.g., "cargo test --nocapture")
  -> Hook intercepts (PreToolUse / plugin event)
  -> Binary reads JSON on stdin, extracts command string
  -> Gates run on the RAW command (Tirith + supply-chain)
  -> Registry matches pattern -> "contextcrawler cargo test --nocapture"
  -> Binary emits the agent-specific JSON response
  -> Agent executes "contextcrawler cargo test --nocapture" instead
  -> Filtered output reaches LLM (~90% fewer tokens)
```

Gate ordering is deliberate: **gates run before rewritability is decided**, so
non-rewritable commands (`bash`, unknown subcommands) are still inspected. A
`block` finding downgrades an auto-allow to *Ask* — never to a silent allow.

All rewrite logic lives in the Rust binary (`src/discover/registry.rs`). This
is the single source of truth for all 70+ rewrite patterns; hook scripts never
reimplement it.

## Directory Structure

Each agent subdirectory has its own README with hook-specific details:

- **[`claude/`](claude/README.md)** — Shell hook, `PreToolUse` JSON format, `settings.json` patching, test script
- **[`copilot/`](copilot/README.md)** — Rust binary hook, dual format (VS Code Chat vs Copilot CLI), deny-with-suggestion fallback
- **[`cursor/`](cursor/README.md)** — Shell hook, Cursor JSON format, empty `{}` response requirement
- **[`cline/`](cline/README.md)** — Rules file (prompt-level), `.clinerules` project-local installation
- **[`windsurf/`](windsurf/README.md)** — Rules file (prompt-level), `.windsurfrules` workspace-scoped
- **[`codex/`](codex/README.md)** — Awareness document, `AGENTS.md` integration, `$CODEX_HOME` or `~/.codex/` location
- **[`opencode/`](opencode/README.md)** — TypeScript plugin, `zx` library, `tool.execute.before` event, in-place mutation

## Supported Agents

| Agent | Mechanism | Hook Type | Can Modify Command? |
|-------|-----------|-----------|---------------------|
| Claude Code | Shell hook (`PreToolUse`) | Transparent rewrite | Yes (`updatedInput`) |
| VS Code Copilot Chat | Rust binary (`contextcrawler hook copilot`) | Transparent rewrite | Yes (`updatedInput`) |
| GitHub Copilot CLI | Rust binary (`contextcrawler hook copilot`) | Deny-with-suggestion | No (agent retries) |
| Cursor | Shell hook (`preToolUse`) | Transparent rewrite | Yes (`updated_input`) |
| Gemini CLI | Rust binary (`contextcrawler hook gemini`) | Transparent rewrite | Yes (`hookSpecificOutput`) |
| Cline / Roo Code | Custom instructions (rules file) | Prompt-level guidance | N/A |
| Windsurf | Custom instructions (rules file) | Prompt-level guidance | N/A |
| Codex CLI | AGENTS.md / instructions | Prompt-level guidance | N/A |
| OpenCode | TypeScript plugin (`tool.execute.before`) | In-place mutation | Yes |

## JSON Formats by Agent

### Claude Code (Shell Hook)

**Input** (stdin):
```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "git status" }
}
```

**Output** (stdout, when rewritten):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "ContextCrawler auto-rewrite",
    "updatedInput": { "command": "contextcrawler git status" }
  }
}
```

### Cursor (Shell Hook)

**Input**: Same as Claude Code.

**Output** (stdout, when rewritten):
```json
{
  "permission": "allow",
  "updated_input": { "command": "contextcrawler git status" }
}
```

Returns `{}` when no rewrite (Cursor requires JSON for all paths).

### Copilot CLI (Rust Binary)

**Input** (stdin, camelCase, `toolArgs` is JSON-stringified):
```json
{
  "toolName": "bash",
  "toolArgs": "{\"command\": \"git status\"}"
}
```

**Output** (no `updatedInput` support -- uses deny-with-suggestion):
```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "Token savings: use `contextcrawler git status` instead"
}
```

### VS Code Copilot Chat (Rust Binary)

**Input** (stdin, snake_case):
```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "git status" }
}
```

**Output**: Same as Claude Code format (with `updatedInput`).

### Gemini CLI (Rust Binary)

**Input** (stdin):
```json
{
  "tool_name": "run_shell_command",
  "tool_input": { "command": "git status" }
}
```

**Output** (when rewritten):
```json
{
  "decision": "allow",
  "hookSpecificOutput": {
    "tool_input": { "command": "contextcrawler git status" }
  }
}
```

**No rewrite**: `{"decision": "allow"}`

### OpenCode (TypeScript Plugin)

Mutates `args.command` in-place via the zx library:
```typescript
const result = await $`contextcrawler rewrite ${command}`.quiet().nothrow()
const rewritten = String(result.stdout).trim()
if (rewritten && rewritten !== command) {
  (args as Record<string, unknown>).command = rewritten
}
```

## Command Rewrite Registry

The registry (`src/discover/registry.rs`) handles command patterns across these categories:

| Category | Examples | Savings |
|----------|----------|---------|
| Test Runners | vitest, pytest, cargo test, go test, playwright | 90-99% |
| Build Tools | cargo build, npm, pnpm, dotnet, make | 70-90% |
| VCS | git status/diff/show | 70-80% |
| VCS (log) | git log (plain) | ~35%; `--oneline`/`--format` pass through |
| Language Servers | tsc, mypy | 80-83% |
| Linters | eslint, ruff, golangci-lint, biome | 80-85% |
| Package Managers | pip, cargo install, pnpm list | 75-80% |
| File Operations | ls, find, grep, cat, head, tail | 60-75% |
| Infrastructure | docker, kubectl, aws, terraform | 75-85% |

### Compound Command Handling

The registry handles `&&`, `||`, `;`, `|`, and `&` operators:

- **Pipe** (`|`): Only the left side is rewritten (right side consumes output format)
- **And/Or/Semicolon** (`&&`, `||`, `;`): Both sides rewritten independently
- **find/fd in pipes**: Never rewritten (output format incompatible with xargs/wc/grep)

Example: `cargo fmt --all && cargo test` becomes `contextcrawler cargo fmt --all && contextcrawler cargo test`

### Override Controls

- **`CTXCRL_DISABLED=1`**: Per-command override (`CTXCRL_DISABLED=1 git status` runs raw). The pre-rebrand `RTK_DISABLED=1` is still honoured but deprecated; see `is_disabled_by_env_prefix` in `src/discover/registry.rs`.
- **`exclude_commands`**: In `~/.config/contextcrawler/config.toml`, list commands to never rewrite. Matches against the full command after stripping env prefixes. Subcommand patterns work (`"git push"` excludes `git push origin main`). Patterns starting with `^` are treated as regex.
- **Already-proxied**: `contextcrawler git status` passes through unchanged (no `contextcrawler contextcrawler git`)

## Exit Code Contract

Hooks must **never block command execution**. All error paths (missing binary, bad JSON, rewrite failure) must exit 0 so the agent's command runs unmodified. A hook that exits non-zero prevents the user's command from executing.

When there is no rewrite to apply, the hook must produce no output (or `{}` for Cursor, which requires JSON on all paths).

## Graceful Degradation

Hooks are **non-blocking** -- they never prevent a command from executing:

- jq not installed: warning to stderr, exit 0 (command runs raw)
- contextcrawler binary not found: warning to stderr, exit 0
- contextcrawler missing the `rewrite` subcommand: warning to stderr, exit 0
- Invalid JSON input: pass through unchanged
- `contextcrawler hook` crashes: hook exits 0 (subprocess error ignored)
- Filter logic error: fallback to raw command output

## Adding a New Agent Integration

New integrations must follow the [Exit Code Contract](#exit-code-contract) and [Graceful Degradation](#graceful-degradation) above, as well as the project's [Design Philosophy](../CONTRIBUTING.md#design-philosophy).

### Integration Tiers

| Tier | Mechanism | Maintenance | Examples |
|------|-----------|-------------|----------|
| **Full hook** | Shell script or Rust binary, intercepts commands via agent's hook API | High — must track agent API changes | Claude Code, Cursor, Copilot, Gemini |
| **Plugin** | TypeScript/JS plugin in agent's plugin system | Medium — agent manages loading | OpenCode |
| **Rules file** | Prompt-level instructions the agent reads | Low — no code to break | Cline, Windsurf, Codex |

### Eligibility

ContextCrawler supports AI coding assistants that developers actually use day-to-day. To add a new agent:

- Agent has a **documented, stable hook/plugin API** (not experimental/alpha)
- Agent is **actively maintained** (commit activity in last 3 months)
- Integration follows the **exit code contract** (exit 0 on all error paths)
- Hook output matches the **agent's expected JSON format** exactly

### Maintenance

If an agent's API changes and the hook breaks, the integration should be updated promptly. If the agent becomes unmaintained or the hook can't be fixed, the integration may be deprecated with a release note.

