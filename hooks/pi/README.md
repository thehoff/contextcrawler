# Pi integration

ContextCrawler ships a Pi (https://pi.dev) extension that rewrites bash
commands to use `contextcrawler` for token savings, plus a guidance
block upserted into the user's `~/.pi/agent/AGENTS.md`.

## Files

- `rtk-extension.ts` — the Pi extension. Embedded into the binary via
  `include_str!` from `src/hooks/init.rs` and written verbatim to
  `~/.pi/agent/extensions/contextcrawler.ts` on `contextcrawler init
  --agent pidev`.
- Guidance content lives in `hooks/shared/guidance.md` (the canonical
  source) and is composed per-harness by `agent_guidance(AGENT_PIDEV)`
  in `src/hooks/init.rs`.

## How the extension works

Pi's [`createBashTool`](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/examples/extensions/bash-spawn-hook.ts)
helper exposes a `spawnHook({command, cwd, env}) -> {command, cwd, env}`
callback that fires before each bash invocation. The extension shells
out to `contextcrawler rewrite <command>` (the single source of truth
for rewrite rules — `src/discover/registry.rs`) and returns the
rewritten command. Exit 3 (Ask) still carries the rewritten command on
stdout, and the extension uses it. The original command is kept only
when stdout is empty or identical to the input.

This mirrors the OpenCode plugin (`hooks/opencode/rtk.ts`): thin
delegate, no JS-side rewrite logic to drift.

## Editing rewrite rules

Edit `src/discover/registry.rs` in the ContextCrawler repo. The Pi
extension picks up changes immediately on the next Pi session because
it re-shells `contextcrawler rewrite` per command.
