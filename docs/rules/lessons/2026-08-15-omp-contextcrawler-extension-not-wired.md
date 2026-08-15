# OMP contextcrawler extension was not wired — now installed (2026-08-15)

- **Date:** 2026-08-15
- **Origin:** OMP extension dir inspection + isolated-runtime verification
- **Proposed status:** REVIEW
- **Resolution:** installed `hooks/pi/rtk-extension.ts` →
  `~/.omp/agent/extensions/contextcrawler.ts` (2026-08-15). Takes effect next
  session start. Rollback = delete that one file.

## Observation

`~/.omp/agent/extensions/` contains no `contextcrawler.*` file. The Pi
extension (`hooks/pi/rtk-extension.ts`) that intercepts bash commands and
routes them through `contextcrawler rewrite` is absent from OMP's extension
directory. A deprecated `~/.pi/` directory also had no extension.

**This does NOT necessarily mean contextcrawler is silent.** The Tirith gate
runs inside the binary when `contextcrawler hook` or `contextcrawler rewrite`
is invoked — the 4,200+ downgrade-log entries prove the binary IS being
called, likely through the Claude Code shell hook (which writes to the same
downgrades log regardless of which harness triggered it).

## What is unverified:
- Whether OMP's `createBashTool` goes through the Claude shell hook or OMP's
  own tool layer. If OMP bypasses the Claude hook, then contextcrawler's bash
  rewrite is not running in OMP (but the Claude shell hook still fires when
  Claude Code is the agent).
- Whether the binary's own `hooks/pi/` extension (designed for the Pi SDK's
  `@earendil-works/pi-coding-agent`) is compatible with OMP's
  `@oh-my-pi/pi-coding-agent`.

## Verification performed (2026-08-15, isolated OMP profile)

1. `bun` load test: `@earendil-works/pi-coding-agent` resolves in OMP's global
   node_modules — `createBashTool` is exported and callable.
2. `createBashTool(cwd, { spawnHook })` returns tool named `bash`; calling the
   same `rewrite()` the extension uses rewrites `git status` → `contextcrawler
   git status`, `ls` → `contextcrawler ls`, and passes `curl | python3`
   through unchanged (permission gate exit 3 = ask, by design).
3. Real OMP headless run (`omp --profile <test> -e ./rtk-extension.ts -p
   ...`): session starts clean (exit 0), exactly ONE `bash` tool is advertised
   (SDK: `toolRegistry.set(tool.name, tool)` replaces the built-in by name —
   no duplicate), and `ls -la <dir>` returned the compacted mode-only output,
   proving the spawnHook rewrite actually fired in-session.

## How it was found

```bash
ls ~/.omp/agent/extensions/contextcrawler*  # empty
ls ~/.pi/agent/extensions/contextcrawler*    # empty
ls ~/.omp/agent/extensions/                  # 8 extensions, no contextcrawler
which contextcrawler                          # /home/thehoff/.cargo/bin/contextcrawler — on PATH
```

## Check (if re-visiting)

Before assuming the extension is missing: verify whether OMP routes bash
through the Claude shell hook or its own extension system. If OMP uses
`createBashTool` directly, the contextcrawler Pi extension must be placed in
`~/.omp/agent/extensions/`. If OMP uses the Claude hook, the existing shell
hook is already working and the only gap is token-saving rewrite.