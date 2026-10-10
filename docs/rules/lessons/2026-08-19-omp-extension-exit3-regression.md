# OMP extension: rewrite() must honour exit-3 rewritten stdout (regression 2026-08-19)

## Symptom

`contextcrawler gain` reports **no new savings** in the OMP harness, even though
`contextcrawler proxy` run manually records rows. Tool-driven commands are
never tracked; only shell-hook / manual `contextcrawler proxy` commands are.

## Root cause (two-part)

1. `contextcrawler rewrite` returns **exit 3 (Ask verdict)** with **valid
   rewritten stdout** for every proxyable command under the current
   `profile=trusted` + `CONTEXTCRAWLER_TRUST_UNATTESTABLE=1` setup:
   `ls -la` → stdout `contextcrawler ls -la`, exit **3** (not 0). The
   documented exit-code contract (src/hooks/rewrite_cmd.rs) says exit 3 +
   stdout is a *legitimate* rewrite — the hook must use the stdout and let the
   host prompt.
2. The OMP extension `hooks/pi/rtk-extension.ts` used `execFileSync`, which
   **throws on exit 3**, so its `catch` returned the original command
   unrewritten → contextcrawler never ran → no tracking. The old pi-agent
   version used `spawnSync` and took `result.stdout` regardless of exit code —
   the `execFileSync` rewrite (added alongside the HARD-FAIL guard) silently
   dropped exit-3 handling.

## Not the cause

- **Not** a binary/PATH issue: `~/.cargo/bin/contextcrawler` is on PATH in the
  live OMP process; `node`/`bun` resolve it.
- **Not** `CONTEXTCRAWLER_DISABLED=1` (only `CONTEXTCRAWLER_TRUST_UNATTESTABLE=1`
  is set, a trust-relaxation, not a disable).
- **Not** the import: OMP aliases `@earendil-works/pi-coding-agent` →
  `@oh-my-pi/pi-coding-agent` via `PI_SCOPE_ALIASES` in
  `src/extensibility/plugins/legacy-pi-compat.ts`.

## Fix

`rewrite()` must use `spawnSync` and accept stdout on exit **0 or 3**, falling
back to the raw command only when stdout is empty or byte-identical to the
input. Applied to BOTH `hooks/pi/rtk-extension.ts` (source of truth) and the
installed `~/.omp/agent/extensions/contextcrawler.ts` (which also carries the
HARD-FAIL LAW GEN-CTXCRL-001 guard).

## Check

- `contextcrawler rewrite 'git status'` → exit 3, stdout `contextcrawler git status`.
- Extension `rewrite()` must return the rewritten stdout, not the original.
- A session restart is REQUIRED — the extension module is imported at session
  start, so the old (broken) version stays loaded for the whole session.

## Verify after restart

1. Run a proxyable command via the OMP Bash tool (e.g. `ls -la .`).
2. `contextcrawler gain --history` / `sqlite3 ~/.local/share/contextcrawler/history.db
   "SELECT MAX(id),MAX(timestamp) FROM commands;"` → a new row with non-zero
   savings appears.