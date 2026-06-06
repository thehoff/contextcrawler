# Audit — subprocess timeouts across the binary

**Date:** 2026-05-18
**Scope:** every production `Command::output()` / `Command::status()` /
`Command::spawn()` site in `src/`, excluding `#[test]` and `#[cfg(test)]`.
**Driver:** v0.2.0 ROADMAP item "Subprocess timeouts everywhere". The
tirith gate already got the wait-timeout + stdout-cap + stdin-null
treatment in v0.1.6 (`b4c93c3`); this audit determines which other
sites need the same — and which deliberately don't.

## TL;DR

`exec_capture` is the **major** choke point — 18 modules route through
it. But it is **not** the only path: a class of filter modules
(`aws_cmd`, `go_cmd`, `git.rs::run_commit`, the main-level TOML-match
filter dispatch, the proxy command) call `Command::output()` /
`Command::status()` / `Command::spawn()` directly. The original cut of
this audit understated that surface; the **2026-05-18 re-grep** (Codex
review of the first hardening commit) found those sites and they are
now enumerated below.

Also surfaced by the re-grep: `src/analytics/security_cmd.rs::{fetch_audit_stats, fetch_doctor_status}`
is **NOT** hardened despite the v0.1.6 overnight summary claiming it
was. There is no `run_tirith_capture` helper and no `wait_timeout`
import in that file — `Command::new(bin).output()` runs unbounded.
This is the same "trust the commit subject, not the code" failure mode
the project memory rule covers. Tracked as F-06 below.

Three policy classes emerge:

| Class | Examples | Timeout policy |
|---|---|---|
| **A — hook-blocking** | tirith gate (✓ done), `permissions.rs` git rev-parse, future PreToolUse hooks | Aggressive: **8–10s hard cap**. Hung child = hung agent. |
| **B — user-driven filter** | `contextcrawler cargo test`, `contextcrawler pnpm install`, `contextcrawler vitest`, `contextcrawler container exec` | No deadline by default. User explicitly invoked, can ^C. Apply a **stdout cap (64 MiB)** as DoS bound, not a wall-clock cap. |
| **C — internal short-lived** | `gh pr view`, `pip list`, `pnpm outdated`, `golangci-lint`, doctor scripts | **Soft deadline (30–60s)** with cap, surfaced as a filter warning, fallback to raw output. |

The hardening therefore is **not** "wrap every site in wait-timeout".
It's "add the right primitive in `core/stream.rs` and route each
caller to the class it belongs to". Most callers stay on the default
path (class B); only the hook-path callers switch to the short-deadline
variant.

## Method

Initial grep was over `Command::new`. The 2026-05-18 re-grep widened
to also catch `.output()`, `.status()`, `.spawn()` on Command values
returned by helpers like `resolved_command` / `build_commit_command`,
which the original grep missed. Filtering out `#[test]`,
`#[cfg(test)]`, `#[ignore]`, and pure factories (`ruby_exec`,
`resolved_command`, `build_command`, `build_shell_command` — they
return a `Command` but don't run it), the production call surface is:

```
[CENTRAL — hardened in this branch]
src/core/stream.rs::exec_capture(_with_limits)   default 64 MiB cap, optional timeout

[HARDENED — v0.1.6]
src/hooks/tirith_gate.rs::check                  spawn + wait_timeout(8s) + cap

[BYPASSES exec_capture — needs assessment]
src/analytics/security_cmd.rs:459 fetch_audit_stats   F-06 — NOT hardened despite doc claim
src/analytics/security_cmd.rs:479 fetch_doctor_status F-06 — NOT hardened despite doc claim
src/analytics/ccusage.rs:98       npx ccusage --help check   class C (short-lived)
src/cmds/cloud/aws_cmd.rs:244     aws CLI invocation         class B (user-driven filter)
src/cmds/go/go_cmd.rs:138         go subcommand              class B (user-driven filter)
src/cmds/git/git.rs:1058          git commit (stdin inherit) class B (user-driven, needs TTY)
src/main.rs:1301                  TOML-match filter dispatch class B (user-driven filter)
src/main.rs:2263                  npx prisma passthrough     class B* (explicit passthrough)
src/main.rs:2483                  Proxy command              class B* (explicit passthrough)
src/main.rs:2711                  contextcrawler web curl invocation    in-process timeout via --max-time 30
src/main.rs:2393                  --shell raw passthrough    class B* (explicit passthrough)

[HOOK-PATH — newly hardened in this branch]
src/hooks/permissions.rs:179      git rev-parse fallback     exec_capture_short(10s)
```

class B* = explicit user-requested passthrough; documented as accepted.

## Findings

### F-01 (HIGH) — `exec_capture` has no stdout cap

`src/core/stream.rs:502`:

```rust
pub fn exec_capture(cmd: &mut Command) -> Result<CaptureResult> {
    cmd.stdin(Stdio::null());
    let output = cmd.output().context("Failed to execute command")?;
    ...
}
```

`Command::output()` reads stdout and stderr to completion. A runaway
child (e.g. `pnpm list` against a circular monorepo, or a malicious
filter command in `contextcrawler summary "$evil"`) can fill memory until OOM.
18 modules inherit this gap, including `cmds/cloud/curl_cmd.rs`
(network-attacker-controlled) and `cmds/system/summary.rs` (user-string
command).

**Fix:** add a `CaptureLimits` struct with `stdout_max: usize` and
`stderr_max: usize`, default **64 MiB** each (matches the tirith
hardening); replace `cmd.output()` with `spawn` + bounded
`take().read_to_end_limited()`. Existing `exec_capture` keeps its
signature and calls the limited variant with defaults.

### F-02 (HIGH) — Hook-path callers have no deadline

`src/hooks/permissions.rs:177` invokes `git rev-parse --show-toplevel`
during Claude Code's PreToolUse path. Normally <50 ms. A pathological
case (network mount stalled, FUSE driver hung, gitdir on dead NFS)
hangs the agent indefinitely — the same failure mode tirith F-01 had.

**Fix:** add `exec_capture_short(cmd, Duration)` that wraps
`exec_capture_with_limits` and additionally applies `wait_timeout`.
Default budget for hook callers: **10s**. Permissions hook switches to
this. Same primitive available for any future PreToolUse hook.

### F-03 (MEDIUM) — `contextcrawler summary "$cmd"` runs arbitrary user input

`src/cmds/system/summary.rs:65` calls `exec_capture` on a command
string the user passed. Agent-controlled in CC integration. Mitigated
by the shlex parser + shell-metachar reject (v0.1.5 boundary work) so
it can't smuggle shells, but it CAN run a legitimate binary that
happens to hang or stream forever. With F-01 fixed (stdout cap),
this becomes "the command finishes when the cap fires or the user
hits ^C" — acceptable for a `summary` UX. No additional fix
recommended; F-01's cap is the mitigation.

### F-04 (LOW) — stderr is unbounded even after F-01

If we only cap stdout, an attacker can still flood stderr (which is
piped, not null, because the filter uses it). Apply the same cap to
stderr — same primitive, same default.

### F-06 (HIGH — newly surfaced) — `security_cmd.rs` is not actually hardened

The v0.1.6 overnight summary (`docs/sessions/2026-05-15-overnight.md`,
branch #12) claimed `fetch_audit_stats` and `fetch_doctor_status` had
the wait_timeout / stdout-cap / stdin-null pattern applied via a
`run_tirith_capture` helper. Grepping the current file:

```
$ grep -n 'run_tirith_capture\|wait_timeout' src/analytics/security_cmd.rs
$ # (no matches)
```

Both call sites use raw `Command::new(bin).output()`. The hardening
either was never committed or got lost in a rebase. **Acute** because
`security_cmd` runs from `contextcrawler security` — invoked from the dashboard
poll path; a hung tirith here is the same UX failure mode tirith F-01
existed to fix in the hook path.

**Fix:** route both call sites through `exec_capture_short(_, 8s)`
using the new primitive. Lands in its own branch off `develop`
(`feat/sec-security-cmd-actual-timeout`) since it's a caller change
independent of the primitive itself.

### F-07 (LOW — newly surfaced) — `aws_cmd`, `go_cmd`, `git commit` bypass exec_capture

These three filter modules run user-driven commands directly via
`cmd.output()`. They are class B (user can ^C, no wall-clock deadline
appropriate) but they also bypass the new 64 MiB cap.

**Recommendation:** route through `exec_capture` (default limits,
no timeout). Caveat: `git commit` uses `stdin(Stdio::inherit())` to
let the user edit the commit message in `$EDITOR`; `exec_capture`
nulls stdin. Solution: either widen `exec_capture` with an
`stdin_inherit: bool` flag, or leave `git commit` on its own path and
document why. Defer to a per-caller branch.

### F-08 (LOW — newly surfaced) — `main.rs:1301` TOML-match filter

Same as F-07 — direct `cmd.output()` bypassing the cap. Same fix
recommendation, same `stdin(Stdio::inherit())` constraint. Defer.

### F-09 (informational) — `main.rs:2711` `contextcrawler web` curl call

Not capped at the spawn layer, but curl is invoked with
`--max-time 30` and `--max-filesize 64M` (v0.1.6 web hardening).
That's a process-internal timeout — the parent will block until
curl exits, but curl itself bounds the work. Acceptable as is;
documenting for completeness.

### F-05 (LOW / out of scope) — `main.rs:2393` raw shell passthrough

The `--shell` / raw passthrough path inherits the parent's stdin/stdout
and uses `.status()`. No timeout, no cap. **This is by design** — it's
the explicit "I want raw passthrough" escape hatch. The user can ^C
themselves. Adding a cap or deadline would change documented behaviour
and break legitimate long-running commands (`contextcrawler proxy 'tail -f log'`,
`contextcrawler proxy 'cargo watch'`). Document this in THREAT_MODEL.md as an
accepted limitation if not already there.

## Recommended changes

```
src/core/stream.rs
  + struct CaptureLimits { stdout_max: usize, stderr_max: usize,
                           timeout: Option<Duration> }
  + impl Default for CaptureLimits { 64 MiB / 64 MiB / None }
  + fn exec_capture_with_limits(cmd, limits) -> Result<CaptureResult>
  + fn exec_capture_short(cmd, timeout) -> Result<CaptureResult>
    (convenience wrapper: default limits + Some(timeout))
  ~ fn exec_capture(cmd) -> exec_capture_with_limits(cmd, default)

src/hooks/permissions.rs:177
  ~ exec_capture(&mut cmd)  →  exec_capture_short(&mut cmd, Duration::from_secs(10))

src/cmds/system/summary.rs
  no change — F-01 cap is sufficient.

src/main.rs:2393
  no change — F-05 accepted limitation.

Cargo.toml
  no new deps — wait-timeout already added in v0.1.6.
```

## Test plan

1. **Cap fires under load.** Spawn a child that prints 100 MiB of
   `'a'` to stdout. `exec_capture` returns `CaptureResult` whose
   `stdout` is exactly 64 MiB and `exit_code` reflects the kill (or a
   sentinel — TBD during impl).
2. **Timeout fires without cap exhaust.** `exec_capture_short` against
   `sleep 60` with 1s deadline returns an error inside ~1.1s.
3. **Normal commands unchanged.** `exec_capture` against `echo hi`
   still returns `("hi\n", "", 0)`.
4. **stderr capped independently.** Child that floods stderr but says
   nothing on stdout still gets capped.
5. **Permissions hook returns a path under normal conditions.** Same
   integration test as today, no regression.

Target: +5 unit tests, total suite stays green (1842 → 1847).

## What this audit does NOT cover

- `Command::spawn` chains that read stdout incrementally
  (`core/runner.rs::run_streamed`). Those are user-driven filters
  (class B) and apply their own backpressure via the streaming pipe.
  Not in scope for v0.2.0 first cut; revisit if a hang case is
  reported in the wild.
- Process groups / signal propagation. If the parent dies the child
  may survive on Linux. Out of scope; existing `ChildGuard` in
  `core/stream.rs` already handles the supervised cases.
- Anything in `discover/registry.rs` (test-only) or the factory helpers
  in `core/utils.rs`.

## Acceptance for this work item

This item ships when:

- [ ] `CaptureLimits` + `exec_capture_with_limits` + `exec_capture_short`
      exist in `src/core/stream.rs`
- [ ] `exec_capture` delegates to the limited variant with defaults
- [ ] `hooks/permissions.rs:177` uses `exec_capture_short(_, 10s)`
- [ ] 5 unit tests covering F-01, F-02, F-04, no-regression on
      normal output, and the new helpers' signatures
- [ ] Codex review pass clean
- [ ] CHANGELOG entry under v0.2.0 candidates
- [ ] This audit doc updated with "shipped in <commit>"
