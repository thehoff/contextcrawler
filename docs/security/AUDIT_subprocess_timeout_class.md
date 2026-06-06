# Audit conclusion — subprocess-timeout class

Closing the broader "what other `Command::output()` calls need a
timeout?" question after the tirith + security_cmd + web (curl) fixes.

## Scope

Every place in `src/` that spawns an external process. The concern:
without a wall-clock timeout, a hung subprocess can freeze the caller.
For the auto-approve hook path (`Commands::Hook`), a freeze means the
agent's UI hangs until the agent's own outer timeout fires (typically
30 s). For user-explicit invocations the user can Ctrl-C.

## Count

`grep -rE '\.output\(\)' src/` returns ~34 hits. ~10 are in test code
(`#[cfg(test)]` blocks); the rest are production call sites. Spread
across `cmds/git/`, `cmds/cloud/`, `cmds/system/`, `cmds/rust/`,
`cmds/python/`, `cmds/js/`, `cmds/go/`, `cmds/dotnet/`,
`cmds/ruby/`, `core/utils.rs`, `core/stream.rs`, `analytics/`, and
`hooks/`.

## What we already fixed

| Module | Fix | Branch |
|---|---|---|
| `src/hooks/tirith_gate.rs::check` | `wait_timeout(8s)` + `Stdio::null` on stderr/stdin | `feat/sec-tirith-timeout` |
| `src/analytics/security_cmd.rs::run_tirith_capture` | Same pattern, factored helper | `feat/sec-security-cmd-timeout` |
| `Commands::Web` (curl subprocess) | `--max-time 30 --max-filesize 64MiB --max-redirs 10 --resolve` | `feat/sec-web-cmd-hardening` + `feat/sec-web-ssrf-block` |

These are the **three subprocess paths reachable from the
auto-approve PreToolUse hook path** (tirith gate + security dashboard
that may be called via init's verification flow + web command if an
agent invokes it). They're now bounded.

## Why the remaining ~24 sites are out of scope

`src/hooks/hook_cmd.rs` — the auto-approve hook dispatcher — contains
no `Command::output()` calls. It emits JSON to stdout for the host
agent's permission system; the heavy lifting is the trust / gate
modules which we've already covered.

The remaining `Command::output()` sites are all on **user-explicit
invocation paths**:

- `contextcrawler git log`, `contextcrawler cargo test`, `contextcrawler go test`, etc.: the user
  typed the command, sees terminal output, can Ctrl-C if it hangs.
- `contextcrawler init` subprocess probes (looking for `claude`, `tirith`,
  etc.): one-shot init flow; user runs it interactively.
- `contextcrawler ls`, `contextcrawler grep`, `contextcrawler find`: shell-like helpers; same shape.

For these, a hung subprocess is a UX issue, not a security one. The
agent's outer timeout still catches them; the user has interactive
recourse.

## What would change the calculus

If any of the following becomes true, revisit:

1. **A new auto-approve gate** is added that spawns a subprocess
   (e.g. an external policy engine, a sandbox like firejail). Add it
   to the timeout-bounded list at design time.
2. **`hook_cmd.rs` grows a subprocess call** for any reason. Same
   answer: timeout it.
3. **A user-explicit command is migrated to an auto-rewrite target**
   (i.e. the hook rewrites `cargo test` → `contextcrawler cargo test`
   which then runs `Command::output()`). Today the rewrite is
   structural (passes argv to the right module), not auto-executing
   on the hook path itself — the subprocess runs after the user
   approves. Verify this assumption holds for any new rewrite target.

## Recommendation

**Do not** add a blanket timeout wrapper around every
`Command::output()` in `src/`. The current bounded set is
sufficient for the documented threat model. A blanket wrapper would:

- Pull a runtime cost on the user-interactive path (Ctrl-C is faster
  than a wall-clock timer for the user case).
- Add a new failure mode (timer expires on a legitimately-slow
  command like `cargo build --release`).
- Force a tradeoff on the timeout value that's wrong for most call
  sites (`cargo build` legitimately takes minutes; `tirith check`
  legitimately takes <1 s).

The targeted pattern — "subprocess on auto-approve path gets a
timeout, user-explicit subprocess gets the user's interactivity as
the timeout" — is the right balance.

## Status

Class-fix is complete for v0.1.6 / v0.1.7 scope. Re-audit at v0.2.0
or whenever the hook path changes shape (whichever is sooner).
