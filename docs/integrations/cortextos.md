# Using ContextCrawler with cortextOS

> Status: design + quick-start. The plumbing is settled; the open questions are
> about packaging, and they are flagged at the end for a decision.

ContextCrawler is a token-optimising CLI proxy: it intercepts dev commands
(`git status`, `cargo test`, `npm run ...`) and rewrites them through its own
filters, returning the same signal in 60-90% fewer tokens, with an opt-in
Tirith security gate in front. cortextOS runs autonomous agents that shell out
constantly. Putting ContextCrawler in front of those agents is the obvious win.

The good news: the integration is plumbing-light. Two properties make it safe
to ship.

## Why the integration is trivial

**1. Hooks are additive across scopes.** cortextOS's agent settings already
carry hooks (loop-detector, Telegram notifications, and so on). ContextCrawler
does not replace them. Its installer *appends* a `PreToolUse` entry to the
existing array and preserves everything already there
(`src/hooks/init.rs:1377`, `insert_hook_entry`). cortextOS's hooks keep firing
untouched; ContextCrawler's hook rides alongside in the same `Bash` matcher
list.

**2. The hook is double-wrap-safe and rewrites in-place.** When a command is
already a ContextCrawler invocation, the rewriter detects it and passes it
through unchanged (`src/discover/registry.rs:743` for the `contextcrawler `
prefix; the hook returns `PassThrough` for already-wrapped input,
`src/hooks/hook_cmd.rs:42`). There is no "did it already wrap?" footgun, so the
hook is safe to ship enabled-by-default once a user has opted in.

Net: an integration never has to reason about ordering, replacement, or
re-entrancy. It concatenates one hook and gets out of the way.

## Quick start (the immediate ship)

This is the manual path. It works against any cortextOS install today, no
upstream changes required.

### 1. Install ContextCrawler from source

```bash
git clone <contextcrawler-repo> && cd contextcrawler
cargo install --path .
contextcrawler --version    # sanity check
```

### 2. Add the hook to the agent's settings

ContextCrawler ships a hook subcommand; you point a `PreToolUse` Bash hook at
it. For cortextOS distribution, put this in the **agent template (Project
scope)** so it travels with the agent and never depends on a per-user
`~/.claude`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "contextcrawler hook claude" }
        ]
      }
    ]
  }
}
```

If the agent already has `PreToolUse` hooks, append this entry to the existing
array rather than replacing it. (cortextOS's own hooks stay; see "additive"
above.) `contextcrawler init` does this merge automatically when run against a
`settings.json`, but for a shipped template you hand-place the block.

### 3. Restart and verify

Restart the agent, then run `git status`. The command is transparently
rewritten to `contextcrawler git status` with zero token overhead. Confirm
savings are being recorded:

```bash
contextcrawler gain            # token-savings analytics
contextcrawler gain --history  # per-command history
```

That is the whole integration. Everything below is about turning this manual
recipe into something the cortextOS community can discover and install.

## Packaging roadmap

Four shapes, increasing ambition:

| Shape | What ships | Who maintains | Reach |
|---|---|---|---|
| **1. Integration doc** | This file, "paste this `PreToolUse` block" | both repos | manual, low friction to ship |
| **2. Community catalog item** | A ContextCrawler skill in cortextOS's `community/catalog.json`, installable via `browse-catalog` | cortextOS community | discoverable, opt-in, self-contained |
| **3. Generic proxy extension point** (recommended) | A cortextOS config knob, `command_proxy: "contextcrawler"` in agent `config.json`, that `add-agent` / templates honour by injecting the hook | cortextOS core + ContextCrawler as the reference impl | any proxy can plug in; you own the flagship one |
| **4. Standalone installer** | A `cortextos-contextcrawler` bridge (in the style of `serena-fleet`) | ContextCrawler repo | works against any cortextOS install |

### Recommendation: ship 1 now, build toward 3

Land **Shape 1** (this doc) immediately, then upstream **Shape 3**: a generic
`command_proxy` extension point in cortextOS. A one-line config knob stamps a
`PreToolUse` Bash hook into the agent's settings; ContextCrawler is documented
as the reference integration that fills the slot.

This is the strategically right framing for "these two things moving forward":

- cortextOS gains a genuinely reusable extensibility feature. The community can
  wrap *any* proxy or gate, not just ContextCrawler.
- ContextCrawler becomes the canonical example that demonstrates it.

You are not bolting one tool onto another. You are giving cortextOS a proxy
slot and filling it with your tool. Maintainers accept non-vendor-specific
extension points far more readily than a hard-coded dependency on someone's
fork.

The generic-slot framing also removes any global-install dependency. For
distribution you never rely on each user's `~/.claude`; the hook ships in the
agent template at Project scope, self-contained and opt-in. (For the record,
cortextOS's PTY environment does pass `HOME` through, `agent-pty.ts:341`
allowlists it, so a global install would reach agents on a single box, but that
is the wrong model for distribution.)

## Open decisions

Two calls to make before Shape 3 is drafted.

### 1. Generic slot vs ContextCrawler-specific flag

A generic `command_proxy` is more upstreamable (maintainers like non-vendor
extension points) and dodges "why is cortextOS hard-coding your fork?". It is
slightly more design work. A ContextCrawler-specific flag is faster but
narrower.

**Lean: generic.**

### 2. Does the security gate travel with it?

The token-savings angle is easy: zero new dependencies, broad appeal. The
Tirith gate on autonomous agents is the differentiated value, but it pulls in a
`tirith` dependency and a fail-open/fail-closed policy decision.

- **Token-savings-only**: broadest appeal, zero new deps, the gate is a
  documented add-on.
- **Batteries-included**: the gate is front-and-centre as the security story
  for autonomous fleets.

**Undecided. Pick one before the Shape 3 design.**

## Reference

- ContextCrawler meta commands: `contextcrawler gain | discover | proxy | security`
- Hook command constant: `contextcrawler hook claude` (`src/hooks/constants.rs:14`)
- Security gate guide: `docs/security/working-with-the-gate.md`
