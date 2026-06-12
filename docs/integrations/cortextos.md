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

That is the whole integration. 
