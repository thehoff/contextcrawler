---
title: Discover and Session
description: Find missed savings opportunities with contextcrawler discover, and track contextcrawler adoption with contextcrawler session
sidebar:
  order: 2
---

# Discover and Session

## contextcrawler discover — find missed savings

`contextcrawler discover` analyzes your Claude Code command history to identify commands that ran without contextcrawler filtering and calculates how many tokens you lost.

```bash
contextcrawler discover                    # analyze current project history
contextcrawler discover --all              # all projects
contextcrawler discover --all --since 7    # last 7 days, all projects
```

**Example output:**

```
Missed savings analysis (last 7 days)
────────────────────────────────────
Command              Count   Est. lost
cargo test              12     ~48,000 tokens
git log                  8     ~12,000 tokens
pnpm list                3      ~6,000 tokens
────────────────────────────────────
Total missed:           23     ~66,000 tokens

Run `contextcrawler init --global` to capture these automatically.
```

If commands appear in the missed list after installing contextcrawler, it usually means the hook isn't active for that agent. See [Troubleshooting](../resources/troubleshooting.md) — "Agent not using contextcrawler".

## contextcrawler session — adoption tracking

`contextcrawler session` shows contextcrawler adoption across recent Claude Code sessions: how many shell commands ran through contextcrawler vs. raw.

```bash
contextcrawler session
```

**Example output:**

```
Recent sessions (last 10)
─────────────────────────────────────────────────────
Session                         Total   contextcrawler   Coverage
2026-04-06 14:32  (45 cmds)       45    43      95.6%
2026-04-05 09:14  (38 cmds)       38    38     100.0%
2026-04-04 16:50  (52 cmds)       52    49      94.2%
─────────────────────────────────────────────────────
Average coverage: 96.6%
```

Low coverage on a session usually means contextcrawler was disabled (`CTXCRL_DISABLED=1`) or the hook wasn't active for a specific subagent.
