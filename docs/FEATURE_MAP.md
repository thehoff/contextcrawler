# Feature Map

Single-page index of every shipped / planned / stubbed capability in
ContextCrawler. The README links here from its Capabilities section;
CLAUDE.md links here too. This file is the source of truth — every
other doc should point at it rather than restate.

Status legend:

| Symbol | Meaning |
|---|---|
| ✅ | Shipped on `develop` |
| 🟡 | Shipped as a stub or behind a flag; wire-up pending another issue |
| 🔵 | Planned, issue filed, not yet implemented |
| ⚪ | Idea, no issue yet |

## 1. Context compression (`contextcrawler <verb>`)

The 60+ command-output filters inherited from `rtk-ai/rtk`. ContextCrawler
adds three of its own.

| Capability | Status | Savings target | Source |
|---|---|---|---|
| 60+ command filters (git, cargo, npm, gh, pnpm, vitest, kubectl, docker, …) | ✅ | 60-90% per command | upstream rtk |
| `web <url>` — HTML chrome stripping | ✅ | ~86% on landing pages | contextzip |
| `sessions compact <id>` — Claude Code session-JSONL compactor | ✅ | varies (sidecar-based) | contextzip |
| Stacktrace compressor (Node / Python / Rust / Go / Java) | ✅ | framework-frame elision | contextzip |
| `read --intent <terms>` — surgical lexical extraction on large files | ✅ | ≥80% on 5 KB+ files with intent | [#157](https://github.com/thehoff/contextcrawler/issues/157) / [#163](https://github.com/thehoff/contextcrawler/pull/163) |

## 2. Security gate (Tirith pairing)

Optional. Fail-open if Tirith is not on PATH. Subprocess-only (no AGPL link).

| Capability | Status | Notes | Source |
|---|---|---|---|
| Pre-execution gate (block → downgrade to Ask) | ✅ | only fires on auto-allow rewrites | downstream |
| `security` dashboard CLI | ✅ | text-mode | downstream |
| `security log [--histogram] [--json]` | ✅ | merged Tirith + supply-chain log | downstream |
| `CONTEXTCRAWLER_TIRITH_REQUIRED=1` fail-closed mode | ✅ | refuse auto-allow without working Tirith | downstream |
| `CONTEXTCRAWLER_TIRITH_DISABLED=1` debug-only bypass | ✅ | use only when proving a gate FP | downstream |

## 3. Supply-chain gate

Opt-in via `~/.config/contextcrawler/supply-chain.toml`. Honours pinned
versions; caches OSV lookups for 24 h.

| Capability | Status | Notes |
|---|---|---|
| Pre-install gate on `npm` / `pnpm` / `yarn` / `bun` | ✅ | age + OSV CVE |
| Pre-install gate on `pip` / `pip3` / `uv pip` / `poetry add` / `pipx install` | ✅ | age + OSV CVE |
| `supply-chain check '<cmd>'` shell-side spot check | ✅ | text + JSON output |
| Cooldown protection (default 3 days since publish) | ✅ | per-ecosystem in TOML |
| Severity gate (default block ≥ HIGH) | ✅ | per-ecosystem in TOML |
| `[overrides].always_allow` / `always_deny` globs | ✅ | escape hatch for known-good / known-bad |
| `cargo` / `gem` install detection | 🔵 | not yet wired into the gate — telemetry-only |
| Lockfile vetting (`pnpm install --frozen-lockfile`) | ⚪ | currently fails to Ask as unvettable |

## 4. Local dashboard (`gain --web`)

Loopback-only HTTP server. Read-only. Auto-shutdown after 1 h idle.

| Capability | Status | Issue |
|---|---|---|
| `gain --web` flag + `--port` + `--no-browser` | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |
| Summary pane (lifetime totals + top tools) | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |
| By-day pane (SVG sparkline + detail table) | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |
| Weak-filters pane (leaderboard ranked by leaked tokens) | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |
| Parse-failures pane (recovery rate + recent) | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |
| Release-boundaries pane (install history) | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |
| Security pane (Tirith downgrades + supply-chain verdicts) | ✅ | [#171](https://github.com/thehoff/contextcrawler/issues/171) |
| Installs pane (per-project ledger, project filter dropdown) | ✅ | [#172](https://github.com/thehoff/contextcrawler/issues/172) |
| Insights pane | 🟡 stub | wire-up depends on [#158](https://github.com/thehoff/contextcrawler/issues/158) |
| SIGINT-clean shutdown + 1 h idle auto-shutdown | ✅ | [#162](https://github.com/thehoff/contextcrawler/issues/162) |

### Dashboard endpoints (stable contract)

| Endpoint | Purpose |
|---|---|
| `GET /api/summary` | Lifetime totals + top tools + last 30 days |
| `GET /api/by-day` | `DayStats[]` full recorded history |
| `GET /api/weak-filters` | Leaderboard from latest release boundary |
| `GET /api/failures` | Parse-failure rollup |
| `GET /api/boundaries` | All `release_boundaries` rows + latest pointer |
| `GET /api/security/gate` | Tirith downgrades log (tail-capped at 1 MiB) |
| `GET /api/security/supply-chain` | Supply-chain JSONL rollup |
| `GET /api/installs?project=<path>&limit=<n>` | Per-project install ledger |
| `GET /api/insights` | Stub envelope; awaits [#158](https://github.com/thehoff/contextcrawler/issues/158) |

## 5. Analytics (`gain ...`)

Text-mode statistics. The dashboard panes above ride on the same query
functions, so anything reported here is queryable from `--web` too.

| Capability | Status | Flag |
|---|---|---|
| Lifetime + 30-day summary | ✅ | `gain` |
| ASCII sparkline graph | ✅ | `gain --graph` |
| Command history with per-call savings | ✅ | `gain --history` |
| Monthly quota estimate (`pro` / `5x` / `20x` tiers) | ✅ | `gain --quota --tier 20x` |
| Daily / weekly / monthly breakdowns | ✅ | `gain --daily` / `--weekly` / `--monthly` / `--all` |
| Export (`json` / `csv`) | ✅ | `gain --format json` |
| Parse-failure log | ✅ | `gain --failures` |
| Weak-filters ranking | ✅ | `gain --weak-filters` |
| Per-project scope | ✅ | `gain --project` |
| Insights mode (pattern detection) | 🔵 | [#158](https://github.com/thehoff/contextcrawler/issues/158) |
| Reset (`--reset --yes`) | ✅ | for testing fresh installs |

## 6. Integration / hooks

| Capability | Status |
|---|---|
| Claude Code hook (`init -g --agent claude`) | ✅ |
| Cursor hook (`init -g --agent cursor`) | ✅ |
| Copilot hook (`init -g --agent copilot`) | ✅ |
| Gemini hook (`init -g --agent gemini`) | ✅ |
| OpenCode rules block | ✅ |
| Codex AGENTS.md hook | ✅ |

## 7. Followups noted in peer review

These are flagged in the code or commit history but parked behind a
later PR. Linked to their tracking issue if filed.

| Concern | Where flagged | Status |
|---|---|---|
| Raw command stored unredacted in `installs` table (matches existing `commands` table behaviour) | codex peer-review MED, [#172](https://github.com/thehoff/contextcrawler/issues/172) | follow-up — needs a shared redaction helper |
| `project_path` canonicalisation mismatch between live and historical install rows | codex peer-review LOW, [#172](https://github.com/thehoff/contextcrawler/issues/172) | follow-up — symlinks bucket differently |
| GLOB filter accepts literal `*?[]` from user paths | codex peer-review LOW, [#172](https://github.com/thehoff/contextcrawler/issues/172) | follow-up — small in practice (lab paths rarely have glob meta) |
| `cargo` / `gem` install ecosystems detected for telemetry but not gated | this file | needs ecosystem config in supply-chain.toml |
