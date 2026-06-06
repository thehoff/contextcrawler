# ContextCrawler threat model

Living document. Update when adding a new capability, when an external
finding surfaces a class of threat not covered here, or when an
accepted limitation in `SECURITY.md` ages out.

## Scope and trust boundary

ContextCrawler sits **between an AI agent and the host shell** as a
single-user CLI proxy. It does three things that matter for security:

1. **Filters and condenses tool output** before it enters the agent's
   LLM context window.
2. **Rewrites or gates commands** the agent proposes to run, optionally
   auto-approving them via the host agent's permission hook.
3. **Persists command history** (token-savings tracking) and reads it
   back into context via `gain --history`.

The trust boundary is the user. ContextCrawler does not enforce
isolation between users on a multi-tenant host and does not try to
defend against a fully compromised local account.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| The user's LLM context window | Inside the host agent | Untrusted content here can flip the agent's behaviour (prompt injection). Cost-wise: tokens are money. |
| The local shell session | The terminal contextcrawler runs in | Auto-approved commands execute here with the user's privileges. |
| `tracking.db` | `~/.local/share/contextcrawler/` (linux) / `~/Library/Application Support/contextcrawler/` (macOS) | 90-day command log that feeds `gain --history` back into the agent's context. Secrets persisted here re-leak on every read. |
| The hook integrity hash | `~/.local/share/contextcrawler/` | The SHA-256 of the agent-side rewrite hook. Tampering = silent command injection. |
| Trusted project filters | `.ctxcrl/filters.toml` per project | A trusted filter can rewrite *any* command's output before the agent sees it (hide vulnerabilities, redirect URLs). |
| Tirith and supply-chain gate decisions | Subprocess + local cache | Gate downgrades are advisory; bypass undoes downstream defence-in-depth. |

## Trust zones

```
┌─────────────────────────────────────────────────────────────────┐
│  Host LLM provider (Anthropic, OpenAI, Google, GitHub Copilot)  │  trusted at provider level
└──────────────────────────────┬──────────────────────────────────┘
                               │ tool call: shell command + (output → context)
┌──────────────────────────────▼──────────────────────────────────┐
│  Host agent (Claude Code / Cursor / Copilot / Gemini / Codex)   │  trusted but compromisable
│  via prompt injection from tool output                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │ PreToolUse hook
┌──────────────────────────────▼──────────────────────────────────┐
│  ContextCrawler                                                  │  the trust boundary we enforce
│  • argv-mode exec guard (err/test/summary)                       │
│  • permission verdict (Deny > Ask > Allow > Default)             │
│  • strip_ansi on output going back to the agent                  │
│  • scrub_secrets at tracking.db insert                           │
│  • Tirith gate + supply-chain gate (optional)                    │
│  • TOML filter trust store (SHA-256 pinned)                      │
│  • hook integrity check (SHA-256 pinned)                         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ child process
┌──────────────────────────────▼──────────────────────────────────┐
│  Host shell                                                      │  trusted local user
└─────────────────────────────────────────────────────────────────┘
```

The **bold load-bearing assumption** is that anything emerging from the
host shell (build output, network responses, file contents) **is not
trustworthy**. It can carry prompt injection payloads, terminal escape
smuggling, or shell-metacharacter strings that — if not handled at the
ContextCrawler layer — flow back into the agent and become a control
channel.

## Threat actors

| Actor | Capability | Goal |
|---|---|---|
| Malicious tool output | Anything reachable via a shell tool the agent runs (curl, npm install, git fetch, file contents…) | Push instructions into the agent's context to make it run something the user wouldn't approve, or exfiltrate secrets via the agent's response. |
| Malicious upstream package | A dependency the agent installs in response to a user request | Same as above, plus persistence: cron, hook tampering, etc. |
| Compromised npm postinstall / build script | Runs at install time | Modify `~/.claude/hooks/`, `tracking.db`, contextcrawler binary itself. |
| Adversarial repo content | `.ctxcrl/filters.toml` shipped in a public repo | Auto-load on cd into the repo and hide security findings or rewrite command output. |
| Compromised LLM provider | The model itself returns adversarial outputs | Out of scope here — host agent is the controller. |
| Other users on a shared host | None at our layer | Out of scope — single-user CLI by design. |

## Attack surfaces and mitigations

### Surface 1: agent-driven shell exec

The agent calls `contextcrawler err <cmd>` / `test <cmd>` / `summary <cmd>`
with a free-form command string. Without controls, an agent prompted by
malicious tool output can append `; <payload>` and have it auto-execute
via the agent's permission hook.

| Mitigation | Layer | Status |
|---|---|---|
| Argv-mode default — shlex split, no shell | `src/cmds/rust/runner.rs`, `src/cmds/system/summary.rs` | **Live** since v0.1.5 (GHSA-3mmh-86cm-g6w4) |
| Shell-metacharacter reject (` \| ; & < > backtick $ \n `) | same | **Live** |
| Refuse known shell binaries (`sh`, `bash`, … and `.exe` variants) and exec wrappers (`env`, `sudo`, `nohup`, …) as first token | same | **Live** |
| `--shell` opt-in escape hatch (documented trust boundary: agent rewrites must not carry `--shell`) | same | **Live** |
| Hook integrity SHA-256 check on the agent rewrite hook script (`rtk-rewrite.sh` — filename retains the `ctxcrl-` prefix per the rebrand-internals-later policy in `src/main.rs`) | `src/hooks/integrity.rs` | **Live** (inherited from upstream) |

**Residual risk:** Argv mode catches the obvious cases. An agent that
emits a legitimate-looking single-command argv with a credential or
secret arg can still leak via the child process's stderr. Mitigated
downstream by `strip_ansi` and `scrub_secrets`.

### Surface 2: tool output → LLM context injection

Anything ContextCrawler emits to stdout or stderr is read by the agent
and lands in its context window. Terminal escape sequences are an
opaque sidechannel: OSC 8 hyperlinks can carry arbitrary URL payloads;
OSC 0/2 window titles, OSC 9 notifications, DCS / APC sequences all
survive as plain text once the terminal ignores them.

| Mitigation | Layer | Status |
|---|---|---|
| `strip_ansi` covers CSI (incl. private DEC), OSC + OSC 8 hyperlinks, DCS, SOS, PM, APC, Fe/Fp/Fs escapes | `src/core/utils.rs` | **Live** since v0.1.5 (GHSA-wjx4-ffxm-fxxp) |
| Callers in `src/cmds/git/`, `src/cmds/cloud/`, `src/cmds/js/`, `src/cmds/python/`, `src/cmds/dotnet/`, `src/cmds/system/grep_cmd.rs`, `src/cmds/go/`, `src/core/runner.rs` all invoke `strip_ansi` on failure-path raw emits | various | **Live** after the raw-emit sweep (ships on the `feat/sec-raw-emit-sweep` branch in this v0.1.6 cycle) |
| Filter output is *opt-in* per command — modules without filters fall through to the raw passthrough path | `src/cmds/*/registry.rs` | Bypassable by design; the trust assumption is the filter author has handled escape stripping. |

**Residual risk:** Prompt-injection text in tool stdout is still verbatim
visible to the LLM. There's no semantic filtering here — only escape /
encoding sanitisation. Defense-in-depth is the agent's role; we just
make sure escapes don't survive as a hidden control channel.

### Surface 3: secrets in tracking.db

Every command contextcrawler observes is timestamped and persisted for
90 days. `gain --history` reads them back to stdout, which an agent can
ingest. Secrets passed on the command line (curl bearer tokens, psql
--password, mysql -pVALUE, AWS keys, GitHub PATs) would otherwise
recirculate into context on every read.

| Mitigation | Layer | Status |
|---|---|---|
| `scrub_secrets` at INSERT boundary in `src/core/tracking.rs::record` | `src/core/tracking.rs` | **Live** since v0.1.5 (GHSA-2cwv-rr7c-2p4c) |
| Patterns covered: credential-bearing flags, Authorization headers, URL userinfo, AWS keys, GitHub classic + fine-grained PATs, Slack tokens, mysql `-p` (scoped) | same | **Live** |
| Same scrub applied in `record_parse_failure` | same | **Live** |
| Escape-aware quoted-value matching | `FLAG_VALUE` regex | **Live** |

**Residual risk:** The scrubber works on the post-`join(" ")` argv,
which is lossy. Wrappers like `env mysql -p…` keep `env` as the first
token so the mysql `-p` gating doesn't fire. Documented limitation in
SECURITY.md.

### Surface 4: project-local TOML filters

`.ctxcrl/filters.toml` in a repo can rewrite any command's output via
`replace` / `match_output` primitives. A malicious public repo could
ship a filter that silently hides security warnings or rewrites URLs
in command output.

| Mitigation | Layer | Status |
|---|---|---|
| SHA-256 trust store for project-local filters | `src/hooks/trust.rs` | **Live** (inherited, SA-2025-RTK-002 / upstream PR #623) |
| Default: untrusted = skip, not warn-and-load | same | **Live** |
| Content change → auto-revoke trust, require re-review | same | **Live** |
| `CONTEXTCRAWLER_TRUST_PROJECT_FILTERS=1` for CI | env override | **Live** but accepts repo-controlled `CI=1` — same as upstream H-2 limitation |

**Residual risk:** Global filters at `~/.config/contextcrawler/filters.toml`
get the same SHA-256 baseline + warning treatment as project filters
(upstream PR #1068).

### Surface 5: hook tampering

The PreToolUse hook auto-approves rewritten commands via
`permissionDecision: allow`. Any process that can write to
`~/.claude/hooks/contextcrawler-rewrite.sh` can inject arbitrary
auto-approved commands.

| Mitigation | Layer | Status |
|---|---|---|
| SHA-256 hash stored at install time | `src/hooks/integrity.rs` | **Live** |
| Runtime check on operational commands; fail closed | same | **Live** |
| No env-var bypass (PR #1078 / upstream fix(integrity)) | same | **Live** |
| Recovery: `contextcrawler init -g --auto-patch` re-baselines | `src/hooks/init.rs` | **Live** |

### Surface 6: build-host metadata in released binary

Rust embeds dependency source paths for panic backtraces. Without
`--remap-path-prefix`, the binary contains `/Users/<builder>/.cargo/...`
and the workspace path. Anyone who downloads a pre-built release
learns the builder's username and directory layout.

| Mitigation | Layer | Status |
|---|---|---|
| `scripts/build-release.sh` sets `RUSTFLAGS=--remap-path-prefix=…` for CARGO_HOME and workspace | repo root | **Live** (ships on the `feat/sec-strip-build-paths` branch this cycle) |
| `--verify` mode asserts the produced binary contains zero builder paths | same | **Live** |
| Proposed CI job runs `--verify` on every PR | `docs/quality/CI_JOBS_PROPOSED.md` (ships on the `chore/quality-baselines` branch this cycle) | **Drafted**, not wired yet (`.github/` is gitignored on the fork) |

### Surface 7: supply chain

We pull ~250 transitive crates. A compromised dependency can run code
at build time (proc macros, build scripts) and at runtime.

| Mitigation | Layer | Status |
|---|---|---|
| `cargo audit` on PR via CI | `.github/workflows/ci.yml` (upstream) | **Live** |
| `cargo deny` config covers advisories, licenses, bans, sources | `deny.toml` (ships on the `chore/quality-baselines` branch this cycle) | **Live** |
| Wildcard deps denied; unknown registries denied | `deny.toml` | **Live** |
| One accepted advisory exception: `RUSTSEC-2025-0057` (fxhash via scraper, unmaintained, no CVE) | `deny.toml` + `docs/quality/BASELINE.md` | **Documented** |
| `Cargo.lock` checked in | repo root | **Live** |
| ContextCrawler's own pre-install supply-chain gate (age + OSV CVE) — for agent-installed packages, not for our own builds | `src/hooks/supply_chain_gate.rs` | **Live**, opt-in |

## Accepted limitations

These are real but we've consciously decided not to address them in
v0.1.x. Each has a tracking note elsewhere; re-evaluate at v0.2.0.

1. **`args.join(" ")` is lossy.** Both the shell-binary blocklist and
   the mysql `-p` scrub depend on the first whitespace-delimited token.
   Wrappers (`env mysql -p…`) and Windows paths with embedded spaces
   bypass them. Mitigated indirectly by the exec-wrapper blocklist in
   surface 1.
2. **The agent can still emit any single-token argv it wants.**
   Defending against an agent that deliberately runs `python -c '<payload>'`
   would require expanding the blocklist to all interpreters and
   accepting that build/test triage commands lose access to them.
   Out of scope for v0.1.x.
3. **544 non-regex `.unwrap()` calls in production** (most upstream-
   inherited). A panic is a DoS, not RCE, but worth driving down over
   time. Tracked in `docs/quality/BASELINE.md`.
4. **`fxhash` unmaintained advisory** is allow-listed in `deny.toml`.
   No active CVE. Re-evaluate when `scraper` upgrades.
5. **Global TOML filter trust check not yet inherited.** Project-local
   `.ctxcrl/filters.toml` is trust-gated (SA-2025-RTK-002 fix is in), but
   `~/.config/ctxcrl/filters.toml` at `src/core/toml_filter.rs:218` loads
   without an integrity check. Upstream PR #1068 fixed this in contextcrawler; we
   need to either cherry-pick it or wrap the global load with the same
   `hooks::trust` check. Surfaced during the 2026-05-15 audit's Codex
   re-review; do not carry into v0.2.0.

## Out of scope

- Cryptographic protection of `tracking.db` at rest. It's user-readable
  only (mode 0600 on the file via OS defaults), and physical-access
  attackers already have RCE.
- Defending against a fully compromised host shell. If `~/.claude/` is
  writable by an attacker, all bets are off.
- Multi-user isolation. CLI is single-user.
- Real-time prompt-injection content detection. We sanitise
  encoding/escapes; semantic filtering is the agent's job.
- Compliance certifications (SOC2, ISO27001). Personal/community tool.

## Change history

- **2026-05-15** — initial draft. Aligned to v0.1.5 release scope.
  Three new GHSAs covered (shell-exec boundary, ANSI/OSC stripping,
  credential scrubbing). raw-emit sweep landed simultaneously.
