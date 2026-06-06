# ContextCrawler roadmap

Living planning document. Update when scope changes; don't strip the
history — past entries are useful when answering "why did we do it
this way?" later.

## Current line: v0.1.x

v0.1.x is the **security-hardening + maintenance-framework** line.
We're driving down the upstream rtk-ai/rtk security gap that
[`rtk-ai/rtk#640`](https://github.com/rtk-ai/rtk/issues/640)
exposed, while building documentation and tooling that lets us
maintain the fork sustainably.

| Tag | Status | Theme |
|---|---|---|
| v0.1.0 | shipped | First community release |
| v0.1.1–v0.1.4 | shipped | Branding sweep, hook prefix fix, gate-design notes |
| **v0.1.5** | **shipped** | **Three downstream-only GHSAs**: shell-exec boundary, ANSI/OSC stripping, credential scrub |
| **v0.1.6** | **shipped 2026-05-15** | Build-path leak, raw-emit sweep, quality baselines, threat model, release runbook, module audits — plus the two items originally deferred to v0.1.7: global-filter trust gap **H-3** (`52b475e` SHA-256 gate + TOCTOU follow-up `97fe98e`) and tirith subprocess timeout **F-01** (`b4c93c3`). Also web SSRF block, supply-chain CVSS hardening, CI trust-token check. See `docs/sessions/2026-05-15-overnight.md`. |
| v0.1.7 | unscoped | No carry-over from v0.1.6. Reserved for an out-of-band security patch if one needs to ship before a v0.2.0 candidate is ready. |

## v0.2.0 — minor bump, end-Q3 2026

The v0.2.0 boundary is **when we change the default CLI behaviour in
a user-visible way**. Each item below is a v0.2.0-eligible change;
ship them when one of them is mature, not all at once.

### Security and trust

- [x] ~~**Global TOML filter trust check.**~~ Landed in v0.1.6
      (`52b475e` + TOCTOU follow-up `97fe98e`). Closed H-3.
- [ ] **Subprocess timeouts everywhere.** Tirith gate (F-01) was
      closed in v0.1.6 via `b4c93c3`; analytics `security_cmd` got
      the same pattern. **Remaining work:** audit every other
      `Command::output()` / `Command::spawn` site in `src/cmds/*`,
      `src/core/*`, `src/discover/*` and apply the same
      `wait-timeout` + `Stdio::null()` (stdin) + stdout-cap pattern.
      First v0.2.0 work item — see `docs/security/AUDIT-subprocess-timeouts.md`.
- [ ] **Hash-pin the tirith binary** (optional). Defence in depth for
      the `~/.cargo/bin/tirith` fallback path. Adds operational
      friction; only land if F-03 in the tirith audit becomes a real
      concern.
- [ ] **Address upstream issue #1820** if it lands first: contextcrawler proxy
      not used by Claude Code subagents (massive token leak in
      multi-agent workflows). Either inherit upstream's fix or scope
      our own. Reference: rtk-ai/rtk#1820.
- [ ] **`scrub_secrets` v2.** Audit gaps from the 2026-05-15 review:
      env-wrapper bypass (`env mysql -p`), Windows path with spaces,
      additional secret patterns (Stripe / OpenAI / Anthropic API
      keys with their published prefixes). Move from regex-based to a
      tokeniser-based pass that handles argv reconstruction.
- [ ] **Drive down `.unwrap()` in production** (currently 544 non-
      regex unwraps per `docs/quality/BASELINE.md`). Target: -150 by
      v0.2.0. Focus on `src/hooks/` and `src/core/runner.rs`.

### Process and tooling

- [ ] **Land the proposed CI jobs.** `docs/quality/CI_JOBS_PROPOSED.md`
      drafts `release-build` (path-leak gate) and `deny` (cargo deny
      check). Wire into `.github/workflows/ci.yml` when the gitignore
      situation is sorted out.
- [ ] **Commit signing default on.** Existing GHSAs already reference
      unsigned commits; new work signs going forward. Document the
      flow in RELEASING.md once the SSH-agent setup is stable.
- [ ] **Auto-rebase against upstream every two weeks.** Cron-driven
      branch that opens a PR with the rebase diff. Reviewed before
      merge so we never go more than ~50 upstream commits stale.

### Capability expansion

- [ ] **Subagent coverage analysis.** Per upstream #1820 — figure out
      whether `permissionDecision: allow` reaches Claude Code
      subagent tool calls. If not, scope a fix or document the
      limitation in `THREAT_MODEL.md`.
- [ ] **Multi-model peer review hook.** User profile mentions
      OpenCode / ClaudeCode / Pi.Dev as reference models — wire one
      of those into the rewrite-decision path as a second opinion
      gate. Opt-in.
- [ ] **Supply-chain gate v2.** Address findings F-01..F-06 from the
      module audit. Highest priority: parallel HTTP fetches for
      N>1 packages (latency), atomic cache writes, content-type
      checks, CVSS-numeric severity parsing.

### Removals

- [ ] **Drop or vendor `scraper`** to eliminate the `fxhash`
      unmaintained advisory. Either find a different HTML extractor
      or vendor a minimal one inline.
- [ ] **Drop the 1Password commit-signing dependency** from the
      release flow — make `gpg.format = ssh` the documented default,
      no agent intermediary.

## v0.3.0 — major bump, no fixed date

Reserve for things that materially change what ContextCrawler **is**.
No items currently scoped — bumping here would mean either dropping
the rtk-ai/rtk rebase relationship, switching the agent-hook
protocol, or pivoting the project's role in the LLM-agent stack.

If one of those happens, this section gets populated and v0.2.x
becomes the stable LTS line.

## Tracking model

Major / minor / patch follows the same rule as RELEASING.md:

| Change type | Bump |
|---|---|
| Bugfix / security patch / doc-only | patch (e.g. 0.1.6 → 0.1.7) |
| New capability behind an opt-in flag | patch |
| Breaking change in CLI surface or default behaviour | minor (0.1.x → 0.2.0) |
| Dropping the rtk-ai/rtk rebase relationship, hook-protocol switch | major (0.x → 1.0) |

The internal `Cargo.toml` version tracks the upstream rtk version
this fork rebases against. ContextCrawler's own version lives in
`src/main.rs::CONTEXTCRAWLER_VERSION` and the README install commands,
all bumped together via `scripts/bump-version.sh`.

## How this doc gets updated

- Each release: mark items shipped, move incomplete items down the
  list (don't delete — history is useful).
- Each Codex audit pass: add the unfixed findings as v0.2.0
  candidates.
- Each external bug report that names a class of issue we haven't
  tackled: add it to the appropriate section.

Anything that's been on this list for two releases without progress
should either be closed as "won't fix" or escalated.

## Out of scope (current line)

- Cross-platform Windows native parity. macOS + Linux is the focus;
  Windows works to the extent upstream supports it. Re-evaluate if a
  Windows-only contributor steps up.
- Cryptographic protection of `tracking.db`. Documented in
  `THREAT_MODEL.md`.
- Multi-user isolation. ContextCrawler is single-user by design.
- Real-time prompt-injection content detection. We sanitise
  encoding/escapes; semantic filtering is the agent's job.
