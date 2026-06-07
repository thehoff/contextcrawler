# KNOWN_UNBRANDED_TEXT_NEEDLES — Audit (Issue #76)

Audit of `KNOWN_UNBRANDED_TEXT_NEEDLES` in `tests/branding_lint.rs:563-650`.
Goal: reduce ~70 entries to ≤20. This document classifies every entry, points
at its source site, and proposes the action that should retire it.

> Methodology: each entry was grepped against `src/`, then 5-10 lines of
> context were read at the call site. Test-fixture context (`#[cfg(test)]`,
> `assert!`, `expect(...)`) was distinguished from user-visible output
> (`println!`, `eprintln!`, `format!` headers). One entry — the `rtk_cmd`
> assert message — is already wrong (the source now says
> `'contextcrawler '`, the needle still says `'rtk '`); it is a stale-needle
> bug, classified **fix** as a documentation drift.

## Summary

| Bucket | Count |
|--------|-------|
| **fix** — straight rebrand, drop from list, edit source | **38** |
| **reclassify** — belongs in a narrower NAMED allowlist rule | **22** |
| **keep** — genuinely needs `rtk` (legacy install-compat / SQLite column / hook contract) | **10** |
| **Total** | **70** |

After fix + reclassify land, the residual allowlist contains 10 documented
keepers — well under the ≤20 target.

---

## (fix) — Rebrand and remove from allowlist (38)

User-visible output that should now say "ContextCrawler" / `contextcrawler`.
None of these are protocol-bound or persisted; they are headers, hints, and
error messages that ship to the user's terminal.

| Entry literal | File:line | Suggested rebrand |
|---|---|---|
| `RTK Discover -- Savings Opportunities` | src/discover/report.rs:113 | `ContextCrawler Discover -- Savings Opportunities` |
| `Already using RTK:` | src/discover/report.rs:121 | `Already using ContextCrawler:` |
| `RTK usage looks good!` | src/discover/report.rs:131 | `ContextCrawler usage looks good!` |
| `MISSED SAVINGS -- Commands RTK already handles` | src/discover/report.rs:138 | `MISSED SAVINGS -- Commands ContextCrawler already handles` |
| `"RTK Equivalent"` | src/discover/report.rs:143 | `"CC Equivalent"` (column width — keep short) |
| `RTK Parse Failures` | src/analytics/gain.rs:711 | `ContextCrawler Parse Failures` |
| `RTK Session Overview` | src/analytics/session_cmd.rs:148 | `ContextCrawler Session Overview` |
| `RTK commands:` | src/analytics/cc_economics.rs:469 | `ContextCrawler commands:` |
| `RTK compresses CLI outputs` | src/analytics/cc_economics.rs:504 | `ContextCrawler compresses CLI outputs` |
| `"RTK Cmds"` | src/analytics/cc_economics.rs:591,630 | `"CC Cmds"` (table column — keep short) |
| `RTK (Cursor):` | src/hooks/init.rs:643 | `ContextCrawler (Cursor):` |
| `RTK (Gemini):` | src/hooks/init.rs:676 | `ContextCrawler (Gemini):` |
| `RTK was not installed` | src/hooks/init.rs:816 | `ContextCrawler was not installed` |
| `would uninstall RTK` | src/hooks/init.rs:643,676,823,858,1934 | `would uninstall ContextCrawler` (one phrase, 5 sites) |
| `RTK from CLAUDE.md` | src/hooks/init.rs:664 | `ContextCrawler from CLAUDE.md` |
| `RTK from AGENTS.md` | src/hooks/init.rs:847 | `ContextCrawler from AGENTS.md` |
| `RTK from Gemini settings.json` | (no current hit in src/ — orphan; verify before delete) | drop from list if confirmed orphan |
| `RTK for Codex CLI` | src/hooks/init.rs:855,858 | `ContextCrawler for Codex CLI` |
| `RTK for Hermes CLI` | src/hooks/init.rs:1934 | `ContextCrawler for Hermes CLI` |
| `removed RTK plugin entry` | src/hooks/init.rs:2000 | `removed ContextCrawler plugin entry` |
| `RTK end marker must be removed` | src/hooks/init.rs:6188 | test assert message — rebrand to `ContextCrawler end marker must be removed` |
| `Rules file should reference the rewrite tool (RTK or ContextCrawler brand)` | src/hooks/init.rs:4254,4282 | test assert — simplify to `Rules file should reference the rewrite tool` (drop dual-brand parens) |
| `RTK collects anonymous usage metrics` | src/core/telemetry_cmd.rs:72 | `ContextCrawler collects anonymous usage metrics` |
| `[full diff: rtk git diff --no-compact]` | src/cmds/git/git.rs:522 (also assert at 3044) | `[full diff: contextcrawler git diff --no-compact]` |
| `Usage: rtk docker logs` | src/cmds/cloud/container.rs:204 | `Usage: contextcrawler docker logs` |
| `Usage: rtk kubectl logs` | src/cmds/cloud/container.rs:374 | `Usage: contextcrawler kubectl logs` |
| `Usage: rtk proxy` | src/main.rs:2755 | `Usage: contextcrawler proxy` |
| `Use: rtk init --agent kilocode` | src/main.rs:2343 | `Use: contextcrawler init --agent kilocode` |
| `Use: rtk init --agent antigravity` | src/main.rs:2349 | `Use: contextcrawler init --agent antigravity` |
| `To restore:  rtk init -g` | src/hooks/integrity.rs:326 | `To restore:  contextcrawler init -g --auto-patch` |
| `To inspect:  rtk verify` | src/hooks/integrity.rs:327 | `To inspect:  contextcrawler verify` |
| `rtk_cmd '{}' must start with 'rtk '` | src/discover/registry.rs:3188 | **already fixed in source** (now says `'contextcrawler '`) — needle is stale; just drop it from the allowlist |
| `Run some rtk commands to start tracking` | src/analytics/cc_economics.rs:436 | `Run some contextcrawler commands to start tracking` |
| `tracked via \`rtk gain\`` | src/discover/report.rs:218,222 | `tracked via \`contextcrawler gain\`` |

---

## (reclassify) — Belongs in a narrower NAMED allowlist rule (22)

These are not user-visible debt; they're either test fixtures, assert
messages comparing the legacy DB column, or filesystem path literals that
should always exist. Each cluster suggests one new allowlist rule (see
"Suggested new allowlist rules" below).

| Entry literal | File:line | New rule name |
|---|---|---|
| `"RTK-default limit` | src/cmds/git/git.rs:2314 | `test-assert-message` |
| `"RTK", "Adoption"` | src/analytics/session_cmd.rs:153 | `analytics-table-header-short` |
| `r.rtk_cmd == ` | src/core/tracking.rs:1739,1771,1775,1800 | `db-column-test-comparison` |
| `rtk_nonexistent_file` | src/cmds/system/read.rs:641,649 | `test-fixture-path` |
| `failed to run rtk read` | src/cmds/system/read.rs:623,643,662 | `test-fixture-expect-message` |
| `failed to run rtk` | (covered by line above) | same |
| `Failed to run rtk` | src/discover/registry.rs:1585; src/cmds/git/git.rs:2982 | `test-fixture-expect-message` |
| `format_crate_info("rtk"` | src/cmds/rust/cargo_cmd.rs:1866,1867 | `test-fixture-fn-arg` |
| `test-rtk-create-` | src/cmds/git/git.rs:2860,2882 | `test-fixture-branch-name` |
| `-Users-test-rtk` | src/discover/provider.rs:442 | `test-fixture-path` |
| `Some("rtk")` | src/discover/provider.rs:451 | `test-fixture-fn-arg` |
| `fs::write(&nested_plugin_file, "rtk")` | src/hooks/init.rs:4466,4503 | `test-fixture-fs-write` |
| `config_dir.join("rtk/filters")` | src/core/telemetry.rs:397 | `xdg-legacy-path` (kept on disk for migration) |
| `config_dir.join("rtk")` | src/core/telemetry.rs:397 (same expression) | `xdg-legacy-path` |
| `"command": "rtk git status"` | src/analytics/session_cmd.rs:354,382 | `test-fixture-jsonl-fixture` (raw JSONL test input — comment in allowlist mis-attributes to hooks/hook_cmd.rs) |

> **Note**: the allowlist comment for `"command": "rtk git status"` claims
> `src/hooks/hook_cmd.rs` — actual hits are in `src/analytics/session_cmd.rs`
> raw-string JSONL fixtures. Update the comment when reclassifying.

---

## (keep) — Genuine technical reason to retain (10)

These are bound by external contracts (install-compat alias, hook script
filenames Claude Code expects on disk, the SQLite column name) and **must**
remain `rtk` until the legacy alias is formally retired in a future major
version.

| Entry literal | File:line | Justification |
|---|---|---|
| `rtk-rewrite.sh` | src/hooks/constants.rs:1; src/hooks/integrity.rs (many); src/hooks/init.rs (many) | On-disk hook filename hashed and registered in `~/.claude/settings.json`; renaming breaks existing installs until a migration ships |
| `rtk-hook-gemini.sh` | src/hooks/constants.rs:2 | On-disk Gemini hook filename, same constraint |
| `rtk hook claude` | src/hooks/constants.rs:21 (`LEGACY_CLAUDE_HOOK_COMMAND`) | Recognised legacy hook command in user settings.json — kept for detection-and-migration; deliberate constant prefixed `LEGACY_` |
| `rtk hook cursor` | src/hooks/constants.rs:22 (`LEGACY_CURSOR_HOOK_COMMAND`) | Same as above for Cursor |
| `rtk.ts` | src/hooks/constants.rs:27 (`OPENCODE_PLUGIN_FILE`) | OpenCode plugin filename on disk; renaming breaks existing installs |
| `command -v rtk` | src/hooks/init.rs:3350 | Hook-detection probe — handles users who installed via the `rtk` cargo alias; paired with `command -v contextcrawler` |
| `rtk::` | doc-comment examples (DOC_EXAMPLE_NEEDLES — already separate) | Crate path retained for cargo-install-compat; covered by its own narrower rule already |
| `X-RTK-Token`, `RTK_TELEMETRY_TOKEN` | (already in HOOK_PROTOCOL / RTK_ENVISH — listed for completeness) | telemetry header / env contract |
| `RTK_DB_PATH` | (env var — covered by `RTK_ENVISH_RE`) | persistent env contract — users have it set |
| `rtk_cmd` SQLite column references in `tracking.rs` | (covered by `r.rtk_cmd` reclassify above) | DB schema; column rename = migration |

---

## Suggested new allowlist rules

Any rule below would absorb ≥3 of the reclassify-bucket entries with a
narrower, intent-named matcher. Names are draft proposals.

### 1. `test-fixture-expect-message`
Matches lines inside `#[cfg(test)]` modules of the shape
`.expect("... rtk ...")` and `.unwrap_or_else(|_| "... rtk ...")`.
Absorbs: `failed to run rtk read`, `failed to run rtk`, `Failed to run rtk`
(≥4 sites).

Suggested predicate: a regex `\.expect\("[^"]*\brtk\b[^"]*"\)` gated by an
in-test-module check (file under tests/ OR the line being syntactically
inside a `#[cfg(test)]` block — branding_lint already has a strip-comment
helper, the test-block scan should follow that pattern).

### 2. `test-fixture-path`
Matches raw fixture path literals: `*"...rtk_nonexistent_file*"`,
`*"...-Users-test-rtk*"`, etc. Absorbs: `rtk_nonexistent_file`,
`-Users-test-rtk`, and future test-only synthesised path strings.
Predicate: literals inside `#[cfg(test)]` whose content matches
`[A-Za-z0-9_./-]*rtk[A-Za-z0-9_./-]*` (no whitespace).

### 3. `db-column-test-comparison`
Matches `r.rtk_cmd == "..."` and `rule.rtk_cmd` accesses in tests. The
column name is fixed by schema; tests must compare against it.
Predicate: `\.rtk_cmd\s*==` OR `\.rtk_cmd\.` (4+ sites in `core/tracking.rs`
and `discover/registry.rs`).

### 4. `test-fixture-fn-arg`
Matches function-arg fixtures: `format_crate_info("rtk", ...)`,
`Some("rtk")`, `make_cmd("rtk git status", ...)`.
Predicate: literals appearing as positional arguments inside `#[cfg(test)]`
blocks. (Three direct entries today, more latent in `session_cmd.rs`.)

### 5. `xdg-legacy-path`
Matches `~/.config/rtk` and `.rtk/filters` path references kept for
migration. Absorbs the two `config_dir.join(...)` entries plus the
many `.rtk/filters.toml` references already wandering through
`core/toml_filter.rs`, `hooks/trust.rs`, `hooks/init.rs`. Note: most are
already covered by `PATH_NEEDLES`; the entries in
`KNOWN_UNBRANDED_TEXT_NEEDLES` are redundant — verify and delete from
allowlist if PATH_NEEDLES already matches.

### 6. `test-fixture-jsonl-fixture`
Matches raw-string JSONL fixtures used by `session_cmd.rs` tests, e.g.
`r#"...{"command":"rtk git status"}..."#`. Test-only; never executed.
Predicate: `r#".*\bcommand\b.*\brtk\b.*"#` gated by test-block scope.

### 7. `analytics-table-header-short`
Narrow column-header literals like `"RTK"`, `"RTK Cmds"`. Strict
allowlist (3-4 known short headers) so a new header still has to be added
explicitly. Absorbs the short-form entries that fail the wider rebrand
test because column width is constrained.

> **Implementation note**: After landing rules 1-4, the
> `KNOWN_UNBRANDED_TEXT_NEEDLES` allowlist should compress to ~10
> entries — the (keep) bucket above plus any genuinely irreducible debt.

---

## Quick-win cluster (one-PR rebrand)

The 10 highest-confidence, lowest-risk rebrands. All are user-visible string
literals in non-protocol paths; none cross install-compat or DB-schema
boundaries. Recommended single-PR scope:

1. `src/discover/report.rs:113` — `RTK Discover -- Savings Opportunities` → `ContextCrawler ...`
2. `src/discover/report.rs:121` — `Already using RTK:` → `Already using ContextCrawler:`
3. `src/discover/report.rs:131` — `RTK usage looks good!` → `ContextCrawler usage looks good!`
4. `src/discover/report.rs:138` — `MISSED SAVINGS -- Commands RTK already handles` → `... ContextCrawler ...`
5. `src/discover/report.rs:218,222` — `tracked via \`rtk gain\`` → `tracked via \`contextcrawler gain\``
6. `src/analytics/gain.rs:711` — `RTK Parse Failures` → `ContextCrawler Parse Failures`
7. `src/analytics/session_cmd.rs:148` — `RTK Session Overview` → `ContextCrawler Session Overview`
8. `src/analytics/cc_economics.rs:436` — `Run some rtk commands to start tracking` → `Run some contextcrawler commands ...`
9. `src/analytics/cc_economics.rs:469` — `RTK commands:` → `ContextCrawler commands:`
10. `src/analytics/cc_economics.rs:504` — `RTK compresses CLI outputs` → `ContextCrawler compresses CLI outputs`

These touch three files (`discover/report.rs`, `analytics/gain.rs`,
`analytics/cc_economics.rs`, `analytics/session_cmd.rs`) and drop ~12
needles from the allowlist in one shot. No snapshot files need
regenerating — these strings are not snapshot-tested (the headers are
emitted by `gain` / `discover` / `session` commands, which are
integration-tested rather than snapshotted).

### Verification checklist for the quick-win PR

- [ ] Run `cargo test --test branding_lint` — the affected entries must be
      removed from `KNOWN_UNBRANDED_TEXT_NEEDLES` in the same PR or the
      lint fails ("known-unbranded-text-debt rule had unused needles").
- [ ] Run `cargo test` — pick up any string-equality unit tests that
      embed the old header.
- [ ] Update `tests/branding_lint.rs:564-577,633,647` comments to drop
      the deleted entries; renumber the per-file comment groupings.
- [ ] Manually run `contextcrawler discover` and `contextcrawler gain`
      against a populated DB to eyeball the new headers.

---

## Outstanding question

`RTK from Gemini settings.json` (line 585 of the allowlist) returned **0
hits** under `src/`. Either the source was already rebranded and the needle
is orphaned (drop it), or the literal has been split across format
arguments (verify with `cargo test --test branding_lint -- --ignored` after
removing the needle — if the test passes, it was orphaned).
