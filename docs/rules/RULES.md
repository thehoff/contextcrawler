# ctxcrlRules — ratified law for this repository

Rules earned the hard way, kept where a fresh clone can find them.

Modelled on `askew.devRules`: `RULES.md` is **ratified law**; `lessons/` holds
**unratified candidates**. Cite a rule in review and commit messages as
`[ctxcrlRules, CTX-001]`.

## Status meanings

| Status | Meaning |
|---|---|
| **ENFORCED** | A test fails if you break it. The test is named in the rule. |
| **REVIEW** | A machine cannot check it. It is on the pre-merge checklist below. |

## Why this file is here and not in `.claude/rules/`

`.claude/` is gitignored (see `.gitignore`, "personal/AI workspace — never
publish"). The four guides in `.claude/rules/` are excellent and entirely
untracked: a fresh clone, a git worktree, CI, and every agent session outside
this machine gets none of them. Anything that must be honoured *always* lives
here instead.

---

## CTX-001 — A recovery hint that names a path must shell-quote it

**ENFORCED** — `ctx_001_recovery_hints_shell_quote_their_paths`

Any function that renders a runnable command back to the agent must shell-quote
paths it embeds. Register new hint-emitting functions in `HINT_EMITTERS` in
`tests/ctxcrl_rules.rs`.

**Why.** #236 emitted `contextcrawler read /a/dir with spaces/f.rs --force`.
For a feature that withholds content, the recovery hint *is* the safety net —
a hint that cannot be pasted converts a deferral into a withhold. Found by
mmax; codex passed the same diff.

---

## CTX-002 — A suppression key must include every input that changes the bytes

**ENFORCED** — `read_cache::tests::every_render_mode_field_changes_the_key`

If a cache decides "the agent already has this", its key must cover *every*
input that alters the rendered output — filter level, line numbers, windows,
ranges, intent. Add a field to `RenderMode`, add it to `discriminator()`.

**Why.** The filter level was missing, so a `--level aggressive` render
(signatures only) satisfied a later plain read: the agent was told it already
had a file it had only ever seen stripped. The test varies each field from a
baseline and asserts every key differs, so a new field that is forgotten fails.

---

## CTX-003 — Never suppress over another layer's recovery marker

**ENFORCED** — `read::tests::repeat_read::a_capped_read_is_never_stubbed`

Output already truncated by another layer carries that layer's recovery
guidance. A suppression marker must not replace it.

**Why.** A 4,000-line file capped to a 162-line window was later stubbed as
though the whole file had been delivered — reporting 65,723 tokens the agent
had never seen, while the `--force` hint it advertised re-rendered capped, so
the text was unreachable by the advertised route.

---

## CTX-004 — Test fixtures must not inherit the ambient umask

**ENFORCED** — `ctx_004_hook_test_fixtures_do_not_inherit_the_umask`

In the suites whose product code validates fixture permissions — listed in
`MODE_SENSITIVE_SUITES` in `tests/ctxcrl_rules.rs`, currently
`hooks/integrity.rs` and `hooks/init.rs` — construct fixtures via
`private_tempdir()`, never bare `TempDir::new()`. Add a suite to that list when
its product path starts mode-checking. Override a single line with
`// ctxcrl-rules: allow` plus a reason, on the line or immediately above it.

**Why.** `TempDir::new()` and `fs::write` inherit the umask; at 002 fixtures
land 0775/0664 and the integrity checks correctly reject them. 21 tests failed
for every contributor whose umask was not 022 — for months, on the maintainer's
own machine, dismissed repeatedly as "environmental".

---

## CTX-005 — Rules live where a clone can find them

**ENFORCED** — `ctx_005_rules_document_is_tracked_and_cites_every_enforced_rule`

This document is tracked, and every rule claiming ENFORCED names its test.

---

## CTX-006 — Drive the binary for anything that suppresses output

**REVIEW**

Before merging any change that withholds, substitutes, truncates or gates what
the agent receives: build it and drive the real entry point. A unit test on the
decision function is necessary and *not sufficient*.

**Why.** Across the permission gate and the #236 read cache, **unit tests
written first missed 5 of 5 output-suppression bugs.** Every one lived in the
wiring around a decision function that was itself correct and well tested. Two
were found by driving the binary, three by adversarial review, none by TDD.

**Checklist.** For such a change, before merge:

- [ ] Built the binary and exercised the real path, not just the unit under test
- [ ] Confirmed the feature can never withhold content the agent has not seen
- [ ] If it emits a recovery hint, **executed that hint** and confirmed it works
- [ ] Confirmed it does not overwrite another layer's recovery marker
- [ ] Confirmed every fail-open path really emits (bad config, missing env, corrupt state)

---

## CTX-007 — Check telemetry recency before quoting a number

**REVIEW**

Lifetime aggregates from `history.db` are dominated by whatever period had the
most traffic. Before quoting a figure — in an issue, a commit, or to the Hoff —
group it by month and check the recent window separately.

**Why.** "34.1% savings" was quoted as current. It was a lifetime average
dragged down by a bad June; July was 54.7% across 134k commands. Two issues
were sized off lifetime data and both were wrong: #195's remaining work was
already fixed, and #236 was sized ~10x too high.

---

## CTX-008 — Verify an issue is still live before implementing it

**REVIEW**

Read the code and check recent telemetry before starting. Issues go stale
silently.

**Why.** #190 and #203 were already fixed on develop; #195's wrapper work had
shipped in June. Three of the issues picked up in one session were dead.

---

## CTX-009 — Bind Small+ work to an issue *before* implementing

**REVIEW**

Per the Hoff's git-hygiene law. Filing afterwards is not the same thing.

**Why.** #237 was filed after the fix was already committed.

---

## Recording a lesson

When a fix for a recurring or costly quirk is confirmed, write it to
`docs/rules/lessons/` **at that moment** — see `lessons/TEMPLATE.md`. Do not
promote it to a `CTX-` rule yourself: ratification is the Hoff's manual step,
exactly as with `askew.devRules`.
