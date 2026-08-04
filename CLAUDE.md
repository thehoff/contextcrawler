# contextcrawler — agent instructions

Tracked deliberately: `.claude/` is gitignored, so anything kept there reaches
neither a fresh clone, a git worktree, nor CI. This file does.

## ctxcrlRules

Full text and the reasoning behind each rule: **[docs/rules/RULES.md](docs/rules/RULES.md)**.
Cite rules as `[ctxcrlRules, CTX-001]`.

**ENFORCED** — `cargo test` fails if you break these:

| Rule | Law |
|---|---|
| CTX-001 | A recovery hint that names a path must shell-quote it. |
| CTX-002 | A suppression key must include every input that changes the emitted bytes. |
| CTX-003 | Never suppress over another layer's recovery marker. |
| CTX-004 | Fixtures in mode-validating suites must not inherit the ambient umask. |
| CTX-005 | Rules live where a clone can find them; ENFORCED rules name their test. |
| CTX-011 | A persisted store must repair a schema it did not write. |

**REVIEW** — no machine can check these, so they are on you:

| Rule | Law |
|---|---|
| CTX-006 | Drive the binary for anything that suppresses output. |
| CTX-007 | Check telemetry recency before quoting a number. |
| CTX-008 | Verify an issue is still live before implementing it. |
| CTX-009 | Bind Small+ work to an issue *before* implementing. |
| CTX-010 | "Tests pass" must name the suite — `--lib` is not the whole suite. |
| CTX-012 | Verify what a reproduction actually measures before trusting it. |
| CTX-013 | A failing test is a finding until it is root-caused. |

## CTX-006 in full, because it is the one that keeps being broken

If your change withholds, substitutes, truncates or gates what the caller
receives, **TDD is not sufficient**. Across the permission gate and the #236
read cache, unit tests written first missed **5 of 5** bugs of that kind. Every
one lived in the wiring around a decision function that was itself correct and
well tested.

Before merging such a change:

- [ ] Built the binary and exercised the real path, not just the unit under test
- [ ] Drove it against **state a previous version left behind**, not only a clean fixture
- [ ] Confirmed it can never withhold content the caller has not already seen
- [ ] If it emits a recovery hint, **executed that hint** and confirmed it works
- [ ] Confirmed it does not overwrite another layer's recovery marker
- [ ] Confirmed every fail-open path really emits (bad config, missing env, corrupt or stale state)

A feature that fails open can be completely inert and show no symptom at all.
That is not a hypothetical: renaming one cache column did exactly that, passed
every test and two reviews, and was only caught by installing the binary.

## The four ways this repo has been fooled

Each of these cost real time on 2026-08-04 and each is now a rule:

- **Reporting green from a subset.** `cargo test --lib` was clean while
  `cargo test` was red for the whole session (CTX-010).
- **Trusting a reproduction.** #200's repro timed the *shell*, not the process,
  and reported a fixed bug as broken (CTX-012).
- **Writing off red tests.** 21 failures dismissed as "environmental" five
  times; they were a real portability defect (CTX-013).
- **Assuming `IF NOT EXISTS` migrates.** It does not; the feature went silently
  inert against an older DB (CTX-011).

## Recording what you learn

Confirmed a fix for something that cost real time and will recur? Write it to
`docs/rules/lessons/` **at that moment**, using `lessons/TEMPLATE.md`. Do not
promote it to a numbered rule yourself — ratification is the maintainer's step.

## House rules worth knowing

- Verify claims against the source or a real run before stating them. "Tests
  pass" means naming which suite: `cargo test --lib` is not `cargo test`.
- Install from source (`cargo install --path .`). Never copy a built binary.
- Local guides in `.claude/rules/` (Rust patterns, gate architecture, CLI
  testing, search strategy) are useful but untracked — treat them as this
  machine's notes, not as law.
