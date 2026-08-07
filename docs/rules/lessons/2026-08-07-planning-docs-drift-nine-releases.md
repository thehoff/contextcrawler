# A planning doc that names a version must be pinned to the version by a test

- **Date:** 2026-08-07
- **Origin:** codebase review session, 2026-08-07
- **Proposed status:** ENFORCED (a test can catch it)

## Rule

Any tracked document that states the project's current version or release
line must have a test asserting it matches `Cargo.toml`. A doc-update step in
a runbook is not a control — if the only thing enforcing it is someone
remembering, it will drift.

## Why

`docs/ROADMAP.md` opened with `## Current line: v0.1.x` while `Cargo.toml`
said `0.4.9`. It had been wrong across **nine releases** (0.1.7 → 0.4.9), for
roughly nine weeks.

The consequences were not cosmetic:

- Its `v0.2.0` section carried unchecked boxes for work that may have shipped
  under later releases. Nobody could tell without re-auditing each item, so
  the backlog was unusable as a status report.
- Its `v0.3.0` section named "dropping the rtk-ai/rtk rebase relationship" as
  a *hypothetical* trigger for a major bump. That had already happened —
  the fork was 1,424 commits ahead and 490 behind upstream — and the doc
  still described it as a future possibility.
- The same stale claim ("tracked by rebase") had propagated into `README.md`
  and into the project goal document, so three artefacts agreed with each
  other and all three were wrong.

`docs/ROADMAP.md` already contained the process that would have prevented
this: *"Each release: mark items shipped."* The process existed and was
skipped nine times. That is the actual finding — **the failure was not a
missing rule, it was an unenforced one.**

## How it was found

Reading `Cargo.toml` and the ROADMAP header in the same pass during a general
review, and diffing the claim against `git rev-list --count` for the real
upstream divergence. Not by any test, not by any review, and not by any of
the nine releases that shipped past it.

The generalisable part: **claims about the project's own state are the ones
least likely to be checked**, because everyone assumes someone else checks
them. Verify them against the source of truth (`Cargo.toml`, `git`) the same
way you would verify a claim about behaviour [ctxcrlRules, CTX-007].

## Check

ENFORCED. `tests/docs_currency.rs::roadmap_current_line_matches_cargo_version`
parses `## Current line: vX.Y` out of `docs/ROADMAP.md` and asserts it matches
the `major.minor` in `Cargo.toml`. It fails at the release that forgets,
rather than nine releases later.

If ratified, the same test is the natural home for any future
version-asserting doc — add a row, not a new file.
