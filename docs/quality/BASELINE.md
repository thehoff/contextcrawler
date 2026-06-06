# Code quality baseline — 2026-05-15

Snapshot taken on `develop` at commit immediately after the v0.1.5 security
release. Track the trend over time; **don't regress** these numbers without
a clear reason in the commit message.

## Test suite

| Metric | Value |
|---|---|
| Total tests | 1828 passed, 0 failed, 6 ignored |
| Suite runtime | ~1.0 s (debug) |
| Test files | `src/**/*.rs` (inline `#[cfg(test)]` modules) + `tests/` |

Production rule: every `*_cmd.rs` ships with at least one snapshot test
and one token-savings test (see `.claude/rules/cli-testing.md`).
`scripts/check-test-presence.sh` enforces this in CI.

## Static analysis — clippy

| Metric | Value | Notes |
|---|---|---|
| Errors (`-D unsafe_code`) | 0 | CI fail gate |
| Warnings | 28 | Mostly upstream-inherited style nits |
| Auto-fixable | 19 | `cargo clippy --fix --bin contextcrawler -p contextcrawler -- --no-deps` |

Top warning categories: `collapsible_if`, `unnecessary_sort_by`,
`needless_borrow`, `redundant_clone`. None affect correctness.

## `cargo audit` (dependency CVEs)

| Severity | Count | Detail |
|---|---|---|
| Vulnerabilities | 0 | No active CVEs in the dep graph |
| Unmaintained warnings | 1 | `RUSTSEC-2025-0057` — `fxhash 0.2.1` (transitive via `scraper → selectors → fxhash`). Used by the contextcrawler web-extract code path only. Re-evaluate when `selectors` upgrades. |

Database scanned: RustSec, 1088 advisories.

## Unsafe code

| Location | Reason |
|---|---|
| `src/main.rs:2353` `unsafe extern "C" fn handle_signal` | POSIX signal handler — must be `extern "C"`. Calls only async-signal-safe libc functions. |
| `src/main.rs:2363` `unsafe { libc::signal(...) }` | Installing the handler above. Required FFI. |

No other unsafe blocks in production code. CI flag `-D unsafe_code` would
reject new ones; the two existing blocks are grandfathered via the
`#[allow(unsafe_code)]` attribute or similar gating (TODO confirm exact
gating, see follow-up below).

## `.unwrap()` in production code

645 total in `src/` excluding `#[cfg(test)]` blocks.

| Class | Count | Status |
|---|---|---|
| `Regex::new(...).unwrap()` inside `lazy_static!` | 101 | **Acceptable** per project rules — bad regex literal is a programming error caught at first use. |
| Other unwraps | 544 | Mostly inherited from upstream rtk. Triage as follow-up. |

The `.claude/rules/rust-patterns.md` policy is "no `.unwrap()` in
production except `lazy_static!` regex". The 544 are technical debt
from before the policy was tight. Track but do not block on this — many
are also `Mutex::lock().unwrap()` (legitimate poisoning panic) or `OnceCell`
init paths.

## Release binary surface

| Check | Result |
|---|---|
| `strings | grep $HOME` (after `scripts/build-release.sh`) | 0 (verified) |
| `strings | grep /Users/dev/` (test fixture noise) | ~19 (expected — test fixture data) |
| Binary size (release, stripped, trim-paths) | ~8 MB |
| Startup (`time contextcrawler --version`) | <10 ms |

`scripts/build-release.sh --verify` enforces zero builder-path leaks
before publication. Wire this into the release workflow.

## Track-over-time targets

| Metric | Target | Tolerance |
|---|---|---|
| Test count | Increase only | -0 (CI fails on net deletion via test-presence check) |
| Clippy warnings | Decrease | +5 ok in a single PR if justified |
| `cargo audit` vulns | 0 | 0 |
| Unwrap drift | -5/release | net |
| Build path leaks | 0 | 0 (CI gate) |

## Follow-ups (not blocking)

- [ ] Confirm grandfathering mechanism for the two `unsafe` blocks (`#[allow]` vs `-D` ordering).
- [ ] Plan to reduce non-regex unwraps by ~50/release. First targets: hot paths in `src/hooks/` and `src/core/runner.rs`.
- [ ] Evaluate alternatives to `fxhash` chain via `scraper` (or vendor a minimal HTML extractor without the dep).
- [ ] Run clippy with `-W clippy::pedantic` once to scope what's there; cherry-pick the high-signal ones into the default-warn set.
- [ ] **Wire `cargo deny check` and `scripts/build-release.sh --verify` into CI.** `.github/` is gitignored on this fork (the workflow file lives outside the repo). Two new CI jobs are drafted in `docs/quality/CI_JOBS_PROPOSED.md` — paste into the real workflow when convenient.
