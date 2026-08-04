# Unit tests do not catch output-suppression bugs; driving the binary does

- **Date:** 2026-08-04
- **Origin:** #236 (repeat-read cache), and the earlier #2286 permission-gate work
- **Proposed status:** REVIEW — ratified as CTX-006

## Rule

For any change that withholds, substitutes, truncates or gates what the agent
receives, build the binary and drive the real entry point before merge. A unit
test on the decision function is necessary and not sufficient.

## Why

Across two features, **unit tests written first missed 5 of 5 output-suppression
bugs**, despite TDD and 3400+ passing tests.

#2286 (permission gate): the verdict function was correct and well tested; the
bug lived in the consumer, which let a bare `Ask` fall through to an empty
Skip, so `git status $(whoami)` ran unprompted.

#236 (repeat-read cache), four bugs, all mine:

1. Cache refused to key on render mode, so the largest repeat clusters (a file
   read 84x via `nl -ba`) were skipped entirely.
2. A read truncated by the large-file cap was later stubbed as though the whole
   file had been delivered — reported 65,723 tokens never emitted, and the
   `--force` hint it advertised re-rendered capped, so the text was unreachable
   by the advertised route.
3. Filter level missing from the cache key, so a `--level aggressive` render
   (signatures only) satisfied a later plain read.
4. Recovery command unquoted, so any path with a space produced a hint the
   agent cannot run — and that hint is the feature's entire safety net.

Every one of them lived in the *wiring* around a decision function that was
itself correct.

## How it was found

Bugs 1 and 2: driving the real binary. Bugs 3 and 4: adversarial review (mmax).
Zero by the unit tests. Note also that codex returned SHIP on the diff that
still contained bugs 3 and 4 — a single reviewer was not enough either.

## Check

REVIEW checklist, now CTX-006 in `../RULES.md`. Two of its lines became
enforceable rules in their own right: CTX-001 (recovery hints must be
shell-quoted) and CTX-002 (a suppression key must include every input that
changes the bytes), both with tests in `tests/ctxcrl_rules.rs` and
`read_cache.rs` respectively.
