# A schema change to a cache goes silently inert, and tests cannot see it

- **Date:** 2026-08-04
- **Origin:** #236, found during `cargo install` smoke test
- **Proposed status:** ENFORCED — a schema-mismatch test per persisted store

## Rule

Any persisted store owned by a feature must detect a shape it did not write and
repair it. For a cache, recreate. Never assume `CREATE TABLE IF NOT EXISTS` is
a migration — it is not.

## Why

Renaming `first_seen` to `last_seen` in the read cache passed every test and
every review. On a machine that had already run the previous build, the live DB
still had `first_seen`, `CREATE TABLE IF NOT EXISTS` left it alone, and every
query then errored. The feature fails open by design, so it emitted content
correctly and went **completely inert without a single symptom**.

Safe, but useless, and invisible. The savings simply never appeared.

## How it was found

Not by tests — by `cargo install --path .` and then using the binary on a real
machine with real prior state. **Unit tests structurally cannot catch this
class of bug: they always start from an empty database.** Nor can review, which
sees only the new schema and agrees it is correct.

This is the same lesson as CTX-006 with a sharper edge: it is not enough to
drive the binary on a clean fixture, it must be driven against *existing state*
left by the previous version.

## Check

`read_cache::tests::a_stale_schema_is_rebuilt_rather_than_breaking_every_query`
writes the legacy shape, then asserts a round-trip still works. Repeat this
pattern for any new persisted store. Candidate rule text:

> Every persisted store must have a test that writes the *previous* schema and
> asserts the feature still functions.
