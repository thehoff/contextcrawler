# Shell parsing and permission-gate hardening

## Status

The scoped permission, lexer, and rewriter work is implemented and verified.
Seven issues are fully resolved. Issue #218 is partial: substitution extraction is
now bounded and iterative, but the separate filter-file read remains open because
its live callsites are in `src/core/toml_filter.rs`, outside the explicit allowed
edit set (`permissions.rs`, `lexer.rs`, and `registry.rs`).

## Design

- Permission matching now resolves the executed command after shell assignments,
  leading redirects, `!`, `time`, `env`, `command`, `builtin`, `exec`, `noglob`,
  and `nocorrect`. Unknown wrapper shapes and runtime-produced command words fail
  closed to Ask. Redirects and their operands are removed without erasing command
  tokens on either side.
- Wildcard-free allow rules require exact token equality. Prefix behavior remains
  available only through an explicit wildcard. Deny and ask rules retain their
  existing prefix semantics.
- Command substitutions use the full permission decomposition and shell-aware
  argument parsing. Literal interpreter payloads are recursively checked with a
  depth bound; dynamic interpreter, `eval`, and `source` payloads Ask.
- Pipeline taint rejects reader-to-network exfiltration and
  network-to-interpreter execution. Network sinks with file-backed input redirects
  Ask. Ordinary non-hazardous pipelines remain allowable.
- Policy loading distinguishes missing files from unreadable, malformed, or
  schema-invalid files. Any applicable validation failure prevents auto-Allow.
  Project discovery prefers the worktree `.git` root, so nested `.claude`
  directories cannot shadow root policy.
- The lexer removes active backslash-newline continuations, treats `|&` as one
  pipe token, rejects ANSI-C quoting and identifier-based arithmetic as
  unattestable, and preserves raw grouped pipelines, redirect-bearing assignment
  prefixes, and commands following persistent `exec` redirections.
- Substitution extraction uses an iterative worklist with 64 KiB input, depth 64,
  1,024-substitution, and 256 KiB extracted-byte limits. Limit breaches emit a
  malformed sentinel so callers fail closed.

## Issue and planned commit mapping

The intended local commit is
`fix(security): harden shell permission parsing (#212 #213 #214 #215 #216 #217 #218 #230)`.
The sandbox cannot create `.git/worktrees/ccrawl-perm/index.lock` because the
worktree's git metadata is read-only, so the changes remain unstaged for the
driver to commit with that subject. Nothing was pushed.

| Issue | Status | Covered by the working tree |
| --- | --- | --- |
| #212 | RESOLVED | Resolved command-word matching through assignments, redirects, and shell prefixes |
| #213 | RESOLVED | Substitution command-word checks, interpreter recursion, full decomposition, shell-aware flags |
| #214 | RESOLVED | Reader/network/interpreter pipeline taint |
| #215 | RESOLVED | Exact wildcard-free allow matching |
| #216 | RESOLVED | Fail-closed policy validation and worktree-root discovery |
| #217 | RESOLVED | ANSI-C, continuation, `|&`, group, arithmetic, env-redirect, and persistent-`exec` handling |
| #218 | PARTIAL | Iterative bounded substitution extraction only |
| #230 | RESOLVED | Dynamic command-word Ask and network input-redirect Ask |

Every listed trigger has a named regression test. The regressions were exercised
as failing tests before their implementations and now pass with
`CONTEXTCRAWLER_TRUST_UNATTESTABLE` unset.

## Verification

- `cargo build --lib`: PASS.
- `cargo clippy --lib`: PASS (exit 0). It reports 20 pre-existing warnings in
  untouched files; none point to the three edited Rust files.
- Clean environment (`umask 077`, trust override unset):
  - `cargo test --lib issue_21`: PASS, 26 tests.
  - `cargo test --lib issue_230`: PASS, 2 tests.
  - `cargo test --lib hooks::permissions`: PASS, 141 tests.
  - `cargo test --lib discover::lexer`: PASS, 133 tests.
  - `cargo test --lib discover::registry`: PASS, 359 tests.
- Full clean `cargo test --lib`: BLOCKED by the known sandbox subprocess class.
  `core::stream::tests::test_exec_capture_default_unchanged_for_short_output`
  aborts in `wait-timeout`'s SIGCHLD handler with `Operation not permitted
  (os error 1)` and SIGABRT. The changed-module suites above complete cleanly.

## Residual

Issue #218 also requires bounded, no-follow reads for project and global
`filters.toml`. The active unbounded, symlink-following reads are at
`src/core/toml_filter.rs` (including the project and global load paths). No helper
added to one of the allowed files can secure those reads unless that callsite is
changed. This item is deliberately not represented as closed.
