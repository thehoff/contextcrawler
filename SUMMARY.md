# Filter-engine cluster summary

## Commit and issue mapping

The commit containing this file is `fix(filter): harden filter engine bounds and parsers (#226 #232 #233)`.

- **#226** — replaces regex-only ANSI stripping with a blob-wide OSC/DCS/CSI state machine; redacts TOML debug command arguments; fixes aggressive-filter brace tracking and inline-body redaction; adds a UTF-8-safe 1 MiB filter-input ceiling.
- **#232** — recognises Go receiver methods; preserves JS/TS template literals and Rust/Go raw strings while scanning block comments; tracks prefixed and single-quoted Python docstrings.
- **#233** — caps user regex source, set source, compiled NFA, and DFA sizes; caps materialised line metadata; suppresses success short-circuits when input was truncated.

## Security and correctness notes

- ANSI sanitisation now runs on the complete bounded TOML output blob before it is split into lines. Unterminated OSC, DCS, SOS, PM, and APC strings remain in discard state through newlines and EOF.
- `CTXCRL_TOML_DEBUG` logs only a conservative executable basename. Arguments, headers, tokens, env assignments, and shell-shaped command tokens are never logged.
- `AggressiveFilter` initialises brace depth from the signature line, ignores braces in literals/comments, and removes same-line implementation bodies.
- Dynamic TOML regexes use a 16 KiB per-pattern source cap, a 64 KiB combined set cap, and 1 MiB compiled/DFA limits. Pattern text is not echoed in compilation errors.
- `smart_truncate` and TOML `apply_filter` borrow a UTF-8 boundary-safe prefix before allocation. TOML filtering also caps materialisation at 100,000 lines and appends a truncation notice.
- The `EnvOverride` trust path was audited but not changed: it requires the explicit trust flag to equal `1` and a recognised CI marker; otherwise normal hash-based trust remains in force.

## Verification

- `cargo build --lib` — pass, no warnings.
- `cargo clippy --lib` — exit 0; no warning introduced by this lane. The repository currently reports 20 pre-existing Clippy warnings in unrelated code.
- Clean-env focused suites (`umask 077`, `CONTEXTCRAWLER_TRUST_UNATTESTABLE` unset):
  - `core::filter::tests` — 26 passed.
  - `core::toml_filter::tests` — 63 passed.
  - ANSI `strip_` tests — 12 passed.
- Broad sandbox-compatible library run — 2,950 passed, 7 ignored, 0 failed.

## Residual / deferred

No filter-engine code is deferred.

The local commit could not be created because the worktree Git metadata is read-only (`index.lock: Read-only file system`). The driver should stage `src/core/utils.rs`, `src/core/filter.rs`, `src/core/toml_filter.rs`, and `SUMMARY.md`, then commit with the subject shown above. Nothing was pushed.

The exact full library command cannot complete inside this managed sandbox for reasons outside this change:

- subprocess tests abort in `wait-timeout` because its SIGCHLD handler receives `EPERM` when writing its wake-up fd;
- tee/tracking tests attempt to create recovery files, SQLite databases, or symlinks under read-only `/home/thehoff`.

Redirecting `XDG_DATA_HOME` to `/tmp` resolves the tee failures. Skipping only the sandbox-incompatible stream, tracking, and hook subprocess modules produces the green broad run reported above. The unmodified full command should be rerun in the normal repository environment.
