# branding-rebrand Merge Driver — Decisions (post multi-model review)

**Issue**: #77
**Source design**: `REBRAND_MERGE_DRIVER_DESIGN.md`
**Reviews**:
- `REBRAND_MERGE_DRIVER_REVIEW_CODEX.md` (Codex/GPT-5)
- `REBRAND_MERGE_DRIVER_REVIEW_GEMINI.md` (Gemini 0.42.0)
- This consolidation by Claude Opus 4.7

**Status**: Ready for implementation pending Hoff approval

---

## Open-question resolutions

### Q1: Shell vs Rust for the rule application sub-script — **RUST** ✅

Strong cross-model consensus (Codex + Gemini both Rust).

- **Decision**: Implement as a standalone Rust workspace member, e.g. `tools/branding-engine/`, with its own `Cargo.toml` and `src/main.rs`.
- **Why**: The existing `tests/branding_lint.rs` already runs 15+ complex regexes (`TRACKING_LABEL_RES`, `IDENT_BINDING_RE`, etc.) to distinguish leaks from identifiers. Replicating that discipline in bash/sed is the silent-corruption path the design is explicitly trying to avoid. Rust gets us `toml` crate parsing, `regex` crate engine, and the option to share patterns with the lint test.
- **Hot-path constraint**: `cargo build` does NOT happen at merge time. `scripts/install-merge-driver.sh` builds the binary once and writes the path into git config. CI builds it in a setup step.
- **Binary location**: `target/release/branding-engine` (gitignored). The git config `merge.branding-rebrand.driver` setting points at the workspace path; `scripts/branding-merge-driver.sh` becomes a thin wrapper that locates the binary, errors loud if missing, and execs it.

### Q2: Line-number stability — **FORBID NEWLINE-CHANGING RULES** ✅

Both reviewers agree. Codex flagged the deeper bug (Section "Diff-Aware Approach" below).

- **Decision**: At TOML load time, validate that every `needle` and `replacement`:
  - Contains no `\n` character
  - For regex rules: does not include `\n`, `(?m)`, or any pattern that could span lines
- **Decision**: The TOML loader rejects any rule that fails validation, with a clear error pointing at the rule `id`.
- **Why**: With this constraint, the changed-line set computed at the start of the substitution pass remains valid for the entire pass. Length-changing within a line is fine; line-count changes are forbidden.

### Q3: Conflict-marker handling — **SKIP BLOCKS** ✅

Both reviewers explicitly disagreed with the design's original "substitute inside markers" stance. Codex framed it well: "too clever for a merge driver whose top risk is silent corruption."

- **Decision**: The driver MUST NOT touch any line inside a `<<<<<<<` / `=======` / `>>>>>>>` block. Mark these lines as "no-touch" before the substitution pass starts.
- **Decision**: The conflict markers themselves are also not touched.
- **Why**: When a human resolves a conflict, they need upstream's text verbatim to understand WHY the conflict occurred. The driver rewriting inside conflict blocks would mask intent (e.g., if upstream renamed a variable AND we also rebranded the line, the conflict surfaces a real design question — we shouldn't auto-resolve it). The `branding_lint` CI gate catches any residual once the human resolves.

### Q4: safe_guard scope — **PER-RULE TOML + HARDCODED GLOBAL CLASSES** ✅

Codex and Gemini split here:
- **Gemini**: hybrid (global defaults + per-rule overrides)
- **Codex**: per-rule TOML + hardcoded global classes (matches current design)

**Decision: Codex.** Reasoning:

- The three "global" categories (env-var-shape `RTK_*`, hook-protocol literals, identifier-shaped tokens) are STRUCTURAL invariants. They're not substitution rules — they're "this line is never a branding leak." Putting them in user-editable TOML invites accidental removal (the TOML is the authoritative source for substitutions, so it gets edited often).
- The existing `tests/branding_lint.rs` mirrors this split: narrow allowlists for specific shapes, NOT one coarse "if line matches X, skip everything." That structure works well.
- Per-rule `safe_guard` retains fine-grained control where it's needed (e.g. `slim-instructions-filename` needs `RTK_MD\b|LEGACY_RTK_MD` specifically).

Concession to Gemini's verbosity concern: document the three hardcoded classes prominently in the rule-engine source so future contributors see them when reading code.

### Q5: Driver invocation cost during git rebase — **DON'T SPECIAL-CASE** ✅

Both reviewers agree: with a compiled Rust binary, per-commit replay is in the milliseconds range.

- **Decision**: No rebase-vs-merge detection. The driver runs identically for both. Per-invocation cost is the entire optimization target.
- **Decision**: Keep the driver stateless and O(changed lines). Pre-parse the TOML at process start (typically <5ms), then process the single file.
- **Acceptance criterion**: dry-run measurement on a 10-file rebase should show <500ms total driver wall-time. Failure of this target is a re-design trigger.

---

## Critical fixes (raised in review, not in original design)

### Fix A — Diff-aware coordinate-system bug (Codex)

The design's Section 4a unions line numbers from `diff %O→%A` and `diff %O→%B`, but those are TWO DIFFERENT COORDINATE SYSTEMS. The `%B` line numbers don't map to `%A` without an explicit mapping pass.

**Fix**: Derive the target line-number set from `%A` only:
```bash
# Compute "lines in %A that are different from %O" — these are the lines the merge introduced into the working copy.
diff --unchanged-line-format="" --old-line-format="" --new-line-format="%dn\n" "$O" "$A"
```

This is the only line-number source the driver needs. The `%B` diff is informational only (useful for logging "this changed line came from upstream"), not for substitution targeting.

**Why this matters**: the original union would have caused the driver to either skip lines that should be substituted, or attempt to substitute on phantom line numbers that don't exist in `%A` — both silent-corruption failure modes.

### Fix B — Atomic write in the rule engine (Codex)

Section 5's cleanup-on-non-zero-exit restores `%A` from backup, but only if the driver process exits non-zero. A successful exit after a partially-corrupted in-place rewrite is silent corruption.

**Fix**: The Rust rule engine writes to `%A.tmp` and only `rename(%A.tmp, %A)` after all rules apply cleanly. Any error mid-pass deletes `%A.tmp` and exits 1; the outer `trap cleanup EXIT` then restores `%A` from backup.

### Fix C — UTF-8 validation (Gemini)

The design assumes UTF-8 throughout but never validates.

**Fix**: At process start, attempt to read `%A` as UTF-8. If invalid:
- Log: `[branding-rebrand] WARN: <path> — not valid UTF-8; leaving file untouched for human review`
- Exit 0 (file unchanged, branding_lint will catch it post-merge)

This is rare in practice (Rust source is always UTF-8) but the failure mode is silent and bad, so the check is worth the 1-line of code.

### Fix D — TOML schema tightening (Codex)

The schema doesn't define:
- Whether duplicate `id` values are illegal → **make them illegal**
- Whether two rules can share an identical literal `needle` in the same scope → **make them illegal**
- The exact regex dialect for `safe_guard` and `type = "regex"` rules → **document as Rust `regex` crate syntax (no lookaround, no backreferences in needle; `$N` for capture groups in replacement per Gemini's note)**
- Whether `needle`/`replacement` may contain newlines → **NO (per Q2)**

**Fix**: TOML loader rejects on any of these conditions with an `id`-referenced error message.

### Fix E — Single-source-of-truth asymmetry (Codex)

The current design lets `FORBIDDEN_TOKENS` drift downward freely — entries can sit there without TOML coverage. That makes it hard to know which `FORBIDDEN_TOKENS` rows are driver-managed vs lint-only.

**Fix**: Add a `// driver-managed` marker comment convention in `FORBIDDEN_TOKENS`:
```rust
const FORBIDDEN_TOKENS: &[(&str, &str)] = &[
    // driver-managed (rebrand.toml rule: prefix-rtk-bracket)
    ("[rtk]", "warning/error prefix — use \"[contextcrawler]\" (issue #23)"),
    // lint-only — no TOML rule; surfaces require human judgement
    ("\"rtk: ", "error prefix in unstructured stderr — use \"contextcrawler: \" (post-v0.1.8 user report)"),
    ...
];
```

Then the equivalence test asserts:
- Every `driver-managed` row maps to a TOML rule with matching needle ✓ (existing)
- Every TOML literal rule has a matching `driver-managed` row in FORBIDDEN_TOKENS ✓ (new)
- `lint-only` rows are not asserted (escape hatch for residual human-judgement cases)

---

## Implementation order (revised)

1. **`tools/branding-engine/`** — standalone Rust workspace member
   - `Cargo.toml` with `toml`, `regex`, `clap` (for argv parsing)
   - `src/main.rs` implementing: TOML load + validation, UTF-8 check, conflict-block scan, diff-aware changed-line computation, rule application with safe_guards, atomic temp-file write
   - Unit tests on the rule engine
2. **`branding/rebrand.toml`** — initial rule set (16 entries from FORBIDDEN_TOKENS)
3. **`scripts/branding-merge-driver.sh`** — thin wrapper: locate binary, exec it, surface stderr
4. **`scripts/install-merge-driver.sh`** — builds the binary (release mode), writes git config
5. **`.gitattributes`** — three `merge=branding-rebrand` lines
6. **`tests/branding_lint.rs`** — new test `branding_lint_toml_rules_covered_by_forbidden_tokens` with bidirectional assertion (per Fix E)
7. **`docs/contributing/UPSTREAM_REBASE.md`** — flow update + recovery section
8. **`.github/workflows/ci.yml`** — build engine + install driver + validate TOML

---

## Risks remaining after these decisions

| Risk | Mitigation | Residual |
|---|---|---|
| Rust binary not built before first merge (fresh clone) | `install-merge-driver.sh` does the build; CI runs install before any merge step | Low |
| TOML edit introduces invalid regex / duplicate rule | TOML loader rejects with clear error; equivalence test re-runs in CI | Low |
| Driver corrupts a line that `branding_lint` doesn't catch | Diff-aware + safe_guards keep substitution surface narrow; lint is backstop | Medium — accept |
| Upstream introduces a NEW leak class the TOML doesn't cover | `branding_lint` allowlist-style scan from #67 catches it; manual fix + TOML update | Medium — accept |
| Performance regression on rebase (e.g. accidental O(n²) in rule pass) | Acceptance criterion: <500ms wall-time for 10-file rebase | Low |

---

*Decisions doc complete. Implementation can begin per the order above. Approval requested before any code lands on `develop`.*
