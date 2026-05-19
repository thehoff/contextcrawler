# Multi-Model Review — Gemini

**Reviewer**: Gemini 0.42.0 (CLI)
**Target**: `docs/contributing/REBRAND_MERGE_DRIVER_DESIGN.md` (issue #77)
**Date**: 2026-05-19

---

## Executive Summary

The design is structurally sound and addresses the primary pain point: the high friction of manual re-branding during upstream rebases. The "diff-aware" approach is a clever optimization to avoid corrupting intentionally preserved legacy strings. However, the choice of implementation language for the rule engine and the handling of line-number drift are critical risks.

---

## Part 1: Review of Open Questions (Section 10)

### Q1: Shell vs Rust for the rule application sub-script
**Recommendation: Rust.**

Bash is insufficient for this task. The `branding_lint.rs` file already demonstrates the complexity required: it uses 15+ complex regexes (like `TRACKING_LABEL_RES` and `IDENT_BINDING_RE`) to distinguish between a "leak" and a "legitimate internal identifier." Re-implementing this logic in `sed` or `awk` is a recipe for the very "silent corruption" this design seeks to avoid.

- **Rationale**: Rust allows you to share logic (or at least regex patterns) with the lint test. A standalone workspace member (e.g., `tools/rebrand-engine`) ensures type safety and robust TOML parsing.
- **Mitigation**: To avoid `cargo build` delays during a 641-commit rebase, the installer script should pre-build the binary.

### Q2: Line-number stability
**Assessment: The risk is low, but the design is slightly ambiguous.**

If a rule replaces `rtk` (3 chars) with `contextcrawler` (14 chars), the *line length* changes, but the *line number* does not. Since the driver operates on a per-line basis using a pre-computed `changed_lines.txt`, drift is only an issue if a rule adds or removes **newlines**.

- **Constraint**: You must explicitly forbid rules from introducing or removing newlines. If a rule remains 1-line-to-1-line, the pre-computed union of line numbers remains stable throughout the pass.

### Q3: Conflict-marker handling
**Recommendation: Skip blocks between `<<<<<<<` and `>>>>>>>`.**

The driver should not touch lines within conflict markers.

- **Rationale**: When a human resolves a conflict, they need to see exactly what upstream sent to understand the context. If the driver "auto-fixes" the upstream side of a conflict, it might mask the reason *why* the conflict occurred (e.g., if upstream renamed a variable that we also rebranded). Let the human resolve the structural conflict, then run the branding lint to catch residuals.

### Q4: safe_guard scope: per-rule vs global
**Recommendation: Hybrid (Global defaults + Per-rule overrides).**

The `branding_lint.rs` already identifies clear global categories: `RTK_ENVISH_RE`, `PATH_NEEDLES`, and `HOOK_PROTOCOL`.

- **Action**: Implement a `[global_safeguards]` table in `rebrand.toml`. If a line matches a global safeguard, it is skipped by default. Individual rules can then have an `ignore_global_safeguards = true` flag for rare cases where a substitution must happen even in a protected zone. This reduces TOML verbosity and prevents "rule-leak" where a new rule forgets a common safeguard.

### Q5: Driver invocation cost
**Assessment: Rebase performance is a non-issue with a compiled binary.**

A 641-commit rebase sounds daunting, but git only invokes the driver for files that actually have changes in those commits. Even if it runs 641 times, a pre-compiled Rust binary performing a few regex matches on a single file will finish in milliseconds.

- **Comparison**: The overhead of `bash` starting up and forking `diff`, `sort`, and `grep` multiple times (as shown in the script skeleton) is likely *higher* than a single optimized Rust process that handles the diffing and substitution in one go.

---

## Part 2: Independent Assessment

### 1. Diff-Aware Approach (Section 4a)
**Verdict: Sound, but requires a "Safety Valve."**

Limiting substitutions to changed lines is the correct way to respect `// branding-lint: allow legacy` markers. However, it assumes the merge driver is the *only* thing that runs.

- **Risk**: If a file has a "clean" 3-way merge but introduces a leak on a line git *didn't* mark as changed (unlikely but possible in complex renames), the driver misses it.
- **Requirement**: The `branding_lint` must remain a mandatory CI gate. The driver is a productivity tool, not a guarantee of correctness.

### 2. Single-Source-of-Truth (Section 6)
**Verdict: Strong Strategy.**

The equivalence test (`branding_lint_toml_rules_covered_by_forbidden_tokens`) is excellent. It provides the safety of codegen without the build-system fragility. It forces developers to keep the lint in sync with the driver.

### 3. Silent Corruption Risks
The design misses **Unicode/Encoding corruption**.

- **Risk**: If a file uses a non-UTF8 encoding (rare in Rust, but possible in assets), `sed` or simple Rust `String` operations might mangle it.
- **Fix**: The driver should validate that the file is valid UTF-8 before attempting substitution. If not, it should log a warning and exit 0 (leaving the file for human review).

### 4. TOML-Schema Gotchas
- **Regex Anchors**: Ensure the engine treats `needle` regexes as unanchored by default but supports standard `\b` word boundaries. Most `rtk` leaks are word-bound.
- **Capture Groups**: If `type = "regex"`, the `replacement` string should support capture group backreferences (e.g., `$1`). Without this, regex rules are significantly less powerful.

---

## Final Conclusion

Proceed with implementation, but **pivot the sub-script from Bash to Rust**. The complexity of the existing `branding_lint.rs` logic is too high to safely replicate in shell scripts. A Rust-based `branding-engine` utility will be faster, safer, and easier to maintain as the project grows.
