# branding-rebrand Merge Driver — Design Document

**Issue**: #77
**Status**: DESIGN ONLY — zero production files modified
**Author**: Daniel Hoffman
**Date**: 2026-05-19

---

## Background

Every upstream rebase from `rtk-ai/rtk` reintroduces `rtk`-branded strings in user-visible code paths. The c35339e merge (641 upstream commits) required three separate hotfix rounds in the v0.1.8→v0.1.9 cycle. Leak classes surfaced only via user reports, not CI. The `branding_lint.rs` suite is the regression gate; this driver is the auto-remediation layer that runs *before* CI sees the merged state, reducing the leak→detect→fix loop from days to zero.

**Risk posture**: silent code corruption is the primary concern. The driver must fail loud and leave files recoverable in every bad-state case. It may not silently write a corrupted file and exit 0.

---

## 1. Architecture Overview

```
git merge origin/master
        |
        v
  3-way merge (git builtin)
  %O = ancestor  %A = ours (post-merge)  %B = theirs (upstream)
        |
        | git invokes merge driver for each conflicted/merged file
        v
 scripts/branding-merge-driver.sh  %O %A %B %L %P
        |
        |-- 1. Load + validate branding/rebrand.toml
        |       on failure → exit 1 (git aborts merge, file untouched)
        |
        |-- 2. Compute changed-line set
        |       diff %O %A  →  lines added/modified by OUR commits
        |       diff %O %B  →  lines added/modified by UPSTREAM commits
        |       union        →  lines the merge touched (either side)
        |
        |-- 3. Apply substitution rules to changed lines ONLY
        |       literal rules first (ordered by rule-file position)
        |       regex rules after literals
        |       write result back to %A (in-place on working copy)
        |
        |-- 4. Exit
        |       0  → git accepts %A as merged result, continues
        |       1  → git treats file as unresolved conflict, stops merge
        |
        v
  cargo test  (branding_lint catches any residual leaks)
```

The driver is invoked by git *after* its own 3-way merge algorithm has already run. `%A` on disk is the post-merge file (possibly containing conflict markers if git could not auto-resolve). The driver's job is substitution on clean-merged lines only; it does NOT resolve conflict markers — those remain for the human. If conflict markers are present, the driver still runs substitution on the non-conflicted changed lines, then exits 0. Git will leave the file marked conflicted for the human to resolve.

---

## 2. `.gitattributes` Scope Decision

**Chosen scope** — annotate these path patterns only:

```gitattributes
# branding-rebrand merge driver
# Applied on git merge/rebase to auto-substitute known rtk→contextcrawler strings
# in newly-introduced lines.

src/**/*.rs                 merge=branding-rebrand
Cargo.toml                  merge=branding-rebrand
release-please-config.json  merge=branding-rebrand
```

**Rationale for narrow scope vs `src/**/*.rs` blanket:**

`src/**/*.rs` IS the scope. The distinction being drawn is against a true blanket `**/*.rs` that would also cover:

- `tests/branding_lint.rs` — deliberately contains forbidden tokens as data. Running substitution here would corrupt the lint test itself. SKIPPED.
- `docs/**/*.md` — no substitution needed here; docs contain attribution text and human-readable history. Free-form text substitution is higher-risk with lower return.
- `scripts/*.sh` — shell scripts have their own `rtk` references (hook filenames, binary names) that are intentionally not rebranded (see `PATH_NEEDLES` allowlist in branding_lint). Corrupting these during merge would break the hook system.
- `hooks/**/*.sh`, `hooks/**/*.md` — hook script filenames (`rtk-rewrite.sh`, `rtk-hook-gemini.sh`) are part of the filesystem protocol; they are NOT substituted.
- `Cargo.toml` and `release-please-config.json` — explicitly included because these two files have a known upstream-rebase regression (the c35339e merge silently reset `release-please-config.json`'s `package-name` back to `"rtk"`). The branding_lint test `branding_lint_config_files_pin_canonical_package_name` already pins this; the driver catches it at merge time instead of test time.

**Why not enumerate every file?** The `.gitattributes` glob is a first filter; the substitution rules in `rebrand.toml` are a second filter. A file that matches `.gitattributes` but has no changed lines that match any rule is a no-op pass-through. The cost of a false include is negligible; the cost of a false exclude is a missed auto-fix.

**Files explicitly excluded from `.gitattributes`:**

| Path | Reason |
|---|---|
| `tests/branding_lint.rs` | Contains forbidden tokens as test data |
| `scripts/*.sh` | `rtk-*` filenames are filesystem protocol, not branding |
| `hooks/**/*.sh` | Same |
| `docs/**/*.md` | Attribution text; free-form substitution too risky |
| `*.lock` | Never hand-edited; upstream changes are authoritative |
| `.github/**` | CI configs; upstream CI identifiers not our concern |

---

## 3. `branding/rebrand.toml` Schema

The file lives at `branding/rebrand.toml` in the repo root. It is the single authoritative source for substitution rules.

### Schema (annotated)

```toml
# branding/rebrand.toml
# Schema version. Increment when the rule format changes.
schema_version = 1

# Optional: global defaults applied to every rule unless overridden.
[defaults]
# If true, a rule match on a changed line applies the substitution and
# continues checking remaining rules. If false, first-match wins.
# Default: false (first-match-wins per line).
continue_on_match = false

# Rules are evaluated in file order. Each [[rule]] is one substitution.
# A rule fires only if:
#   (a) the line is in the changed-line set computed by the driver, AND
#   (b) the `needle` matches the line.
#
# Rule fields:
#   id          - unique slug, used in driver log output and TOML equivalence test
#   needle      - the string to search for (literal or regex depending on `type`)
#   replacement - the string to substitute in
#   type        - "literal" | "regex"  (default: "literal")
#   scope       - optional list of path globs; rule only fires for files matching at least one
#   reason      - human-readable description
#   issue       - upstream issue or PR reference
#   safe_guard  - optional regex; if the LINE matches safe_guard, skip this rule
#                 (used to avoid mangling identifiers that share a token with the needle)

[[rule]]
id          = "prefix-rtk-bracket"
needle      = "[rtk]"
replacement = "[contextcrawler]"
type        = "literal"
reason      = "Warning/error prefix in user-visible output"
issue       = "#23"

[[rule]]
id          = "prefix-rtk-colon"
needle      = "[rtk:"
replacement = "[contextcrawler:"
type        = "literal"
reason      = "Diagnostic prefix variant"
issue       = "#23"

[[rule]]
id          = "slim-instructions-filename"
needle      = "RTK.md"
replacement = "CONTEXTCRAWLER.md"
type        = "literal"
scope       = ["src/**/*.rs"]
reason      = "Slim instructions filename — use CONTEXTCRAWLER.md or RTK_MD constant"
issue       = "#19/#20"
safe_guard  = "RTK_MD\\b|LEGACY_RTK_MD"

[[rule]]
id          = "at-slim-instructions-ref"
needle      = "@RTK.md"
replacement = "@CONTEXTCRAWLER.md"
type        = "literal"
scope       = ["src/**/*.rs"]
reason      = "Slim instructions @-reference — use @CONTEXTCRAWLER.md or RTK_MD_REF constant"
issue       = "#19/#20"

[[rule]]
id          = "clap-savings-doc"
needle      = "RTK savings"
replacement = "ContextCrawler savings"
type        = "literal"
scope       = ["src/**/*.rs"]
reason      = "Clap doc comment leaks into --help output (branding sweep round 3)"
issue       = "#77"
```

### Notes on the example rules

The five rules above derive from `FORBIDDEN_TOKENS` history at `tests/branding_lint.rs:28-40`. They map 1:1 to known leak classes.

The `safe_guard` field on `slim-instructions-filename` is the key safety mechanism: lines containing `RTK_MD` (the constant name) or `LEGACY_RTK_MD` (the registry) contain the token `RTK.md` as a substring of an identifier, not a literal filename reference. The safe_guard regex prevents the rule from firing on those lines.

The full initial rule set should populate one entry per `FORBIDDEN_TOKENS` row — see Appendix A for the mapping table.

---

## 4. Substitution Engine Semantics

### 4a. When substitutions fire

**Decision: diff-aware (changed-line set only), not whole-file.**

Rationale: The branding_lint suite already gates whole-file correctness at `cargo test` time. The driver's exclusive responsibility is to handle lines that the merge just introduced. Applying substitutions to the entire file carries two risks:

1. It would rewrite lines that already have carefully placed `// branding-lint: allow legacy` markers (the allowlist infrastructure in branding_lint.rs). A whole-file rewrite could turn a legitimately allowlisted line into a different string that no longer needs the marker — corrupting the intent, even if the result passes lint.
2. It makes the driver's diff unauditable. A post-merge diff should show only changes the driver made to newly-introduced lines, not a sea of changes across unchanged lines.

**How the changed-line set is computed:**

```bash
# Lines added or modified by either side of the merge:
diff --unchanged-line-format="" --old-line-format="" --new-line-format="%dn\n" "$O" "$A" > /tmp/ours_changed.txt
diff --unchanged-line-format="" --old-line-format="" --new-line-format="%dn\n" "$O" "$B" > /tmp/theirs_changed.txt
# Union: any line number present in either set is a candidate for substitution.
sort -un /tmp/ours_changed.txt /tmp/theirs_changed.txt > /tmp/changed_lines.txt
```

Line numbers in the union set are the only lines written to by the substitution pass. Lines not in the set are copied verbatim from `%A`.

**Conflict marker handling:** If `%A` contains `<<<<<<<` / `=======` / `>>>>>>>` conflict markers, those lines are included in the changed-line set (they are definitely newly introduced) but the driver does NOT attempt to resolve them. It applies substitutions to them and exits 0. Git will still mark the file as conflicted because the markers remain. The human resolves the structural conflict; the driver only cleaned the strings within it.

### 4b. Order of rule evaluation

**Decision: literal rules before regex rules, file order within each tier.**

Within literals, file order in `rebrand.toml` is the evaluation sequence.
Within regex, file order is the evaluation sequence.

Rationale for literals-first:

- A literal rule is precise and O(n) via `str::contains`. It will not accidentally match an identifier that shares a token.
- A regex rule can match more broadly. Running it after literals ensures a literal rule has already had the first claim on the token. Example: `"[rtk]"` (literal) fires before a hypothetical `\[rtk[:\]]` (regex) on the same line, consuming the match before the regex sees it.

When `continue_on_match = false` (the default), the first matching rule per line wins. This means the order in `rebrand.toml` is load-bearing — document it explicitly in the file header.

### 4c. Safety: avoiding mangling of legitimate code

Three categories of `rtk`-token strings must NOT be substituted:

**1. Rust identifiers that contain `rtk` as a sub-token**

Examples: `rtk_cmd` (SQLite column name), `rtk_equivalent` (struct field), `LEGACY_RTK_MD_FILES` (registry constant), `RtkBlockUpsert` (type name).

These are internal program identifiers, not user-visible strings. Renaming them is a correctness-tier change tracked separately (branding_lint's `IDENT_TOKEN_RE` and `IDENT_BINDING_RE` already allowlist them). The driver must not touch them.

Mechanism: the `safe_guard` field on each rule is a regex that, if it matches the line, suppresses the rule for that line.

**2. Environment variable names (`RTK_*`)**

`RTK_TELEMETRY_TOKEN`, `RTK_DB_PATH` — these are programmatic interfaces. Renaming them breaks user configs and CI scripts. The driver applies a global implicit safe_guard: any rule whose needle appears on a line where `RTK_[A-Z0-9_]+` also appears does NOT fire unless the rule's `scope` explicitly opts in.

**3. Hook-protocol literals**

`[RTK:PASSTHROUGH]`, `RTK auto-rewrite`, `X-RTK-Token` — these are over-the-wire contract strings (listed in `HOOK_PROTOCOL_NEEDLES` in branding_lint). The driver treats any line containing a hook-protocol literal as a no-op for ALL rules.

**Implementation note:** These three categories are checked as pre-conditions before any rule fires on a line. They are hardcoded in the driver (not in `rebrand.toml`) because they are structural constraints, not substitution rules. Putting them in the TOML would allow an accidental TOML edit to remove them.

---

## 5. Driver Script Contract

**File**: `scripts/branding-merge-driver.sh`
**Language**: bash (no external deps beyond `diff`, `grep`, `sed`; TOML parsing is done via a small Rust helper binary if rule parsing gets complex — see Section 10 open question)

### Argv

Git invokes the driver as:

```
branding-merge-driver.sh %O %A %B %L %P
```

| Position | Git placeholder | Value |
|---|---|---|
| `$1` | `%O` | Ancestor (common base) temp file path |
| `$2` | `%A` | Current version (ours + auto-merged result) — **the file to write back** |
| `$3` | `%B` | Other version (upstream/theirs) |
| `$4` | `%L` | Conflict marker label length (passed to merge tools; driver can ignore) |
| `$5` | `%P` | Path of the file being merged, relative to repo root |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Merge resolved. Git accepts `%A` as the merged result. File may still have conflict markers — git's conflict-detection looks at markers, not exit code. |
| `1` | Merge failed. Git stops and reports the file as unresolved. `%A` is left unchanged from git's auto-merge attempt. |

**The driver MUST NOT exit 0 if it has partially written `%A`.**

If the driver writes partial output and then hits an error, it must restore the original `%A` from a temp backup before exiting. This is non-negotiable given the silent-corruption risk.

### Stdout / stderr policy

- **stdout**: nothing. Git captures stdout from merge drivers and it interferes with git's own output. Use `>&2` for all logging.
- **stderr**: structured log lines prefixed `[branding-rebrand]`. Format: `[branding-rebrand] <level>: <message>`. Levels: `INFO`, `WARN`, `ERROR`.

Examples:
```
[branding-rebrand] INFO: loaded 12 rules from branding/rebrand.toml
[branding-rebrand] INFO: src/hooks/init.rs — 3 changed lines, 1 substitution applied (rule: prefix-rtk-bracket)
[branding-rebrand] WARN: src/hooks/init.rs:47 — rule slim-instructions-filename skipped (safe_guard matched)
[branding-rebrand] ERROR: branding/rebrand.toml — parse failed: schema_version missing
```

### TOML load failure behaviour

If `branding/rebrand.toml` is absent or malformed:

- Log to stderr: `[branding-rebrand] ERROR: could not load branding/rebrand.toml — <reason>`
- **Exit 1** — do NOT proceed with zero rules (which would silently be a no-op pass-through).

Rationale: a missing/malformed TOML is either an environment setup error (fresh clone that hasn't run install) or a TOML edit gone wrong. In both cases, the correct outcome is a loud failure that stops the merge so the human can investigate. A silent no-op pass-through would mean the merge completes with unbranded strings, which defeats the whole system.

The TOML path is resolved relative to the git repo root, not the CWD. The driver locates the repo root via `git rev-parse --show-toplevel`.

### Script skeleton

```bash
#!/usr/bin/env bash
# scripts/branding-merge-driver.sh
# Git merge driver for contextcrawler branding substitutions.
# Invoked by git as: branding-merge-driver.sh %O %A %B %L %P
# See docs/contributing/REBRAND_MERGE_DRIVER_DESIGN.md for full spec.

set -euo pipefail

O="$1"  # ancestor
A="$2"  # ours (write result here)
B="$3"  # theirs
# $4 = label length (unused)
P="$5"  # file path relative to repo root

REPO_ROOT="$(git rev-parse --show-toplevel)"
TOML="${REPO_ROOT}/branding/rebrand.toml"
LOG_PREFIX="[branding-rebrand]"

log_info()  { echo "${LOG_PREFIX} INFO: $*" >&2; }
log_warn()  { echo "${LOG_PREFIX} WARN: $*" >&2; }
log_error() { echo "${LOG_PREFIX} ERROR: $*" >&2; }

# Backup %A before any writes.
A_BACKUP="$(mktemp)"
cp "$A" "$A_BACKUP"

cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "driver exiting with code $exit_code — restoring %A from backup"
        cp "$A_BACKUP" "$A"
    fi
    rm -f "$A_BACKUP" /tmp/branding_ours_changed.$$ /tmp/branding_theirs_changed.$$ /tmp/branding_changed.$$
}
trap cleanup EXIT

# 1. Validate TOML exists and has expected schema_version.
if [[ ! -f "$TOML" ]]; then
    log_error "branding/rebrand.toml not found at $TOML — run scripts/install-merge-driver.sh"
    exit 1
fi
schema=$(grep -m1 '^schema_version' "$TOML" | grep -oP '\d+' || true)
if [[ "$schema" != "1" ]]; then
    log_error "branding/rebrand.toml schema_version not 1 (got: '${schema}') — update driver or TOML"
    exit 1
fi

# 2. Compute changed-line set (union of both sides).
diff --unchanged-line-format="" --old-line-format="" --new-line-format="%dn\n" \
    "$O" "$A" > /tmp/branding_ours_changed.$$ 2>/dev/null || true
diff --unchanged-line-format="" --old-line-format="" --new-line-format="%dn\n" \
    "$O" "$B" > /tmp/branding_theirs_changed.$$ 2>/dev/null || true
sort -un /tmp/branding_ours_changed.$$ /tmp/branding_theirs_changed.$$ \
    > /tmp/branding_changed.$$ 2>/dev/null || true

changed_count=$(wc -l < /tmp/branding_changed.$$ | tr -d ' ')
log_info "${P} — ${changed_count} changed lines identified"

# 3. Apply substitutions (delegated to helper or inline awk/sed).
#    The actual substitution logic is in a separate helper so it can be
#    tested in isolation. See Section 10 open question on Rust vs shell helper.
"${REPO_ROOT}/scripts/branding-apply-rules.sh" \
    "$A" "$TOML" /tmp/branding_changed.$$ "$P" \
    || { log_error "branding-apply-rules.sh failed"; exit 1; }

log_info "${P} — substitution pass complete"
exit 0
```

The `branding-apply-rules.sh` sub-script handles the per-line rule application. Splitting it out allows unit testing the rule engine independently of the git plumbing.

---

## 6. Single Source of Truth Strategy

**Decision: Option (c) — `cargo test` asserts equivalence. `branding/rebrand.toml` is the authoritative source; a test validates that `FORBIDDEN_TOKENS` in `branding_lint.rs` covers every rule id in the TOML.**

### Why not (a) — codegen?

Generating `branding_lint.rs::FORBIDDEN_TOKENS` from `rebrand.toml` at test time requires a build script or proc-macro. This adds complexity to a test file that is already the regression backstop. If the build script has a bug, the lint test silently has fewer entries. Risk is unacceptable.

### Why not (b) — shared file both read?

The lint test is pure Rust, compiled by cargo. Reading a TOML file at test time is possible (`include_str!` or `fs::read_to_string`) but requires parsing TOML in the test harness to extract needle strings. The substitution rule format and the lint needle format are not identical — a needle in `FORBIDDEN_TOKENS` is a literal string to `contains`-check; a rule in `rebrand.toml` can be a regex with a safe_guard. Mapping between them requires non-trivial logic that is itself a source of bugs.

### The chosen approach: equivalence assertion

Add one new test to `tests/branding_lint.rs`:

```rust
#[test]
fn branding_lint_toml_rules_covered_by_forbidden_tokens() {
    // Every literal substitution rule in branding/rebrand.toml that has
    // type = "literal" MUST have its `needle` present in FORBIDDEN_TOKENS.
    // This ensures the lint backstop covers everything the driver would auto-fix.
    //
    // Regex rules are excluded: they cover pattern classes, not specific literals,
    // so they cannot be 1:1 mapped to FORBIDDEN_TOKENS entries.
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let toml_path = repo_root.join("branding/rebrand.toml");
    let toml_str = fs::read_to_string(&toml_path)
        .expect("branding/rebrand.toml must exist — run scripts/install-merge-driver.sh");
    let toml_doc: toml::Value = toml::from_str(&toml_str)
        .expect("branding/rebrand.toml must be valid TOML");

    let rules = toml_doc.get("rule")
        .and_then(|v| v.as_array())
        .expect("rebrand.toml must have at least one [[rule]]");

    let mut uncovered: Vec<String> = Vec::new();
    for rule in rules {
        let rule_type = rule.get("type").and_then(|v| v.as_str()).unwrap_or("literal");
        if rule_type != "literal" {
            continue; // regex rules not checked here
        }
        let needle = rule.get("needle")
            .and_then(|v| v.as_str())
            .expect("each [[rule]] must have a needle field");
        let id = rule.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("<no-id>");
        let covered = FORBIDDEN_TOKENS.iter().any(|(ft, _)| *ft == needle);
        if !covered {
            uncovered.push(format!("  rule id={} needle={:?} not in FORBIDDEN_TOKENS", id, needle));
        }
    }

    if !uncovered.is_empty() {
        panic!(
            "\n\n--- branding TOML ↔ FORBIDDEN_TOKENS drift ---\n\
             The following rules in branding/rebrand.toml are NOT covered by\n\
             FORBIDDEN_TOKENS in tests/branding_lint.rs:\n\n{}\n\n\
             FIX: add the needle to FORBIDDEN_TOKENS so the lint backstop covers\n\
             what the merge driver auto-fixes.\n",
            uncovered.join("\n")
        );
    }
}
```

**Enforcement direction**: TOML rules → FORBIDDEN_TOKENS (TOML is authoritative, lint must keep up). When a new rule is added to the TOML, this test fails until the corresponding entry is added to FORBIDDEN_TOKENS. The reverse is NOT enforced: FORBIDDEN_TOKENS may have entries that are not in the TOML (they represent known leaks that the driver does not auto-fix, perhaps because they require human judgement).

---

## 7. Failure Modes

### F1. Driver crashes mid-merge (partial write to `%A`)

**Symptom**: git merge stops with an error; `%A` is potentially corrupt.

**Prevention**: The `cleanup()` trap in the driver (Section 5) restores `%A` from `$A_BACKUP` on any non-zero exit. This is the primary guard.

**Recovery**: If the trap somehow fails (signal kill, disk full during backup restore):
```bash
git merge --abort
# or, if mid-rebase:
git rebase --abort
# Then check git status for any modified files and restore from:
git checkout HEAD -- <path>
```

The backup file is in `/tmp` and may have been cleaned; `git checkout HEAD` is always available.

### F2. TOML is malformed

**Symptom**: driver exits 1, merge stops. No file has been written. Git reports the file as unresolved.

**Recovery**: Fix `branding/rebrand.toml`, validate with `cargo test branding_lint_toml_rules_covered_by_forbidden_tokens` (which will catch malformed TOML via the `toml::from_str` call), then re-run the merge.

**Detection**: Run `scripts/validate-branding-toml.sh` (a simple schema check, ~20 lines) before any merge. Add it to the pre-push hook installed by `scripts/install-merge-driver.sh`.

### F3. Substitution conflicts with itself (rule A produces output that matches rule B)

The dangerous variant: rule A replaces `"rtk"` → `"contextcrawler"`, rule B replaces `"contextcrawler"` → `"contextcrawler2"` (hypothetical). This produces a double-substitution.

**Prevention**: The rule format does not allow cyclic replacements because:
1. Substitutions are applied to the original line text, NOT to the running output of previous rules. Each rule reads the line as it entered the substitution pass.
2. Exception: if `continue_on_match = true` is set (not the default), rules ARE chained. With the default `continue_on_match = false`, first-match-wins and subsequent rules see the same original text.

**Detection**: The equivalence test in Section 6 can extend to detect rules whose replacement string matches another rule's needle — add a static cross-rule check.

### F4. Driver is not installed (fresh clone)

**Symptom**: git merge proceeds WITHOUT the driver; `branding-rebrand` is set in `.gitattributes` but git cannot find the driver in config.

**Detection**: git silently falls back to its built-in merge. No error. The merge succeeds but no substitutions are applied.

**Mitigation**:
1. `scripts/install-merge-driver.sh` sets the git config entry. CI must run this before merge operations.
2. Add a pre-merge hook that checks `git config merge.branding-rebrand.driver` is set.
3. The `cargo test` suite still catches leaks — the driver is defence-in-depth, not the last gate.

### F5. Driver produces wrong output (substitution correct but changes semantic meaning)

Example: a changed line contains `"rtk_cmd"` as a Rust field name AND `"[rtk]"` as a string literal on the same line. A safe_guard on the literal rule might be too broad and skip the line entirely, missing the `[rtk]` substitution.

**Detection**: `cargo test` — `branding_lint_no_forbidden_upstream_literals_in_src` catches any `[rtk]` that survived into `src/`.

**Recovery**: add the `// branding-lint: allow legacy` marker if the residual is intentional, or fix the safe_guard regex in `rebrand.toml` if it was too broad.

---

## 8. Rollout Plan

### Install instructions for fresh clones

`scripts/install-merge-driver.sh`:

```bash
#!/usr/bin/env bash
# Install the branding-rebrand git merge driver for this repo.
# Run once after cloning or when the driver is updated.
# Safe to re-run: idempotent.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Register the driver in local git config (not --global; repo-scoped).
git config merge.branding-rebrand.name "ContextCrawler branding substitution driver"
git config merge.branding-rebrand.driver \
    "scripts/branding-merge-driver.sh %O %A %B %L %P"

echo "[install-merge-driver] git merge driver registered."
echo "[install-merge-driver] Driver: scripts/branding-merge-driver.sh"
echo "[install-merge-driver] Config: $(git config merge.branding-rebrand.driver)"
echo ""
echo "Verify with: git config --list | grep branding"
echo "Test with:   cargo test branding_lint_toml_rules_covered_by_forbidden_tokens"
```

### CI verification

Add to the CI workflow (`.github/workflows/ci.yml`) before any merge/rebase steps:

```yaml
- name: Install branding merge driver
  run: bash scripts/install-merge-driver.sh

- name: Validate branding TOML
  run: |
    # Fail fast if rebrand.toml is malformed before any merge runs.
    cargo test branding_lint_toml_rules_covered_by_forbidden_tokens

- name: Branding lint (post-merge gate)
  run: cargo test --test branding_lint
```

### Update to `UPSTREAM_REBASE.md`

Add to the "Re-verification checklist after any rebase" table:

```markdown
| Branding driver installed | `git config merge.branding-rebrand.driver` — must not be empty |
| TOML equivalence | `cargo test branding_lint_toml_rules_covered_by_forbidden_tokens` |
```

Add to the "Heavy" rebase workflow, after `git merge origin/master`:

> The branding-rebrand merge driver runs automatically during the merge for all
> `src/**/*.rs`, `Cargo.toml`, and `release-please-config.json` files. Check
> the merge output for `[branding-rebrand]` log lines. If the driver exited 1
> on any file, fix `branding/rebrand.toml` before continuing.

### File creation sequence for implementation

In implementation order:

1. `branding/rebrand.toml` — create with schema_version, initial rules from FORBIDDEN_TOKENS
2. `scripts/branding-merge-driver.sh` — main driver (Section 5 skeleton)
3. `scripts/branding-apply-rules.sh` — rule application sub-script
4. `scripts/install-merge-driver.sh` — installer
5. `.gitattributes` — add the three merge=branding-rebrand lines
6. `tests/branding_lint.rs` — add `branding_lint_toml_rules_covered_by_forbidden_tokens` test
7. `docs/contributing/UPSTREAM_REBASE.md` — add checklist entries
8. `.github/workflows/ci.yml` — add install + validate steps

---

## 9. Dry-Run Validation

The design should be verified against c35339e (the last heavy upstream merge) before implementation begins.

### Extract the conflict surface from c35339e

```bash
# List every file that was touched by the c35339e merge:
git diff-tree --no-commit-id -r --name-only c35339e

# For each .rs file in that list, extract lines that were added by the merge:
git diff c35339e^1 c35339e -- src/hooks/init.rs | grep '^+' | grep -v '^+++' | head -50
```

### Fixture extraction for driver testing

```bash
# Extract ancestor (%O), ours (%A pre-merge), and upstream (%B) for a specific file:
git show c35339e^1:src/hooks/init.rs > /tmp/dry_run/init_ancestor.rs
git show c35339e^2:src/hooks/init.rs > /tmp/dry_run/init_upstream.rs
git show c35339e:src/hooks/init.rs   > /tmp/dry_run/init_merged.rs

# Simulate what the driver would receive and produce:
bash scripts/branding-merge-driver.sh \
    /tmp/dry_run/init_ancestor.rs \
    /tmp/dry_run/init_merged.rs \
    /tmp/dry_run/init_upstream.rs \
    7 \
    src/hooks/init.rs

# Diff the result against the manually-fixed version we shipped:
diff /tmp/dry_run/init_merged.rs <(git show HEAD:src/hooks/init.rs)
```

### Pass criteria for dry-run

The dry-run passes if:

1. The driver exits 0 for all files touched by c35339e
2. `cargo test --test branding_lint` passes on the driver-substituted output
3. The diff between driver output and the manually-fixed shipped version shows only driver-applied substitutions — no content the driver changed that the human didn't also change, and vice versa (no substitution the human made that the driver missed)

Any delta between driver output and the shipped fix identifies either:
- A rule that needs to be added to `rebrand.toml` (driver missed a substitution), or
- A safe_guard that is too narrow (driver applied a substitution the human left alone as intentional)

### Specific files to target in dry-run (highest signal)

1. `src/hooks/init.rs` — init messages, hook install strings (most historically leaky file)
2. `src/hooks/constants.rs` — hook command strings
3. `src/cmds/git/git.rs` — diff truncation hints, clap doc comments
4. `src/analytics/gain.rs` — report headlines
5. `Cargo.toml` — package name
6. `release-please-config.json` — package-name field (known c35339e regression)

---

## 10. Open Questions for Multi-Model Review

These are unresolved design questions that should be put to Claude + Codex + Gemini before implementation begins, because they each carry meaningful implementation risk.

**Q1: Shell vs Rust for the rule application sub-script**

The design sketches `scripts/branding-apply-rules.sh`. Parsing TOML and applying rules in bash is doable (grep/awk for TOML extraction, sed for substitution) but fragile. An alternative is a small Rust binary `branding/apply-rules/src/main.rs` (not part of the contextcrawler crate; a standalone workspace member) that reads `rebrand.toml` with the `toml` crate, applies rules with the `regex` crate, and writes the output. This is more robust but requires `cargo build` to be available at merge time. Question: is adding a cargo build step to the merge driver acceptable for this repo's CI topology? If the Rust binary is pre-built and committed, what is the binary-in-repo policy?

**Q2: Line-number stability when diff counts change**

The changed-line-set computation uses `diff --new-line-format="%dn\n"` to get line numbers in `%A`. If an earlier rule substitution changes the line count of `%A` (which it won't with literal substitution since replacements are same-length, but could with regex), the line numbers computed from the original `%A` drift. Is a second diff pass needed after each rule application, or does the design guarantee substitutions are length-preserving (and if so, how)?

**Q3: Conflict marker lines in the changed-line set**

The design says conflict-marker lines (`<<<<<<<`, `=======`, `>>>>>>>`) are included in the changed-line set and the driver applies substitutions to them. Is this correct? A conflict marker line like `<<<<<<< HEAD` contains no branding tokens, so in practice substitution is a no-op. But if upstream introduced a conflict on a line that contains `[rtk]`, the driver would substitute inside the conflict block. Is that safe — or should the driver skip all lines inside conflict blocks and let the human resolve them clean?

**Q4: Safe_guard regex scope — per-rule or per-line global**

The design has `safe_guard` as a per-rule field. An alternative is a global `[[safe_guard]]` table in the TOML that applies to ALL rules: if a line matches any global safe_guard, no rules fire on it. The global approach is simpler to reason about (one gate, not N) but may be too broad for some rules. The per-rule approach allows fine-grained control but is more verbose. Which approach better fits the actual safe_guard patterns needed (RTK_ENVISH, IDENT_TOKEN, HOOK_PROTOCOL)?

**Q5: Driver invocation during `git rebase` vs `git merge`**

The runbook in UPSTREAM_REBASE.md uses both `git rebase origin/develop` (light-touch) and `git merge origin/master` (heavy). Git invokes merge drivers during both operations — but the three-way merge semantics differ between rebase (each commit replayed) and merge (single merge commit). During rebase, the driver is invoked once per commit that touches a branding-annotated file. For a 641-commit rebase this could be 641 invocations with micro-diffs. Is this acceptable performance-wise, or should the driver detect it is running inside a rebase and behave differently (e.g. batch at the end)?

---

## Appendix A: Rule Mapping — FORBIDDEN_TOKENS → Initial rebrand.toml

| FORBIDDEN_TOKENS entry | Proposed rule id | Auto-fixable? |
|---|---|---|
| `[rtk]` | `prefix-rtk-bracket` | Yes |
| `[rtk:` | `prefix-rtk-colon` | Yes |
| `RTK.md` | `slim-instructions-filename` | Yes, with safe_guard |
| `@RTK.md` | `at-slim-instructions-ref` | Yes |
| `rtk instructions` | `rtk-instructions-phrase` | Yes |
| `"rtk: ` | `error-prefix-rtk` | Yes |
| `rtk telemetry` | `rtk-telemetry-cmd` | Yes |
| `RTK savings` | `clap-savings-doc` | Yes |
| `RTK adoption` | `clap-adoption-doc` | Yes |
| `RTK equivalent` | `clap-equivalent-doc` | Yes |
| `RTK artifacts` | `clap-artifacts-doc` | Yes |
| `RTK and native` | `clap-and-native-doc` | Yes |
| `(rtk)` | `inline-attribution-rtk` | Yes, with safe_guard (avoid `$(rtk`) |
| `$(rtk ` | `shell-example-rtk-prefix` | Yes |
| `` `rtk rewrite`` | `cli-example-rtk-rewrite` | Yes |
| `rtk find:` | `find-filter-error-prefix` | Yes |

All 16 entries are auto-fixable via literal substitution. None require regex for initial rollout. Start with literals only; add regex rules only when a TOML-confirmed use-case emerges.

---

*End of design document. Next step: multi-model review of the 5 open questions, then implementation.*
