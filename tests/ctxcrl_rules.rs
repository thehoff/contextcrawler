//! ctxcrlRules enforcement — the machine-checkable subset of `docs/rules/RULES.md`.
//!
//! Modelled on `tests/branding_lint.rs`: a tracked test that scans real source
//! and fails with a pointer back to the rule it broke. Rules that cannot be
//! checked by a machine live in the same document as REVIEW items and are
//! enforced by the pre-merge checklist, not here.
//!
//! When a rule's shape changes, update the table in this file — that is the
//! single place the check is defined.

use std::fs;
use walkdir::WalkDir;

/// Marker that opts a line out of a lint, mirroring `// branding-lint: allow legacy`.
const ALLOW_MARKER: &str = "ctxcrl-rules: allow";

fn rust_sources_under(dir: &str) -> Vec<(String, String)> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
        .filter_map(|e| {
            let path = e.path().display().to_string();
            fs::read_to_string(e.path()).ok().map(|body| (path, body))
        })
        .collect()
}

/// Extract a function body by brace matching from its signature line.
fn function_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let open = start + source[start..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in source[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[open..open + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// CTX-001 — a recovery hint that names a path must shell-quote it.
// ─────────────────────────────────────────────────────────────────────────────

/// Functions that render a *runnable command* back to the agent, and therefore
/// must shell-quote any path they embed.
///
/// Origin: #236 round-2. `render_stub` emitted
/// `contextcrawler read /a/dir with spaces/f.rs --force` — a hint the agent
/// cannot run. The recovery hint is the entire safety net for a feature that
/// withholds content, so an unrunnable hint converts a deferral into a
/// withhold. Found by mmax; codex passed the same diff.
///
/// Add new hint-emitting functions here as they appear.
const HINT_EMITTERS: &[(&str, &str, &str)] = &[
    (
        "src/cmds/system/read_cache.rs",
        "pub fn render_stub(",
        "CTX-001: the repeat-read stub advertises `contextcrawler read <path> --force`",
    ),
    (
        "src/cmds/system/read.rs",
        "fn apply_unknown_extension_cap(",
        "CTX-001: the large-file cap advertises `contextcrawler proxy cat <path>`",
    ),
];

/// Quoting calls that satisfy CTX-001.
const QUOTING_CALLS: &[&str] = &["shlex::try_quote", "shlex::quote", "shell_escape::escape"];

#[test]
fn ctx_001_recovery_hints_shell_quote_their_paths() {
    let mut failures = Vec::new();
    for (file, signature, why) in HINT_EMITTERS {
        let source = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{file}: cannot read ({e}) — did the file move?"));
                continue;
            }
        };
        let Some(body) = function_body(&source, signature) else {
            failures.push(format!(
                "{file}: `{signature}` not found — if it was renamed, update HINT_EMITTERS in tests/ctxcrl_rules.rs"
            ));
            continue;
        };
        if !QUOTING_CALLS.iter().any(|q| body.contains(q)) {
            failures.push(format!(
                "{file} :: {signature}\n    {why}\n    but the body calls none of {QUOTING_CALLS:?}.\n    \
                 An unrunnable recovery hint turns a deferral into a withhold."
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "CTX-001 violated (see docs/rules/RULES.md):\n\n{}\n",
        failures.join("\n\n")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CTX-004 — test fixtures must not inherit the ambient umask.
// ─────────────────────────────────────────────────────────────────────────────

/// Origin: #237. `TempDir::new()` and `fs::write` inherit the umask, so on a
/// umask-002 machine fixtures land at 0775/0664 and the integrity checks
/// correctly refuse to trust them. 21 tests failed for every contributor whose
/// umask was not 022 — including on the maintainer's own machine, for months.
///
/// The hooks suites must go through `private_tempdir()`, which forces a private
/// mode and normalises the process umask.
/// Suites whose *product code* validates fixture permissions. Fixtures here
/// must not inherit the umask. Add a file when its product path starts
/// mode-checking; the lint is deliberately scoped rather than repo-wide, so a
/// cache-TTL test in an unrelated suite does not need an exemption comment.
const MODE_SENSITIVE_SUITES: &[&str] = &["src/hooks/integrity.rs", "src/hooks/init.rs"];

#[test]
fn ctx_004_hook_test_fixtures_do_not_inherit_the_umask() {
    let mut failures = Vec::new();
    for (path, body) in rust_sources_under("src/hooks")
        .into_iter()
        .filter(|(p, _)| {
            MODE_SENSITIVE_SUITES
                .iter()
                .any(|s| p.replace('\\', "/").ends_with(s))
        })
    {
        for (n, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            // Prose about the rule is not a violation of it.
            let is_comment =
                trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("!");
            if !line.contains("TempDir::new()") || is_comment {
                continue;
            }
            // The helper itself is the one legitimate constructor.
            let is_helper_definition = body
                .lines()
                .nth(n.saturating_sub(1))
                .is_some_and(|prev| prev.contains("fn private_tempdir()"))
                || line.contains("let dir = TempDir::new().expect(\"create temp dir\")");
            // The marker may sit on the line itself or in the comment block
            // immediately above it, where there is room to give a reason.
            let lines: Vec<&str> = body.lines().collect();
            let allowed = line.contains(ALLOW_MARKER)
                || lines[n.saturating_sub(3)..n]
                    .iter()
                    .any(|l| l.contains(ALLOW_MARKER));
            if is_helper_definition || allowed {
                continue;
            }
            failures.push(format!(
                "{}:{}: {}\n    CTX-004: use `private_tempdir()` — a bare TempDir::new() inherits the\n    \
                 ambient umask, and the integrity checks reject a group-writable fixture.",
                path,
                n + 1,
                line.trim()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "CTX-004 violated (see docs/rules/RULES.md):\n\n{}\n",
        failures.join("\n\n")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CTX-005 — the rules document and its enforcement must stay in step.
// ─────────────────────────────────────────────────────────────────────────────

/// A rules file nobody can find is a rules file nobody follows — and this
/// repo has already proved it: the four guides in `.claude/rules/` are
/// gitignored, so they reach neither a fresh clone nor a worktree.
#[test]
fn ctx_005_rules_document_is_tracked_and_cites_every_enforced_rule() {
    let rules = fs::read_to_string("docs/rules/RULES.md")
        .expect("docs/rules/RULES.md must exist and be tracked in git");

    for id in ["CTX-001", "CTX-004", "CTX-005"] {
        assert!(
            rules.contains(id),
            "{id} is enforced by tests/ctxcrl_rules.rs but not documented in docs/rules/RULES.md"
        );
    }

    // Every ENFORCED rule must name the test that enforces it, so a reader can
    // tell law from aspiration.
    let enforced_without_test: Vec<&str> = rules
        .lines()
        // The status-legend table explains the word; it does not claim a rule.
        .filter(|l| l.contains("**ENFORCED**") && !l.trim_start().starts_with('|'))
        // A rule line earns ENFORCED by naming its test in backticks.
        .filter(|l| !l.contains('`'))
        .collect();
    assert!(
        enforced_without_test.is_empty(),
        "these rules claim ENFORCED but name no test:\n{enforced_without_test:#?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CTX-005 (part 2) — the session-loaded summary must not drift from the law.
// ─────────────────────────────────────────────────────────────────────────────

/// `CLAUDE.md` is what an agent actually reads at session start; `RULES.md` is
/// the law. A rule that exists only in the law is a rule no session sees, and
/// a rule listed only in the summary is one with no reasoning behind it.
///
/// This is the decay this whole system is meant to resist, so it is checked
/// rather than trusted.
#[test]
fn ctx_005_claude_md_lists_exactly_the_ratified_rules() {
    let rules = fs::read_to_string("docs/rules/RULES.md").expect("docs/rules/RULES.md");
    let summary = fs::read_to_string("CLAUDE.md")
        .expect("CLAUDE.md must exist and be tracked — .claude/ is gitignored");

    // Rule IDs are declared by their `## CTX-NNN` heading in the law.
    let mut declared: Vec<String> = rules
        .lines()
        .filter_map(|l| l.strip_prefix("## "))
        .filter(|h| h.starts_with("CTX-"))
        .map(|h| h.split_whitespace().next().unwrap_or_default().to_string())
        .collect();
    declared.sort();
    declared.dedup();
    assert!(!declared.is_empty(), "no CTX- rules found in docs/rules/RULES.md");

    let missing: Vec<&String> = declared.iter().filter(|id| !summary.contains(*id)).collect();
    assert!(
        missing.is_empty(),
        "ratified rules absent from CLAUDE.md, so no session will see them: {missing:?}"
    );
}
