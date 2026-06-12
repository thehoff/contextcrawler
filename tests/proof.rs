//! Proof harness — reproducible evidence that contextcrawler's filters cut
//! tokens (SAVINGS) without dropping the critical signal (FIDELITY).
//!
//! ```text
//! cargo test --test proof -- --nocapture            # run + print the table
//! PROOF_WRITE=1 cargo test --test proof -- --nocapture   # also regenerate docs/quality/PROOF.md
//! ```
//!
//! Why this exists: every README that claims "60–90% fewer tokens, same
//! answers" needs receipts. headroom proves accuracy with GSM8K/SQuAD; we prove
//! it with two deterministic, zero-cost invariants over a fixed corpus of real
//! command output:
//!
//! 1. SAVINGS — filtered token count < raw token count (never inflates), and
//!    the aggregate clears a floor.
//! 2. FIDELITY — every `must_keep` signal (the failing test, the panic, the
//!    error code: the line you actually opened the output FOR) survives the
//!    filter verbatim.
//!
//! Token counts use the real `cl100k_base` BPE — the tokens a GPT-4/Claude-era
//! model actually pays — not a `len / 4` heuristic. tiktoken is a
//! dev-dependency only, so the shipped binary carries zero extra weight.
//!
//! LLM-judge accuracy evals (feed raw vs filtered to a model, compare answers)
//! are the phase-2 extension. This layer is intentionally deterministic so it
//! runs in CI on every commit with no API key and no flake.

use std::fs;
use std::path::Path;

use tiktoken_rs::cl100k_base;

/// One corpus entry: a real raw output, the filter that compacts it, and the
/// signals that must survive. Fixtures are true single-input transforms
/// (`raw command output -> filter`), so raw-vs-filtered is apples-to-apples.
struct Case {
    /// Human label for the table.
    label: &'static str,
    /// Filter name understood by `contextcrawler::filter_output`.
    filter: &'static str,
    /// Fixture path, relative to the crate root.
    fixture: &'static str,
    /// Substrings that MUST appear in the filtered output. These are the
    /// non-negotiable signal — drop one and the compaction has lied.
    must_keep: &'static [&'static str],
}

// Signals are the FULL critical lines an engineer opens the output for — not
// bare tokens. A bare `"334"` could survive in unrelated text while the actual
// failure line is dropped (council finding); the whole assertion / error line
// surviving is the real fidelity bar. First+last error in multi-error cases
// guards against "kept some, silently dropped the rest".
const CASES: &[Case] = &[
    Case {
        label: "cargo test (1 of 24 failed)",
        filter: "cargo-test",
        fixture: "tests/fixtures/proof/cargo-test.raw",
        must_keep: &[
            "render::tests::test_widget_overflow",
            "assertion `left == right` failed",
        ],
    },
    Case {
        label: "cargo test (20 passed, 0 failed)",
        filter: "cargo-test",
        fixture: "tests/fixtures/proof/cargo-test-pass.raw",
        // The common, non-failure case: the summary must stay truthful. The
        // filter correctly aggregates the lib (18) + doc (2) suites to 20.
        must_keep: &["20 passed"],
    },
    Case {
        label: "pytest (1 of 38 failed)",
        filter: "pytest",
        fixture: "tests/fixtures/proof/pytest.raw",
        must_keep: &["test_partial_refund_rounds_down", "assert 334 == 333"],
    },
    Case {
        label: "tsc (10 errors, 5 files)",
        filter: "tsc",
        fixture: "tests/fixtures/proof/tsc.raw",
        // Count + first error's code + the LAST error's code and file — proves
        // the filter grouped/reformatted without silently dropping the tail.
        must_keep: &["10 errors in 5 files", "TS2322", "money.ts", "TS2416"],
    },
    Case {
        label: "go test -json (1 fail)",
        filter: "go-test",
        fixture: "tests/fixtures/proof/go-test.raw",
        must_keep: &["TestRefundRoundsHalfEven", "got 334, want 333"],
    },
    Case {
        label: "ruff check --output json",
        filter: "ruff-check",
        fixture: "tests/fixtures/proof/ruff-check.raw",
        // First and last rule + their files: nothing silently dropped.
        must_keep: &["F401", "refund.py", "F841", "ledger.py"],
    },
    Case {
        label: "git diff (2 files)",
        filter: "git-diff",
        fixture: "tests/fixtures/proof/git-diff.raw",
        // The actual changed content (a removed line) plus both files — the
        // unchanged `clip_child` context line is legitimately dropped.
        must_keep: &["clip.rs", "returned the child unclipped", "mod.rs"],
    },
    Case {
        label: "rg search (37 hits, 3 files)",
        filter: "grep",
        fixture: "tests/fixtures/proof/grep-search.raw",
        // Every file must survive the per-file cap — dropping a whole file is
        // the failure mode a bare single-path signal would miss.
        must_keep: &["config.rs", "client.rs", "upload.rs"],
    },
];

/// Floor the aggregate savings must clear. Conservative — the point is to catch
/// a regression that quietly halves savings, not to chase a vanity number.
const AGGREGATE_FLOOR_PCT: f64 = 40.0;

fn count(bpe: &tiktoken_rs::CoreBPE, s: &str) -> usize {
    bpe.encode_with_special_tokens(s).len()
}

fn savings_pct(raw: usize, filtered: usize) -> f64 {
    if raw == 0 {
        0.0
    } else {
        100.0 * (raw as f64 - filtered as f64) / raw as f64
    }
}

struct Row {
    label: String,
    filter: String,
    raw_tokens: usize,
    filtered_tokens: usize,
    savings: f64,
    fidelity_ok: bool,
}

#[test]
fn proof_savings_and_fidelity() {
    let bpe = cl100k_base().expect("load cl100k_base BPE");
    let root = env!("CARGO_MANIFEST_DIR");

    let mut rows: Vec<Row> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut total_raw = 0usize;
    let mut total_filtered = 0usize;

    for c in CASES {
        let path = Path::new(root).join(c.fixture);
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));

        let filtered = contextcrawler::filter_output(c.filter, &raw);

        let raw_tokens = count(&bpe, &raw);
        let filtered_tokens = count(&bpe, &filtered);

        // Invariant 1: never inflate. A token-optimiser that grows output is
        // worse than useless — this is the exact class of bug (#196 / rtk #2035)
        // this harness exists to catch.
        if filtered_tokens > raw_tokens {
            failures.push(format!(
                "[{}] INFLATED: {raw_tokens} -> {filtered_tokens} tokens",
                c.label
            ));
        }

        // Invariant 2: fidelity. Every signal must survive.
        let missing: Vec<&str> = c
            .must_keep
            .iter()
            .copied()
            .filter(|sig| !filtered.contains(sig))
            .collect();
        if !missing.is_empty() {
            failures.push(format!(
                "[{}] DROPPED SIGNAL: {missing:?}\n--- filtered output ---\n{filtered}",
                c.label
            ));
        }

        // Invariant 3: structural sanity. A filter that returns nothing (or
        // collapses a multi-line report to a bare token) has destroyed the
        // output, even if a signal substring happens to survive.
        if filtered.trim().is_empty() && !raw.trim().is_empty() {
            failures.push(format!("[{}] EMPTY OUTPUT from non-empty input", c.label));
        }

        total_raw += raw_tokens;
        total_filtered += filtered_tokens;
        rows.push(Row {
            label: c.label.to_string(),
            filter: c.filter.to_string(),
            raw_tokens,
            filtered_tokens,
            savings: savings_pct(raw_tokens, filtered_tokens),
            fidelity_ok: missing.is_empty(),
        });
    }

    let aggregate = savings_pct(total_raw, total_filtered);
    let report = render_report(&rows, total_raw, total_filtered, aggregate);
    println!("\n{report}");

    // Correctness first — surface savings/fidelity violations before anything
    // about the doc file.
    assert!(
        failures.is_empty(),
        "proof harness found {} violation(s):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(
        aggregate >= AGGREGATE_FLOOR_PCT,
        "aggregate savings {aggregate:.1}% below floor {AGGREGATE_FLOOR_PCT:.1}%"
    );

    // Drift gate: `PROOF_WRITE=1` regenerates the checked-in doc; the default
    // run ASSERTS the committed doc still matches what the filters produce
    // today, so it can never silently go stale (council finding).
    let out = Path::new(root).join("docs/quality/PROOF.md");
    if std::env::var("PROOF_WRITE").is_ok() {
        fs::write(&out, &report).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
        println!("wrote {}", out.display());
    } else {
        let checked_in = fs::read_to_string(&out).unwrap_or_default();
        assert_eq!(
            checked_in.trim_end(),
            report.trim_end(),
            "docs/quality/PROOF.md is STALE — filter behaviour changed without \
             regenerating it. Run: PROOF_WRITE=1 cargo test --test proof"
        );
    }
}

fn render_report(rows: &[Row], total_raw: usize, total_filtered: usize, aggregate: f64) -> String {
    let mut s = String::new();
    s.push_str("# ContextCrawler — proof of claims\n\n");
    s.push_str(
        "Reproducible evidence that the filters cut tokens **and** keep the signal.\n\
         Generated by `tests/proof.rs` (`PROOF_WRITE=1 cargo test --test proof`). Do not hand-edit.\n\n",
    );
    s.push_str("**Method.** Each row is a real command's raw output run through the matching\n");
    s.push_str("filter via the public `contextcrawler::filter_output` API. Tokens are counted\n");
    s.push_str("with the real `cl100k_base` BPE (what a GPT-4/Claude-era model actually pays),\n");
    s.push_str("not a character heuristic. **Fidelity** checks that the critical signal (the\n");
    s.push_str("failing test, the panic, the error code) survives the filter verbatim.\n\n");
    s.push_str(
        "**Scope.** This is a curated corpus of common dev-command shapes (failures, \
         error lists, a passing run, a busy search), not a random sample — it shows what \
         the named filters do on representative input, not a statistical average over all \
         possible output. Numbers are reproduced exactly by the command above.\n\n",
    );

    s.push_str("| Command | Filter | Raw tok | Filtered tok | Savings | Fidelity |\n");
    s.push_str("|---|---|--:|--:|--:|:--:|\n");
    for r in rows {
        s.push_str(&format!(
            "| {} | `{}` | {} | {} | **{:.0}%** | {} |\n",
            r.label,
            r.filter,
            r.raw_tokens,
            r.filtered_tokens,
            r.savings,
            if r.fidelity_ok { "PASS" } else { "**FAIL**" },
        ));
    }
    s.push_str(&format!(
        "| **Total** | — | **{}** | **{}** | **{:.0}%** | — |\n\n",
        total_raw, total_filtered, aggregate,
    ));

    s.push_str(&format!(
        "**Aggregate: {:.0}% fewer tokens across {} dev-command fixtures, \
         with every critical signal preserved.**\n",
        aggregate,
        rows.len(),
    ));
    s
}
