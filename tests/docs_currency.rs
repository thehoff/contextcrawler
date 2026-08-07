//! Planning documents must not lie about which version they describe.
//!
//! `docs/ROADMAP.md` opened with `## Current line: v0.1.x` while `Cargo.toml`
//! said `0.4.9` — wrong across nine releases and roughly nine weeks. The
//! ROADMAP already carried the process that would have caught it ("Each
//! release: mark items shipped"); the process was simply skipped nine times.
//!
//! A runbook step nobody runs is not a control. This is the control.
//!
//! Candidate rule: `docs/rules/lessons/2026-08-07-planning-docs-drift-nine-releases.md`
//! (unratified — promotion to a `CTX-` number is the maintainer's step).

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `version = "0.4.9"` from the `[package]` table → `("0", "4")`.
fn cargo_major_minor() -> (String, String) {
    let manifest = fs::read_to_string(repo_root().join("Cargo.toml"))
        .expect("Cargo.toml must be readable");

    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("version"))
        .expect("Cargo.toml has no `version` line");

    let raw = line
        .split('=')
        .nth(1)
        .expect("`version` line has no value")
        .trim()
        .trim_matches('"');

    let mut parts = raw.split('.');
    let major = parts.next().expect("version has no major").to_string();
    let minor = parts.next().expect("version has no minor").to_string();
    (major, minor)
}

#[test]
fn roadmap_current_line_matches_cargo_version() {
    let roadmap_path = repo_root().join("docs/ROADMAP.md");
    let roadmap = fs::read_to_string(&roadmap_path).expect("docs/ROADMAP.md must be readable");

    let heading = roadmap
        .lines()
        .find(|l| l.trim_start().starts_with("## Current line:"))
        .unwrap_or_else(|| {
            panic!(
                "docs/ROADMAP.md has no `## Current line: vX.Y` heading.\n\
                 That heading is what this test pins to Cargo.toml. If the \
                 roadmap's shape changed, update this test in the same commit \
                 — do not delete the heading to make the test pass."
            )
        });

    // `## Current line: v0.4.x` → `0.4.x`
    let claimed = heading
        .split_once("v")
        .map(|(_, rest)| rest.trim())
        .unwrap_or_else(|| panic!("heading is not `## Current line: vX.Y`: {heading:?}"));

    let mut claimed_parts = claimed.split('.');
    let claimed_major = claimed_parts.next().unwrap_or("").trim();
    let claimed_minor = claimed_parts.next().unwrap_or("").trim();

    let (major, minor) = cargo_major_minor();

    assert_eq!(
        (claimed_major, claimed_minor),
        (major.as_str(), minor.as_str()),
        "\n\n--- docs-currency failure ---\n\
         docs/ROADMAP.md claims the current line is v{claimed_major}.{claimed_minor}.x, \
         but Cargo.toml ships {major}.{minor}.\n\n\
         FIX: update the `## Current line:` heading in docs/ROADMAP.md, and while \
         you are there, move anything that shipped out of the backlog sections.\n\n\
         This test exists because that heading said v0.1.x for nine releases. \
         Do not silence it by loosening the assertion — the whole point is that \
         it fires at the release that forgets, not nine releases later.\n"
    );
}

#[test]
fn roadmap_does_not_claim_upstream_is_tracked_by_rebase() {
    let roadmap = fs::read_to_string(repo_root().join("docs/ROADMAP.md")).expect("readable");
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("readable");

    // The fork diverged 1,424 commits ahead / 490 behind before anyone
    // measured. "tracked by rebase" was carried in both documents and in the
    // project goal, all agreeing with each other and all wrong.
    for (name, body) in [("docs/ROADMAP.md", &roadmap), ("README.md", &readme)] {
        assert!(
            !body.contains("tracked by rebase"),
            "\n\n--- docs-currency failure ---\n\
             {name} claims upstream rtk-ai/rtk is \"tracked by rebase\".\n\n\
             That relationship was retired on 2026-08-07: upstream is a source \
             to harvest, not a base to track. See the `Relationship to upstream` \
             section in README.md.\n\n\
             If the policy genuinely changes back, update that section first and \
             then this test — in that order.\n"
        );
    }
}
