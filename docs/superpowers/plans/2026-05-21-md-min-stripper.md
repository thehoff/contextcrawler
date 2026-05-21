# md-min Stripper Implementation Plan (Plan 1 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `contextcrawler md-min <file> --tier <0-4>` — a markdown minifier with five additive strip tiers and two deterministic losslessness checks (L1 AST equivalence, L2 flattened-text equivalence).

**Architecture:** Parse markdown with `pulldown-cmark` into an `Event` stream, transform the stream per tier, re-serialise with `pulldown-cmark-to-cmark`. Tier 0 is the post-parser re-serialised baseline; tiers 1–4 add progressively more aggressive event deletions. L1/L2 are deterministic Rust tests that prove each tier only drops what it declares.

**Tech Stack:** Rust, `pulldown-cmark` + `pulldown-cmark-to-cmark`, `anyhow`, `clap`. `tiktoken-rs` as a dev-dependency for token-array profiling.

**Scope:** This is Plan 1 of 2. It delivers the stripper and its deterministic validation (spec cycles 1–3). Plan 2 (the council viability harness, cycles 4–6) is written after this lands.

**Spec:** `docs/superpowers/specs/2026-05-21-md-min-viability-design.md` (v2).

---

## File Structure

- `src/cmds/system/md_min.rs` — **new.** The whole feature: `MdMinArgs`, `Tier` enum, `run()`, the per-tier event transform, and (under `#[cfg(test)]`) the L1/L2 deterministic checks plus tier tests.
- `src/main.rs` — **modify.** Add the `MdMin` variant to the `Commands` enum and route it.
- `src/cmds/system/mod.rs` — **modify.** Add `pub mod md_min;`.
- `Cargo.toml` — **modify.** Add `pulldown-cmark`, `pulldown-cmark-to-cmark`; add `tiktoken-rs` under `[dev-dependencies]`.
- `tests/fixtures/md/` — **new dir.** Real markdown fixtures: `prose.md`, `tables.md`, `nested_lists.md`, `code_heavy.md`, `mixed.md`.

One module holds the feature because the tiers, the transform, and the L1/L2 checks all share the `Tier` enum and the event vocabulary — splitting them would scatter one responsibility.

---

## Task 1: Add dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the runtime dependencies**

In `Cargo.toml`, under `[dependencies]`, add:

```toml
pulldown-cmark = { version = "0.13", default-features = false }
pulldown-cmark-to-cmark = "22"
```

- [ ] **Step 2: Add the dev-dependency for token profiling**

Under `[dev-dependencies]` (currently empty), add:

```toml
tiktoken-rs = "0.11"
```

- [ ] **Step 3: Verify it resolves and builds**

Run: `cargo build`
Expected: compiles clean, the three crates appear in `Cargo.lock`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(md-min): add pulldown-cmark + tiktoken-rs deps"
```

---

## Task 2: Module skeleton, `Tier` enum, tier 0, CLI wiring

Tier 0 = parse then re-serialise. This is the post-parser baseline every later tier and check compares against.

**Files:**
- Create: `src/cmds/system/md_min.rs`
- Modify: `src/cmds/system/mod.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing test**

Create `src/cmds/system/md_min.rs` with:

```rust
//! `md-min` — markdown minifier with additive strip tiers.
//!
//! Tier 0 is the post-parser re-serialised baseline. Tiers 1-4 add
//! progressively more aggressive event deletions. See
//! `docs/superpowers/specs/2026-05-21-md-min-viability-design.md`.

use anyhow::{Context, Result};
use pulldown_cmark::{Event, Options, Parser};

/// Strip aggressiveness. Additive: tier N applies tier N-1 plus more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Post-parser re-serialisation only — the baseline.
    Zero,
    /// + HTML comments dropped, hard-break form normalised.
    One,
    /// + emphasis/strong/strikethrough markers, horizontal rules.
    Two,
    /// + heading hashes, blockquote markers, link markup (URL kept).
    Three,
    /// + list markers, code-fence language tags.
    Four,
}

impl Tier {
    /// Parse a `--tier` integer.
    pub fn from_u8(n: u8) -> Result<Tier> {
        match n {
            0 => Ok(Tier::Zero),
            1 => Ok(Tier::One),
            2 => Ok(Tier::Two),
            3 => Ok(Tier::Three),
            4 => Ok(Tier::Four),
            other => anyhow::bail!("md-min: --tier must be 0-4, got {other}"),
        }
    }
}

/// CommonMark parser options used everywhere in this module — fixed so the
/// stripper, L1, and L2 all see the same event vocabulary.
fn parser_options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_TASKLISTS
}

/// Minify `input` markdown at `tier`. On any parse/serialise failure the
/// original input is returned unchanged (RTK fallback convention).
pub fn minify(input: &str, tier: Tier) -> String {
    match try_minify(input, tier) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("contextcrawler: md-min filter warning: {e}");
            input.to_string()
        }
    }
}

fn try_minify(input: &str, tier: Tier) -> Result<String> {
    let events: Vec<Event> = Parser::new_ext(input, parser_options()).collect();
    let transformed = transform(events, tier);
    let mut out = String::with_capacity(input.len());
    pulldown_cmark_to_cmark::cmark(transformed.into_iter(), &mut out)
        .context("md-min: re-serialisation failed")?;
    out.push('\n');
    Ok(out)
}

/// Apply the tier's event transform. Tier 0 is identity.
fn transform(events: Vec<Event>, tier: Tier) -> Vec<Event> {
    match tier {
        Tier::Zero => events,
        // Filled in by later tasks.
        _ => events,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier0_roundtrips_and_is_stable() {
        let input = "# Title\n\nA paragraph with **bold** text.\n";
        let once = minify(input, Tier::Zero);
        // Tier 0 must be idempotent: re-minifying its own output is a no-op.
        let twice = minify(&once, Tier::Zero);
        assert_eq!(once, twice, "tier 0 must be idempotent");
        assert!(once.contains("# Title"));
        assert!(once.contains("**bold**"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --bins md_min::tests::tier0`
Expected: FAIL — module not yet declared / not compiled.

- [ ] **Step 3: Declare the module**

In `src/cmds/system/mod.rs`, add alphabetically among the other `pub mod` lines:

```rust
pub mod md_min;
```

- [ ] **Step 4: Wire the CLI command**

In `src/main.rs`, in the `Commands` enum, after the `Wc { .. }` variant, add:

```rust
    /// Minify a markdown file (token-saving strip tiers 0-4)
    MdMin {
        /// Path to the markdown file
        file: String,
        /// Strip tier: 0 (baseline) .. 4 (most aggressive)
        #[arg(long, default_value_t = 0)]
        tier: u8,
    },
```

In the routing `match` (where `Commands::Wc { args } => wc_cmd::run(...)` sits), add:

```rust
        Commands::MdMin { file, tier } => {
            let input = std::fs::read_to_string(&file)
                .with_context(|| format!("md-min: cannot read {file}"))?;
            let tier = crate::cmds::system::md_min::Tier::from_u8(tier)?;
            print!("{}", crate::cmds::system::md_min::minify(&input, tier));
            0
        }
```

Confirm `use anyhow::Context;` is in scope in `main.rs` (it is — used elsewhere); if the routing arm needs `i32`, match the surrounding arms' return convention.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --bins md_min::tests::tier0`
Expected: PASS.

- [ ] **Step 6: Verify the command runs end to end**

Run: `printf '# Hi\n\n\n\nbye\n' > /tmp/t.md && cargo run --bin contextcrawler -- md-min /tmp/t.md --tier 0`
Expected: prints normalised markdown (the triple blank line collapsed by the serialiser).

- [ ] **Step 7: Commit**

```bash
git add src/cmds/system/md_min.rs src/cmds/system/mod.rs src/main.rs
git commit -m "feat(md-min): module skeleton, Tier enum, tier 0 + CLI wiring"
```

---

## Task 3: Tier 1 — HTML comments + hard-break form

Re-serialisation (tier 0) already collapses blank lines, normalises list markers, and strips table-cell padding. Tier 1's *additional* work is: drop HTML comment events, and normalise hard breaks to whichever form profiling shows is cheapest.

**Files:**
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Write the failing test**

In `md_min.rs` `tests` module, add:

```rust
#[test]
fn tier1_drops_html_comments() {
    let input = "Before.\n\n<!-- a hidden comment -->\n\nAfter.\n";
    let out = minify(input, Tier::One);
    assert!(!out.contains("hidden comment"), "tier 1 must drop HTML comments");
    assert!(out.contains("Before."));
    assert!(out.contains("After."));
}

#[test]
fn tier1_keeps_all_visible_text() {
    let input = "# Heading\n\nReal content here.\n";
    let out = minify(input, Tier::One);
    assert!(out.contains("# Heading"));
    assert!(out.contains("Real content here."));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bins md_min::tests::tier1`
Expected: FAIL — `tier1_drops_html_comments` fails (comment still present).

- [ ] **Step 3: Implement the tier 1 transform**

Replace the `transform` function body's `_ => events` for tier 1. Restructure `transform` so tiers compose:

```rust
fn transform(events: Vec<Event>, tier: Tier) -> Vec<Event> {
    if tier == Tier::Zero {
        return events;
    }
    let mut events = strip_tier1(events);
    if tier == Tier::One {
        return events;
    }
    events = strip_tier2(events);
    if tier == Tier::Two {
        return events;
    }
    events = strip_tier3(events);
    if tier == Tier::Three {
        return events;
    }
    strip_tier4(events)
}

/// Tier 1: drop HTML comment events. (Whitespace/padding normalisation is
/// already done by the serialiser.) Hard-break form is left as the parser
/// emits it — see the profiling test for why no conversion is applied.
fn strip_tier1(events: Vec<Event>) -> Vec<Event> {
    events
        .into_iter()
        .filter(|e| match e {
            Event::Html(html) | Event::InlineHtml(html) => {
                !html.trim_start().starts_with("<!--")
            }
            _ => true,
        })
        .collect()
}

fn strip_tier2(events: Vec<Event>) -> Vec<Event> { events }
fn strip_tier3(events: Vec<Event>) -> Vec<Event> { events }
fn strip_tier4(events: Vec<Event>) -> Vec<Event> { events }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --bins md_min::tests::tier1`
Expected: PASS.

- [ ] **Step 5: Write the hard-break token-profiling test**

Spec requires profiling real token arrays before assuming a hard-break rewrite saves tokens. Add:

```rust
#[test]
fn hard_break_form_profiling() {
    // Spec cycle 1: do NOT assume "  \n" -> "\\\n" saves tokens. Measure.
    use tiktoken_rs::o200k_base;
    let bpe = o200k_base().expect("tokenizer");
    let two_space = "line one  \nline two";
    let backslash = "line one\\\nline two";
    let n_space = bpe.encode_with_special_tokens(two_space).len();
    let n_back = bpe.encode_with_special_tokens(backslash).len();
    // Record the finding in the test output; tier 1 only rewrites hard
    // breaks if the backslash form is strictly cheaper.
    println!("hard-break tokens: two-space={n_space} backslash={n_back}");
    assert!(n_space > 0 && n_back > 0);
}
```

- [ ] **Step 6: Run the profiling test and record the result**

Run: `cargo test --bins md_min::tests::hard_break_form_profiling -- --nocapture`
Expected: PASS; note the printed token counts. If `backslash < two-space`, add a hard-break rewrite to `strip_tier1`; if not, leave hard breaks alone (the default in the code above). Record the decision in a code comment in `strip_tier1`.

- [ ] **Step 7: Commit**

```bash
git add src/cmds/system/md_min.rs
git commit -m "feat(md-min): tier 1 — drop HTML comments; hard-break profiling"
```

---

## Task 4: Tier 2 — emphasis, strong, strikethrough, rules

Tier 2 keeps the text inside emphasis but drops the markers, and drops horizontal rules.

**Files:**
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tier2_strips_emphasis_keeps_text() {
    let input = "A **bold** and _italic_ and ~~struck~~ word.\n\n---\n\nNext.\n";
    let out = minify(input, Tier::Two);
    assert!(out.contains("bold"), "emphasised text must survive");
    assert!(out.contains("italic"));
    assert!(out.contains("struck"));
    assert!(!out.contains("**"), "bold markers must be gone");
    assert!(!out.contains("~~"), "strikethrough markers must be gone");
    assert!(!out.contains("---"), "horizontal rule must be gone");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bins md_min::tests::tier2`
Expected: FAIL — markers still present.

- [ ] **Step 3: Implement `strip_tier2`**

```rust
use pulldown_cmark::{Tag, TagEnd};

/// Tier 2: drop emphasis/strong/strikethrough delimiters (keep inner text)
/// and thematic breaks. The Start/End events are removed; the Text events
/// between them are untouched, so the words survive verbatim.
fn strip_tier2(events: Vec<Event>) -> Vec<Event> {
    events
        .into_iter()
        .filter(|e| {
            !matches!(
                e,
                Event::Start(Tag::Emphasis | Tag::Strong | Tag::Strikethrough)
                    | Event::End(TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough)
                    | Event::Rule
            )
        })
        .collect()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --bins md_min::tests::tier2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cmds/system/md_min.rs
git commit -m "feat(md-min): tier 2 — strip emphasis markers and rules"
```

---

## Task 5: Tier 3 — heading hashes, blockquote markers, link markup

Tier 3 removes heading `#` and blockquote `>` markers, and the link bracket/paren markup — **keeping the URL** as plain text, since URLs are payload.

**Files:**
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tier3_strips_structure_markers_keeps_url() {
    let input = "## Section\n\n> a quote\n\nSee [the docs](https://example.com/d).\n";
    let out = minify(input, Tier::Three);
    assert!(out.contains("Section"), "heading text must survive");
    assert!(!out.contains("## "), "heading hashes must be gone");
    assert!(out.contains("a quote"), "blockquote text must survive");
    assert!(out.contains("the docs"), "link text must survive");
    assert!(out.contains("https://example.com/d"), "URL must be kept — it is payload");
    assert!(!out.contains("](http"), "link markup must be gone");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bins md_min::tests::tier3`
Expected: FAIL.

- [ ] **Step 3: Implement `strip_tier3`**

Headings become plain paragraphs (text survives, level marker gone);
blockquote wrappers are dropped (inner blocks remain); links are reduced
to their text followed by the URL as plain text. The link URL is captured
from the `Start(Link)` tag and re-emitted at `End(Link)` — a single pass,
with a stack so nested links are handled.

```rust
use pulldown_cmark::CowStr;

/// Tier 3: drop heading hashes and blockquote markers, and reduce links to
/// `text url` plain text. The URL is always kept because it is payload.
fn strip_tier3(events: Vec<Event>) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::with_capacity(events.len());
    // Pending link URLs, innermost last.
    let mut link_urls: Vec<CowStr> = Vec::new();
    for e in events {
        match e {
            Event::Start(Tag::Heading { .. }) => out.push(Event::Start(Tag::Paragraph)),
            Event::End(TagEnd::Heading(_)) => out.push(Event::End(TagEnd::Paragraph)),
            Event::Start(Tag::BlockQuote(_)) | Event::End(TagEnd::BlockQuote(_)) => {}
            Event::Start(Tag::Link { dest_url, .. }) => link_urls.push(dest_url),
            Event::End(TagEnd::Link) => {
                if let Some(url) = link_urls.pop() {
                    out.push(Event::Text(CowStr::Borrowed(" ")));
                    out.push(Event::Text(url));
                }
            }
            other => out.push(other),
        }
    }
    out
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --bins md_min::tests::tier3`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cmds/system/md_min.rs
git commit -m "feat(md-min): tier 3 — strip heading/quote/link markup, keep URLs"
```

---

## Task 6: Tier 4 — list markers, code-fence language tags

Tier 4 is the cliff control — expected to lose. It flattens list items to paragraphs and drops the code-fence language.

**Files:**
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tier4_flattens_lists_and_drops_fence_lang() {
    let input = "- one\n- two\n\n```rust\nfn x() {}\n```\n";
    let out = minify(input, Tier::Four);
    assert!(out.contains("one") && out.contains("two"), "item text survives");
    assert!(!out.contains("- one"), "list markers must be gone");
    assert!(out.contains("fn x() {}"), "code body survives verbatim");
    assert!(!out.contains("```rust"), "fence language must be gone");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bins md_min::tests::tier4`
Expected: FAIL.

- [ ] **Step 3: Implement `strip_tier4`**

```rust
use pulldown_cmark::{CodeBlockKind, CowStr};

/// Tier 4: flatten list structure (items become paragraphs, list wrapper
/// dropped) and strip the code-fence language tag. Expected to lose
/// structure — included so the harness can prove the cliff.
fn strip_tier4(events: Vec<Event>) -> Vec<Event> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::Start(Tag::List(_)) | Event::End(TagEnd::List(_)) => None,
            Event::Start(Tag::Item) => Some(Event::Start(Tag::Paragraph)),
            Event::End(TagEnd::Item) => Some(Event::End(TagEnd::Paragraph)),
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_))) => {
                Some(Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(
                    CowStr::Borrowed(""),
                ))))
            }
            other => Some(other),
        })
        .collect()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --bins md_min::tests::tier4`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cmds/system/md_min.rs
git commit -m "feat(md-min): tier 4 — flatten lists, drop fence language"
```

---

## Task 7: Test fixtures + per-tier savings assertions

**Files:**
- Create: `tests/fixtures/md/prose.md`, `tables.md`, `nested_lists.md`, `code_heavy.md`, `mixed.md`
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Create the fixtures**

Create five real markdown files under `tests/fixtures/md/`. Each must be non-trivial (40+ lines) and representative of its name: `prose.md` (paragraphs, emphasis, links), `tables.md` (multiple GFM tables), `nested_lists.md` (3-deep ordered + unordered lists), `code_heavy.md` (fenced blocks in several languages), `mixed.md` (all of the above). Use genuine content — copy from real docs, do not synthesise toy data.

- [ ] **Step 2: Write the savings + safety tests**

```rust
fn count_tokens(s: &str) -> usize {
    s.split_whitespace().count()
}

#[test]
fn every_tier_is_monotonically_smaller_or_equal() {
    let input = include_str!("../../../tests/fixtures/md/mixed.md");
    let sizes: Vec<usize> = [Tier::Zero, Tier::One, Tier::Two, Tier::Three, Tier::Four]
        .iter()
        .map(|t| count_tokens(&minify(input, *t)))
        .collect();
    for w in sizes.windows(2) {
        assert!(w[1] <= w[0], "each tier must be <= the previous: {sizes:?}");
    }
}

#[test]
fn malformed_input_does_not_panic() {
    for junk in ["", "```unclosed", "[", "| broken |", "\u{0}\u{0}"] {
        let _ = minify(junk, Tier::Four); // must not panic
    }
}

#[test]
fn unicode_content_survives_all_tiers() {
    let input = "# 日本語\n\nParagraph with émojis 🚀 and ünïcode.\n";
    for t in [Tier::Zero, Tier::One, Tier::Two, Tier::Three, Tier::Four] {
        let out = minify(input, t);
        assert!(out.contains("日本語"));
        assert!(out.contains("🚀"));
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test --bins md_min::tests`
Expected: PASS for all.

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/md src/cmds/system/md_min.rs
git commit -m "test(md-min): real fixtures, monotonic savings, robustness"
```

---

## Task 8: L2 — flattened-text equivalence

L2: flatten raw and stripped to plain text (all markup removed from both), normalise whitespace, assert equality up to each tier's *declared text changes*. Tiers 0–2 must be exactly text-equal to the raw flatten; tier 3 adds URL text (declared); tier 4 adds nothing new textually.

**Files:**
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// Flatten markdown to bare text: concatenate all Text/Code events, drop
/// all markup, collapse whitespace runs to single spaces.
fn flatten_text(md: &str) -> String {
    let mut buf = String::new();
    for e in Parser::new_ext(md, parser_options()) {
        match e {
            Event::Text(s) | Event::Code(s) => {
                buf.push_str(&s);
                buf.push(' ');
            }
            Event::SoftBreak | Event::HardBreak => buf.push(' '),
            _ => {}
        }
    }
    buf.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn l2_tiers_0_to_2_preserve_all_text() {
    for fixture in [
        include_str!("../../../tests/fixtures/md/prose.md"),
        include_str!("../../../tests/fixtures/md/tables.md"),
        include_str!("../../../tests/fixtures/md/nested_lists.md"),
        include_str!("../../../tests/fixtures/md/code_heavy.md"),
        include_str!("../../../tests/fixtures/md/mixed.md"),
    ] {
        let raw = flatten_text(fixture);
        for t in [Tier::Zero, Tier::One, Tier::Two] {
            assert_eq!(
                flatten_text(&minify(fixture, t)),
                raw,
                "L2: tier {t:?} must not change body text",
            );
        }
    }
}

#[test]
fn l2_tier3_only_adds_urls() {
    let fixture = include_str!("../../../tests/fixtures/md/prose.md");
    let raw_words: std::collections::HashSet<String> =
        flatten_text(fixture).split(' ').map(String::from).collect();
    let t3_words: std::collections::HashSet<String> =
        flatten_text(&minify(fixture, Tier::Three)).split(' ').map(String::from).collect();
    // Tier 3 may ADD url tokens but must never DROP a raw word.
    for w in &raw_words {
        assert!(t3_words.contains(w), "L2: tier 3 dropped body word {w:?}");
    }
}
```

- [ ] **Step 2: Run to verify it fails or passes**

Run: `cargo test --bins md_min::tests::l2`
Expected: PASS if tiers 0–2 are correct; a FAIL here means a tier silently drops text — fix the offending `strip_tierN` before continuing.

- [ ] **Step 3: Resolve any failures**

If `l2_tiers_0_to_2_preserve_all_text` fails, the named tier is dropping text events it should keep — inspect its `strip_` function. Do not weaken the test.

- [ ] **Step 4: Commit**

```bash
git add src/cmds/system/md_min.rs
git commit -m "test(md-min): L2 flattened-text equivalence per tier"
```

---

## Task 9: L1 — AST allowed-mutation equivalence

L1: parse raw (post-tier-0) and stripped to event streams; assert the stripped stream equals the tier-0 stream with exactly the tier's declared event-kinds removed/rewritten — nothing else changed.

**Files:**
- Modify: `src/cmds/system/md_min.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// Classify an event into a coarse kind for L1 comparison.
fn event_kind(e: &Event) -> &'static str {
    match e {
        Event::Start(Tag::Emphasis) | Event::End(TagEnd::Emphasis) => "emphasis",
        Event::Start(Tag::Strong) | Event::End(TagEnd::Strong) => "strong",
        Event::Start(Tag::Strikethrough) | Event::End(TagEnd::Strikethrough) => "strike",
        Event::Rule => "rule",
        Event::Start(Tag::Heading { .. }) | Event::End(TagEnd::Heading(_)) => "heading",
        Event::Start(Tag::BlockQuote(_)) | Event::End(TagEnd::BlockQuote(_)) => "blockquote",
        Event::Start(Tag::Link { .. }) | Event::End(TagEnd::Link) => "link",
        Event::Start(Tag::List(_)) | Event::End(TagEnd::List(_)) => "list",
        Event::Html(_) | Event::InlineHtml(_) => "html",
        Event::Text(_) => "text",
        Event::Code(_) => "code",
        _ => "other",
    }
}

/// Event kinds each tier is permitted to remove or rewrite.
fn declared_deletions(tier: Tier) -> &'static [&'static str] {
    match tier {
        Tier::Zero => &[],
        Tier::One => &["html"],
        Tier::Two => &["html", "emphasis", "strong", "strike", "rule"],
        Tier::Three => &["html", "emphasis", "strong", "strike", "rule",
                          "heading", "blockquote", "link"],
        Tier::Four => &["html", "emphasis", "strong", "strike", "rule",
                         "heading", "blockquote", "link", "list"],
    }
}

#[test]
fn l1_text_and_code_events_are_never_lost() {
    // The strongest L1 invariant: no tier may drop a Text or Code event.
    for fixture in [
        include_str!("../../../tests/fixtures/md/mixed.md"),
        include_str!("../../../tests/fixtures/md/code_heavy.md"),
    ] {
        let raw_codes: Vec<String> = Parser::new_ext(fixture, parser_options())
            .filter_map(|e| match e {
                Event::Code(s) => Some(s.to_string()),
                _ => None,
            })
            .collect();
        for t in [Tier::Zero, Tier::One, Tier::Two, Tier::Three, Tier::Four] {
            let stripped_codes: Vec<String> =
                Parser::new_ext(&minify(fixture, t), parser_options())
                    .filter_map(|e| match e {
                        Event::Code(s) => Some(s.to_string()),
                        _ => None,
                    })
                    .collect();
            assert_eq!(raw_codes, stripped_codes, "L1: tier {t:?} altered inline code");
        }
    }
}

#[test]
fn l1_no_undeclared_event_kinds_disappear() {
    let fixture = include_str!("../../../tests/fixtures/md/mixed.md");
    let raw_kinds: std::collections::HashSet<&str> =
        Parser::new_ext(fixture, parser_options())
            .map(|e| event_kind(&e))
            .collect();
    for t in [Tier::One, Tier::Two, Tier::Three, Tier::Four] {
        let kinds: std::collections::HashSet<&str> =
            Parser::new_ext(&minify(fixture, t), parser_options())
                .map(|e| event_kind(&e))
                .collect();
        let allowed: std::collections::HashSet<&str> =
            declared_deletions(t).iter().copied().collect();
        for k in &raw_kinds {
            assert!(
                kinds.contains(k) || allowed.contains(k),
                "L1: tier {t:?} removed undeclared event kind {k:?}",
            );
        }
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --bins md_min::tests::l1`
Expected: PASS. A failure means a tier mutates more than it declares — fix the `strip_` function, not the test.

- [ ] **Step 3: Run the full module suite**

Run: `cargo test --bins md_min`
Expected: every test PASS.

- [ ] **Step 4: Commit**

```bash
git add src/cmds/system/md_min.rs
git commit -m "test(md-min): L1 AST allowed-mutation equivalence"
```

---

## Task 10: Final verification

- [ ] **Step 1: Full workspace test**

Run: `cargo test --bins`
Expected: the whole suite passes — no regression elsewhere.

- [ ] **Step 2: Clippy clean**

Run: `cargo clippy --bins -- -D warnings`
Expected: no warnings in `md_min.rs`.

- [ ] **Step 3: Manual smoke on a real doc**

Run: `cargo run --bin contextcrawler -- md-min README.md --tier 3 | head -30`
Expected: readable, markup-light markdown; no panic; URLs still present.

- [ ] **Step 4: Final commit if anything changed**

```bash
git add -A
git commit -m "chore(md-min): clippy clean, final verification"
```

---

## Notes for Plan 2 (the harness)

Plan 2 builds `harness/md-viability/` and consumes this stripper via
`contextcrawler md-min <file> --tier N`. It is written once this plan
lands, against the working `Tier` behaviour observed here — in particular
the hard-break profiling result (Task 3 Step 6) and the actual per-tier
token savings (Task 7) feed Plan 2's expectations.
