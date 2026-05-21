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

/// Apply the tier's event transform. Tiers compose additively.
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

/// Tier 1: drop HTML comment events.
///
/// HTML comments arrive as either `Event::Html` (block-level comment) or
/// `Event::InlineHtml` (inline comment). Both carry the raw text including
/// the `<!--` / `-->` delimiters, so we detect them by checking that the
/// trimmed string starts with `<!--`.
///
/// Hard-break form: profiling (see `hard_break_form_profiling` test) showed
/// two-space=5 tokens vs backslash=5 tokens — identical cost on o200k_base.
/// No rewrite is applied; hard breaks are left as the parser emits them.
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

/// Tier 2 placeholder — implemented in a later task.
fn strip_tier2(events: Vec<Event>) -> Vec<Event> {
    events
}

/// Tier 3 placeholder — implemented in a later task.
fn strip_tier3(events: Vec<Event>) -> Vec<Event> {
    events
}

/// Tier 4 placeholder — implemented in a later task.
fn strip_tier4(events: Vec<Event>) -> Vec<Event> {
    events
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

    #[test]
    fn hard_break_form_profiling() {
        // Spec cycle 1: do NOT assume "  \n" -> "\\\n" saves tokens. Measure.
        use tiktoken_rs::o200k_base;
        let bpe = o200k_base().expect("tokenizer");
        let two_space = "line one  \nline two";
        let backslash = "line one\\\nline two";
        let n_space = bpe.encode_with_special_tokens(two_space).len();
        let n_back = bpe.encode_with_special_tokens(backslash).len();
        println!("hard-break tokens: two-space={n_space} backslash={n_back}");
        assert!(n_space > 0 && n_back > 0);
    }
}
