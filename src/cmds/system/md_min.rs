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
