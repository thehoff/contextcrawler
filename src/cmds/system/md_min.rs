//! `md-min` — markdown minifier with additive strip tiers.
//!
//! Tier 0 is the post-parser re-serialised baseline. Tiers 1-4 add
//! progressively more aggressive event deletions. See
//! `docs/superpowers/specs/2026-05-21-md-min-viability-design.md`.

use anyhow::{Context, Result};
use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};

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

/// Tier 1: drop HTML comments. Block comments arrive as a `HtmlBlock`
/// container with one `Html` event per line — only the first line starts
/// with `<!--`, so the whole container must be tracked statefully, not
/// filtered line by line. Inline comments are a single `InlineHtml` event.
///
/// Hard-break form: profiling (see `hard_break_form_profiling` test) showed
/// two-space=5 tokens vs backslash=5 tokens — identical cost on o200k_base.
/// No rewrite is applied; hard breaks are left as the parser emits them.
fn strip_tier1(events: Vec<Event>) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::with_capacity(events.len());
    let mut in_comment_block = false;
    for e in events {
        match &e {
            Event::Html(html)
                if !in_comment_block && html.trim_start().starts_with("<!--") =>
            {
                // First line of a block comment — drop it, and also pop the
                // `Start(HtmlBlock)` container we already pushed.
                if matches!(out.last(), Some(Event::Start(Tag::HtmlBlock))) {
                    out.pop();
                }
                in_comment_block = true;
            }
            Event::Html(_) if in_comment_block => { /* continuation line — drop */ }
            Event::End(TagEnd::HtmlBlock) if in_comment_block => {
                in_comment_block = false; // end of comment block — drop
            }
            Event::InlineHtml(html) if html.trim_start().starts_with("<!--") => {
                /* inline comment — drop */
            }
            _ => out.push(e),
        }
    }
    out
}

/// Tier 2: drop emphasis/strong/strikethrough delimiters (inner text kept)
/// and thematic breaks.
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

/// Tier 3: drop heading hashes and blockquote markers, and reduce links and
/// images to `text url` plain text. The URL is always kept because it is payload.
fn strip_tier3(events: Vec<Event>) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::with_capacity(events.len());
    let mut link_urls: Vec<CowStr> = Vec::new();
    for e in events {
        match e {
            Event::Start(Tag::Heading { .. }) => out.push(Event::Start(Tag::Paragraph)),
            Event::End(TagEnd::Heading(_)) => out.push(Event::End(TagEnd::Paragraph)),
            Event::Start(Tag::BlockQuote(_)) | Event::End(TagEnd::BlockQuote(_)) => {}
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                link_urls.push(dest_url)
            }
            Event::End(TagEnd::Link | TagEnd::Image) => {
                // Parser guarantees balanced tags, so the stack is non-empty here for
                // every real document; `if let` is a defensive no-op otherwise.
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

/// Tier 4: flatten list structure and strip the code-fence language tag.
fn strip_tier4(events: Vec<Event>) -> Vec<Event> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::Start(Tag::List(_)) | Event::End(TagEnd::List(_)) => None,
            Event::Start(Tag::Item) => Some(Event::Start(Tag::Paragraph)),
            Event::End(TagEnd::Item) => Some(Event::End(TagEnd::Paragraph)),
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_))) => {
                Some(Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(
                    CowStr::Borrowed(""), // empty string -> serialiser emits a bare fence with no language tag
                ))))
            }
            other => Some(other),
        })
        .collect()
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
    fn tier1_drops_multiline_html_comments() {
        let input = "Before.\n\n<!--\nhidden body\nmore hidden\n-->\n\nAfter.\n";
        let out = minify(input, Tier::One);
        assert!(!out.contains("hidden body"), "multiline comment body must be dropped");
        assert!(!out.contains("more hidden"));
        assert!(!out.contains("-->"));
        assert!(out.contains("Before."));
        assert!(out.contains("After."));
    }

    #[test]
    fn tier2_strips_emphasis_keeps_text() {
        let input = "A **bold** and _italic_ and ~~struck~~ word.\n\n---\n\nNext.\n";
        let out = minify(input, Tier::Two);
        assert!(out.contains("bold"), "emphasised text must survive");
        assert!(out.contains("italic"));
        assert!(out.contains("struck"));
        assert!(!out.contains("**"), "bold markers must be gone");
        assert!(!out.contains("_italic_"), "underscore emphasis must not be re-emitted");
        assert!(!out.contains("~~"), "strikethrough markers must be gone");
        assert!(!out.contains("---"), "horizontal rule must be gone");
    }

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

    #[test]
    fn tier4_flattens_lists_and_drops_fence_lang() {
        let input = "- one\n- two\n\n```rust\nfn x() {}\n```\n";
        let out = minify(input, Tier::Four);
        assert!(out.contains("one") && out.contains("two"), "item text survives");
        assert!(!out.contains("- one"), "list markers must be gone");
        assert!(out.contains("fn x() {}"), "code body survives verbatim");
        assert!(!out.contains("```rust"), "fence language must be gone");
    }

    #[test]
    fn tier3_strips_image_keeps_url() {
        let input = "An image ![the alt](https://example.com/i.png) here.\n";
        let out = minify(input, Tier::Three);
        assert!(out.contains("the alt"), "image alt text must survive");
        assert!(out.contains("https://example.com/i.png"), "image URL must be kept");
        assert!(!out.contains("!["), "image markup must be gone");
    }

    #[test]
    fn tier3_autolink_url_survives() {
        let input = "Visit <https://example.com/auto> today.\n";
        let out = minify(input, Tier::Three);
        assert!(out.contains("https://example.com/auto"), "autolink URL must survive");
    }

    #[test]
    fn tier4_flattens_ordered_list() {
        let input = "1. first\n2. second\n";
        let out = minify(input, Tier::Four);
        assert!(out.contains("first") && out.contains("second"), "item text survives");
        assert!(!out.contains("1. first"), "ordered list markers must be gone");
    }

    // ── Fixture-based tests (Task 7) ──────────────────────────────────────────

    // Same whitespace-split definition as tests/common/mod.rs — the RTK test-token convention.
    fn count_tokens(s: &str) -> usize {
        s.split_whitespace().count()
    }

    #[test]
    fn every_tier_is_monotonically_smaller_or_equal() {
        let fixtures: &[(&str, &str)] = &[
            ("prose.md", include_str!("../../../tests/fixtures/md/prose.md")),
            ("tables.md", include_str!("../../../tests/fixtures/md/tables.md")),
            ("nested_lists.md", include_str!("../../../tests/fixtures/md/nested_lists.md")),
            ("code_heavy.md", include_str!("../../../tests/fixtures/md/code_heavy.md")),
            ("mixed.md", include_str!("../../../tests/fixtures/md/mixed.md")),
        ];
        for (name, input) in fixtures {
            let sizes: Vec<usize> = [Tier::Zero, Tier::One, Tier::Two, Tier::Three, Tier::Four]
                .iter()
                .map(|t| count_tokens(&minify(input, *t)))
                .collect();
            for w in sizes.windows(2) {
                assert!(
                    w[1] <= w[0],
                    "{name}: each tier must be <= the previous: {sizes:?}"
                );
            }
        }
        // Strict end-to-end reduction on the content-rich mixed fixture confirms
        // the pipeline genuinely reduces, not just shuffles tokens.
        let mixed = include_str!("../../../tests/fixtures/md/mixed.md");
        let tier0 = count_tokens(&minify(mixed, Tier::Zero));
        let tier4 = count_tokens(&minify(mixed, Tier::Four));
        assert!(
            tier4 < tier0,
            "mixed.md: tier4 ({tier4}) must be strictly less than tier0 ({tier0})"
        );
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
            assert!(out.contains("ünïcode"));
            assert!(out.contains("émojis"));
        }
    }

    // ── L2: flattened-text equivalence (Task 8) ───────────────────────────────

    /// Flatten markdown to bare text: concatenate all Text/Code events, drop
    /// all markup, collapse whitespace runs to single spaces.
    ///
    /// Normalisation note (Task 8, case (b)): an inline emphasis span splits a
    /// text run in two at parse time — `**dramatically shorter**.` parses as
    /// `Text("dramatically shorter")` + `Text(".")`, but with the markers
    /// stripped (tier 2+) it re-parses as a single `Text("dramatically
    /// shorter.")`. That moves a space relative to trailing punctuation but
    /// drops/alters no word — a lossless serialiser artifact, not text loss.
    /// To compare flattened text fairly we glue standalone leading punctuation
    /// back onto the preceding word. This is purely a test-side equivalence
    /// normalisation; the stripper itself is unchanged.
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
        let collapsed = buf.split_whitespace().collect::<Vec<_>>().join(" ");
        // Remove the space before a token that is *only* trailing punctuation,
        // so an emphasis-split text run compares equal to its merged form.
        let mut out = String::with_capacity(collapsed.len());
        for tok in collapsed.split(' ') {
            if !out.is_empty()
                && !tok.is_empty()
                && tok.chars().all(|c| matches!(c, '.' | ',' | ';' | ':' | '!' | '?'))
            {
                out.push_str(tok); // glue punctuation onto the previous word
            } else {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(tok);
            }
        }
        out
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
        for w in &raw_words {
            assert!(t3_words.contains(w), "L2: tier 3 dropped body word {w:?}");
        }
    }

    // ── L1: AST allowed-mutation equivalence (Task 9) ─────────────────────────

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
            Event::Start(Tag::Image { .. }) | Event::End(TagEnd::Image) => "image",
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
                              "heading", "blockquote", "link", "image"],
            Tier::Four => &["html", "emphasis", "strong", "strike", "rule",
                             "heading", "blockquote", "link", "image", "list"],
        }
    }

    #[test]
    fn l1_inline_code_is_never_lost() {
        for fixture in [
            include_str!("../../../tests/fixtures/md/mixed.md"),
            include_str!("../../../tests/fixtures/md/code_heavy.md"),
        ] {
            let raw_codes: Vec<String> = Parser::new_ext(fixture, parser_options())
                .filter_map(|e| match e { Event::Code(s) => Some(s.to_string()), _ => None })
                .collect();
            for t in [Tier::Zero, Tier::One, Tier::Two, Tier::Three, Tier::Four] {
                let stripped_codes: Vec<String> =
                    Parser::new_ext(&minify(fixture, t), parser_options())
                        .filter_map(|e| match e { Event::Code(s) => Some(s.to_string()), _ => None })
                        .collect();
                assert_eq!(raw_codes, stripped_codes, "L1: tier {t:?} altered inline code");
            }
        }
    }

    #[test]
    fn l1_no_undeclared_event_kinds_disappear() {
        let fixture = include_str!("../../../tests/fixtures/md/mixed.md");
        let raw_kinds: std::collections::HashSet<&str> =
            Parser::new_ext(fixture, parser_options()).map(|e| event_kind(&e)).collect();
        for t in [Tier::One, Tier::Two, Tier::Three, Tier::Four] {
            let kinds: std::collections::HashSet<&str> =
                Parser::new_ext(&minify(fixture, t), parser_options())
                    .map(|e| event_kind(&e)).collect();
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
        // Decision recorded: backslash form is not cheaper on o200k_base, so
        // strip_tier1 applies no hard-break rewrite. If this flips, revisit.
        assert!(
            n_back >= n_space,
            "backslash hard-break became cheaper ({n_back} < {n_space}) — \
             strip_tier1 should now rewrite hard breaks"
        );
    }
}
