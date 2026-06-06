//! Runs curl and condenses long output for human consumption.
//!
//! For pipes / redirects (non-TTY) and JSON bodies the full response is passed
//! through unchanged — truncating mid-stream would break downstream parsers.
//! The condensed-form-with-tee-hint path is reserved for non-JSON bodies on
//! a real terminal where a human reads the output and the tee file gives the
//! LLM a way to recover the raw response.

use crate::cmds::cloud::web_cmd;
use crate::core::tee::force_tee_hint;
use crate::core::tracking;
use crate::core::{
    stream::exec_capture,
    utils::{check_forbidden_curl_args, secure_curl_command},
};
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::io::IsTerminal;

const MAX_RESPONSE_SIZE: usize = 500;

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if let Err(msg) = check_forbidden_curl_args(args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    // `secure_curl_command` strips CURL_HOME so a tainted parent env can't
    // inject curl flags via .curlrc on every invocation. See issue #38.
    let mut cmd = secure_curl_command();
    cmd.arg("-s"); // Silent mode (no progress bar)

    for arg in args {
        cmd.arg(arg);
    }

    if verbose > 0 {
        eprintln!("Running: curl -s {}", args.join(" "));
    }

    let result = exec_capture(&mut cmd).context("Failed to run curl")?;

    // Skip filtering on failure: curl can return HTML error bodies that would
    // be misleading to summarize, and we want the real exit code surfaced.
    if !result.success() {
        let msg = if result.stderr.trim().is_empty() {
            result.stdout.trim().to_string()
        } else {
            result.stderr.trim().to_string()
        };
        eprintln!("FAILED: curl {}", msg);
        return Ok(result.exit_code);
    }

    let exit_code = result.exit_code;
    let raw = result.stdout;
    let is_tty = std::io::stdout().is_terminal();
    let filtered = filter_curl_output(&raw, is_tty);

    println!("{}", filtered.content);
    if let Some(hint) = &filtered.tee_hint {
        println!("{}", hint);
    }

    timer.track(
        &format!("curl {}", args.join(" ")),
        &format!("contextcrawler curl {}", args.join(" ")),
        &raw,
        &filtered.content,
    );

    Ok(exit_code)
}

fn filter_curl_output(raw: &str, is_tty: bool) -> FilterResult<'_> {
    let trimmed = raw.trim();

    // HTML bodies: run through the chrome-stripping extractor so a page that is
    // mostly nav / script / styling collapses to its readable text. This is the
    // largest raw-token recovery opportunity for curl (#194) — agentic callers
    // capture HTML pages and only the prose matters.
    //
    // Extraction is lossy (it discards markup), so it is gated two ways:
    //   1. `runner::no_bloat` — if the extracted text is not actually smaller
    //      than the raw body (tiny / markup-light pages), emit the raw body.
    //   2. Empty result — a page with no extractable text (all chrome) falls
    //      back to raw rather than printing nothing.
    // Both guards uphold the fallback rule: never block or starve the user.
    if web_cmd::is_html(trimmed) {
        let extracted = web_cmd::extract_content(trimmed);
        // no_bloat guard: only keep the extraction when it is genuinely fewer
        // tokens than the raw body, and only when it is non-empty. Comparing the
        // estimates directly (rather than `runner::no_bloat`, which needs both
        // arms to share a lifetime) keeps the borrow on `trimmed` for the
        // passthrough case.
        if !extracted.trim().is_empty()
            && tracking::estimate_tokens(&extracted) < tracking::estimate_tokens(trimmed)
        {
            return FilterResult {
                content: Cow::Owned(extracted),
                tee_hint: None,
            };
        }
        // Extraction didn't help (empty, or not smaller): fall through to the
        // generic passthrough/truncation path so the user still sees the body.
    }

    // Heuristic: looks like a top-level JSON document. Numbers / booleans / null
    // are always under MAX_RESPONSE_SIZE so they don't need detection here.
    let looks_like_json = (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2);

    // JSON bodies: minify losslessly rather than pass through whole. Re-serialised
    // JSON is still valid JSON (preserve_order keeps key ordering stable), so a
    // downstream `curl ... | jq` keeps working — unlike mid-stream truncation,
    // which is why #1536 left JSON untouched. If the body isn't strictly
    // parseable, or is already minimal, fall through to plain passthrough.
    if looks_like_json {
        return match minify_json(trimmed) {
            Some(min) => FilterResult {
                content: Cow::Owned(min),
                tee_hint: None,
            },
            None => FilterResult {
                content: Cow::Borrowed(trimmed),
                tee_hint: None,
            },
        };
    }

    // Pass through unchanged when:
    // - stdout is not a terminal (pipes / redirects need the full body, #1282)
    // - body fits under the truncation threshold
    //
    // Critically, do NOT call `force_tee_hint` on this path — it has a side effect
    // (writes the raw body to a tee log file) and we don't need a recovery file
    // when the consumer already receives the full body.
    if !is_tty || trimmed.len() < MAX_RESPONSE_SIZE {
        return FilterResult {
            content: Cow::Borrowed(trimmed),
            tee_hint: None,
        };
    }

    // We're about to truncate for a human reader. Write a tee file so they (or
    // the LLM in their stead) can recover the full body from the printed hint.
    let Some(hint) = force_tee_hint(raw, "curl") else {
        // Tee disabled (CTXCRL_TEE=0 or below MIN_TEE_SIZE): we have nowhere to
        // point a recovery hint to, so pass through rather than emit an
        // unrecoverable truncation marker.
        return FilterResult {
            content: Cow::Borrowed(trimmed),
            tee_hint: None,
        };
    };

    let mut end = MAX_RESPONSE_SIZE;
    // Don't cut in the middle of a UTF-8 character — .len() counts bytes.
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    FilterResult {
        content: Cow::Owned(format!(
            "{}... ({} bytes total)",
            &trimmed[..end],
            trimmed.len()
        )),
        tee_hint: Some(hint),
    }
}

struct FilterResult<'a> {
    content: Cow<'a, str>,
    tee_hint: Option<String>,
}

/// Losslessly minify a JSON body by stripping insignificant whitespace only.
///
/// A serde parse/re-serialise round-trip is *not* lossless: numbers beyond f64
/// precision (e.g. a JS millisecond timestamp with a fractional part like
/// `1779167626250.6921`) get truncated when serde re-emits the parsed `f64`.
/// So this validates the body with serde but then strips whitespace *textually*
/// — numbers, key order and string contents stay byte-identical.
///
/// Returns `None` when the body isn't strictly-valid JSON (caller passes it
/// through untouched) or when stripping wouldn't shrink it (already-compact —
/// avoids a needless `Cow::Owned` clone of a multi-MB body).
fn minify_json(raw: &str) -> Option<String> {
    // Validity gate: only minify well-formed JSON. A malformed body passes
    // through untouched rather than getting its whitespace mangled.
    if serde_json::from_str::<serde::de::IgnoredAny>(raw).is_err() {
        return None;
    }

    // Strip whitespace outside string literals. The validity gate above
    // guarantees every string is terminated, so the scan can't run off the end.
    let mut out = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            out.push(ch);
        } else if !matches!(ch, ' ' | '\t' | '\n' | '\r') {
            out.push(ch);
        }
    }

    if out.len() < raw.len() {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_tokens(text: &str) -> usize {
        text.split_whitespace().count()
    }

    // --- #194: HTML response bodies routed through the chrome-stripping
    // extractor. The big curl token-recovery opportunity. ---

    #[test]
    fn test_filter_curl_html_is_extracted() {
        // A page that is mostly chrome (nav/footer/script) collapses to its
        // readable text. Works regardless of TTY — agentic callers pipe.
        let html = r#"<!DOCTYPE html>
<html>
<head><script>var t=1;</script><style>body{color:red}</style></head>
<body>
  <nav><a href="/">Home</a><a href="/about">About</a></nav>
  <main>
    <h1>Article Title</h1>
    <p>The single paragraph of actual content that matters.</p>
  </main>
  <footer>Copyright 2026 Example Corp. All rights reserved.</footer>
</body>
</html>"#;
        for is_tty in [true, false] {
            let result = filter_curl_output(html, is_tty);
            assert!(
                result.content.contains("Article Title"),
                "extracted content kept (tty={is_tty})"
            );
            assert!(result.content.contains("actual content that matters"));
            assert!(!result.content.contains("var t=1"), "script stripped");
            assert!(!result.content.contains("Home"), "nav stripped");
            assert!(!result.content.contains("Copyright"), "footer stripped");
            assert!(result.tee_hint.is_none());
            assert!(matches!(result.content, Cow::Owned(_)));
        }
    }

    #[test]
    fn test_filter_curl_real_html_fixture_savings() {
        // Real captured page (https://www.rust-lang.org/). HTML extraction must
        // hit >=60% token savings per the project's filter contract.
        let raw = include_str!("../../../tests/fixtures/curl/html_page_raw.html");
        let result = filter_curl_output(raw, false);
        let raw_tokens = count_tokens(raw);
        let out_tokens = count_tokens(&result.content);
        let savings = 100.0 - (out_tokens as f64 / raw_tokens as f64 * 100.0);
        assert!(
            savings >= 60.0,
            "HTML extraction expected >=60% token savings, got {savings:.1}% \
             (raw={raw_tokens} -> out={out_tokens})"
        );
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_real_json_fixture_savings() {
        // Real captured GitHub API response (pretty-printed). Lossless minify
        // strips insignificant whitespace and must remain valid JSON.
        let raw = include_str!("../../../tests/fixtures/curl/json_response_raw.json");
        let result = filter_curl_output(raw, false);
        assert!(
            serde_json::from_str::<serde_json::Value>(&result.content).is_ok(),
            "minified JSON must stay parseable"
        );
        assert!(
            result.content.len() < raw.len(),
            "pretty JSON must shrink after minify"
        );
        let raw_val: serde_json::Value = serde_json::from_str(raw).unwrap();
        let out_val: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(raw_val, out_val, "minify is lossless");
    }

    #[test]
    fn test_filter_curl_html_no_extractable_text_falls_back() {
        // HTML with no real text content: extraction is empty, so we fall back
        // to the generic passthrough (never print nothing).
        let html = "<!DOCTYPE html><html><body><nav><a href=\"/\">x</a></nav></body></html>";
        let result = filter_curl_output(html, false);
        // Non-TTY + under cap → borrowed passthrough of the raw body.
        assert_eq!(&*result.content, html.trim());
    }

    #[test]
    fn test_filter_curl_html_small_body_still_extracts() {
        // Even a tiny page strips its tags — stripping markup always reduces
        // the char/4 token estimate, so the no_bloat guard keeps the extraction.
        let html = "<html><body>hi there</body></html>";
        let result = filter_curl_output(html, false);
        assert_eq!(&*result.content, "hi there");
        assert!(matches!(result.content, Cow::Owned(_)));
        // Guard sanity: extraction really is the smaller of the two.
        assert!(tracking::estimate_tokens(&result.content) < tracking::estimate_tokens(html));
    }

    #[test]
    fn test_filter_curl_json_small_no_tee_hint() {
        let output = r#"{"r2Ready":true,"status":"ok"}"#;
        let result = filter_curl_output(output, true);
        assert_eq!(&*result.content, output);
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_non_json() {
        let output = "Hello, World!\nThis is plain text.";
        let result = filter_curl_output(output, true);
        assert_eq!(&*result.content, output);
    }

    #[test]
    fn test_filter_curl_long_output_truncated() {
        let long: String = "x".repeat(1000);
        let result = filter_curl_output(&long, true);
        assert!(result.content.starts_with('x'));
        assert!(result.content.contains("bytes total"));
        assert!(result.content.contains("1000"));
        assert!(result.content.len() < 600);
        assert!(result.tee_hint.is_some(), "TTY truncation must emit a hint");
    }

    #[test]
    fn test_filter_curl_multibyte_boundary() {
        let content = "a".repeat(499) + "é";
        let result = filter_curl_output(&content, true);
        assert!(result.content.contains("bytes total"));
        assert!(result.content.len() < 600);
    }

    #[test]
    fn test_filter_curl_exact_500_bytes() {
        let content = "a".repeat(500);
        let result = filter_curl_output(&content, true);
        assert!(result.content.contains("bytes total"));
    }

    // --- #1536: large JSON must remain parseable for downstream tools ---

    #[test]
    fn test_filter_curl_large_json_object_passthrough() {
        let payload = "x".repeat(600);
        let json = format!(r#"{{"data":"{}"}}"#, payload);
        let result = filter_curl_output(&json, true);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.starts_with('{'));
        assert!(result.content.ends_with('}'));
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_large_json_array_passthrough() {
        let body = (0..50)
            .map(|i| format!(r#"{{"id":{},"name":"item-{:04}"}}"#, i, i))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{}]", body);
        assert!(
            json.len() >= MAX_RESPONSE_SIZE,
            "fixture must exceed cap, got {}",
            json.len()
        );
        let result = filter_curl_output(&json, true);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.starts_with('['));
        assert!(result.content.ends_with(']'));
    }

    #[test]
    fn test_filter_curl_large_json_bare_string_passthrough() {
        // Bare top-level JSON string — e.g. an /api/token endpoint returning "<long-token>".
        let token = "z".repeat(800);
        let json = format!(r#""{}""#, token);
        let result = filter_curl_output(&json, true);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.starts_with('"'));
        assert!(result.content.ends_with('"'));
    }

    // --- #1282: pipes / redirects (non-TTY) must receive full body ---

    #[test]
    fn test_filter_curl_pipe_no_truncation_for_non_json() {
        let long: String = "x".repeat(1000);
        let result = filter_curl_output(&long, false);
        assert!(!result.content.contains("bytes total"));
        assert_eq!(result.content.len(), 1000);
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_pipe_no_truncation_for_json() {
        let payload = "y".repeat(600);
        let json = format!(r#"{{"data":"{}"}}"#, payload);
        let result = filter_curl_output(&json, false);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.ends_with('}'));
        assert!(result.tee_hint.is_none());
    }

    // --- Tier 1: lossless JSON minification ---

    #[test]
    fn test_filter_curl_pretty_json_is_minified() {
        // Pretty-printed JSON in → minified, still valid, smaller.
        let pretty = "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2,\n    3\n  ]\n}";
        let result = filter_curl_output(pretty, true);
        assert_eq!(&*result.content, r#"{"a":1,"b":[1,2,3]}"#);
        assert!(result.content.len() < pretty.len());
        assert!(result.tee_hint.is_none());
        // Output must round-trip as valid JSON (the whole point vs truncation).
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_pretty_json_minified_on_pipe_too() {
        // Minification is lossless, so it applies on non-TTY (pipe to jq) as
        // well — jq receives valid, smaller JSON.
        let pretty = "[\n  {\n    \"id\": 1\n  }\n]";
        let result = filter_curl_output(pretty, false);
        assert_eq!(&*result.content, r#"[{"id":1}]"#);
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_already_minified_json_passthrough_borrowed() {
        // Already-compact JSON: minify_json returns None → borrowed passthrough,
        // no needless allocation.
        let compact = r#"{"a":1,"b":[1,2,3]}"#;
        let result = filter_curl_output(compact, true);
        assert_eq!(&*result.content, compact);
        assert!(matches!(result.content, Cow::Borrowed(_)));
    }

    #[test]
    fn test_filter_curl_malformed_json_passthrough() {
        // Looks JSON-ish (starts { ends }) but isn't valid → must pass through
        // untouched rather than risk corrupting it.
        let bad = "{not: valid, json at all}";
        let result = filter_curl_output(bad, true);
        assert_eq!(&*result.content, bad);
        assert!(matches!(result.content, Cow::Borrowed(_)));
    }

    #[test]
    fn test_filter_curl_minified_json_preserves_key_order() {
        // Textual whitespace stripping keeps keys in source order trivially.
        let pretty = "{\n  \"zebra\": 1,\n  \"apple\": 2,\n  \"mango\": 3\n}";
        let result = filter_curl_output(pretty, true);
        assert_eq!(&*result.content, r#"{"zebra":1,"apple":2,"mango":3}"#);
    }

    #[test]
    fn test_filter_curl_json_preserves_float_precision() {
        // Regression: a serde parse/re-serialise round-trip drops precision on
        // numbers beyond f64 range — e.g. a JS millisecond timestamp with a
        // fractional part. Textual minification keeps the digits byte-identical.
        let raw = "{\n  \"lastSession\": 1779167626250.6921\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, r#"{"lastSession":1779167626250.6921}"#);
        assert!(result.content.contains("1779167626250.6921"));
    }

    #[test]
    fn test_filter_curl_json_preserves_whitespace_inside_strings() {
        // Whitespace inside a string literal is significant — must survive.
        let raw = "{\n  \"msg\": \"hello   world\\ttab\"\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, "{\"msg\":\"hello   world\\ttab\"}");
    }

    #[test]
    fn test_filter_curl_json_escaped_quote_in_string() {
        // An escaped quote must not be misread as the string terminator.
        let raw = "{\n  \"q\": \"she said \\\"hi\\\"\"\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, "{\"q\":\"she said \\\"hi\\\"\"}");
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_json_braces_and_whitespace_inside_string_value() {
        // A string value containing JSON-structural characters AND runs of
        // whitespace — none of it must be touched. This is the case that
        // would break a naive "strip all whitespace" minifier.
        let raw = "{\n  \"tpl\": \"{  \\\"k\\\":  1  }\"\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, "{\"tpl\":\"{  \\\"k\\\":  1  }\"}");
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_json_preserves_unicode() {
        let raw = "{\n  \"name\": \"café \\u00e9 日本語 🎉\"\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, "{\"name\":\"café \\u00e9 日本語 🎉\"}");
    }

    #[test]
    fn test_filter_curl_json_preserves_number_forms() {
        // Negative, exponent, zero, high-precision fraction — all byte-exact.
        let raw = "{\n  \"neg\": -42,\n  \"exp\": 6.022e23,\n  \"zero\": 0,\n  \"frac\": 0.1234567890123456\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(
            &*result.content,
            r#"{"neg":-42,"exp":6.022e23,"zero":0,"frac":0.1234567890123456}"#
        );
    }

    #[test]
    fn test_filter_curl_json_nested_structure_minified() {
        let raw = "{\n  \"a\": {\n    \"b\": {\n      \"c\": [\n        1,\n        2\n      ]\n    }\n  }\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, r#"{"a":{"b":{"c":[1,2]}}}"#);
    }

    #[test]
    fn test_filter_curl_json_escaped_backslash_before_quote() {
        // Trailing escaped backslash inside a string: the `\\` must not let the
        // following `"` be misread as still-inside-string.
        let raw = "{\n  \"path\": \"C:\\\\dir\\\\\"\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, "{\"path\":\"C:\\\\dir\\\\\"}");
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_json_literal_escape_sequences_in_string() {
        // `\n` `\t` inside the JSON string are two-char escape sequences, not
        // real whitespace — they must survive verbatim.
        let raw = "{\n  \"s\": \"line1\\nline2\\tcol\"\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, "{\"s\":\"line1\\nline2\\tcol\"}");
    }

    #[test]
    fn test_filter_curl_json_empty_object_and_array_passthrough() {
        // Already minimal — minify_json returns None → borrowed passthrough.
        for body in ["{}", "[]", r#"{"a":[]}"#] {
            let result = filter_curl_output(body, true);
            assert_eq!(&*result.content, body);
            assert!(matches!(result.content, Cow::Borrowed(_)));
        }
    }

    #[test]
    fn test_filter_curl_json_crlf_whitespace_stripped() {
        // Windows-style CRLF indentation is insignificant whitespace too.
        let raw = "{\r\n  \"a\": 1\r\n}";
        let result = filter_curl_output(raw, true);
        assert_eq!(&*result.content, r#"{"a":1}"#);
    }

    #[test]
    fn test_filter_curl_json_minified_roundtrips_semantically() {
        // The whole contract: filtered JSON parses to the SAME value as raw.
        let raw = "{\n  \"id\": 7,\n  \"tags\": [\"x\", \"y\"],\n  \"meta\": {\"ok\": true}\n}";
        let result = filter_curl_output(raw, true);
        let raw_val: serde_json::Value = serde_json::from_str(raw).unwrap();
        let filt_val: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(raw_val, filt_val, "minified JSON must be the same value as raw");
    }

    // --- Cow optimization: passthrough must not allocate ---

    #[test]
    fn test_filter_curl_passthrough_is_borrowed() {
        // Passthrough paths return Cow::Borrowed to avoid copying multi-MB bodies.
        let pipe_payload = "x".repeat(2000);
        let pipe_result = filter_curl_output(&pipe_payload, false);
        assert!(matches!(pipe_result.content, Cow::Borrowed(_)));

        let json_payload = format!(r#"[{}]"#, "1,".repeat(300));
        let json_result = filter_curl_output(&json_payload, true);
        assert!(matches!(json_result.content, Cow::Borrowed(_)));
    }
}
