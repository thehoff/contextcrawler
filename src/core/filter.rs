//! Strips comments and boilerplate from source code to save tokens.

use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterLevel {
    None,
    Minimal,
    Aggressive,
}

impl FromStr for FilterLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(FilterLevel::None),
            "minimal" => Ok(FilterLevel::Minimal),
            "aggressive" => Ok(FilterLevel::Aggressive),
            _ => Err(format!("Unknown filter level: {}", s)),
        }
    }
}

impl std::fmt::Display for FilterLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterLevel::None => write!(f, "none"),
            FilterLevel::Minimal => write!(f, "minimal"),
            FilterLevel::Aggressive => write!(f, "aggressive"),
        }
    }
}

pub trait FilterStrategy {
    fn filter(&self, content: &str, lang: &Language) -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    C,
    Cpp,
    Java,
    Ruby,
    Shell,
    /// Data formats (JSON, YAML, TOML, XML, CSV) — no comment stripping
    Data,
    Unknown,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "rs" => Language::Rust,
            "py" | "pyw" => Language::Python,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" => Language::TypeScript,
            "go" => Language::Go,
            "c" | "h" => Language::C,
            "cpp" | "cc" | "cxx" | "hpp" | "hh" => Language::Cpp,
            "java" => Language::Java,
            "rb" => Language::Ruby,
            "sh" | "bash" | "zsh" => Language::Shell,
            "json" | "jsonc" | "json5" | "yaml" | "yml" | "toml" | "xml" | "csv" | "tsv"
            | "graphql" | "gql" | "sql" | "md" | "markdown" | "txt" | "env" | "lock"
            | "xcstrings" | "geojson" | "ipynb" | "webmanifest"
            // `code-workspace` covers VS Code workspace files; `workspace`
            // covers JetBrains/Theia project workspace files (also JSON).
            | "code-workspace" | "workspace" => {
                Language::Data
            }
            _ => Language::Unknown,
        }
    }

    pub fn comment_patterns(&self) -> CommentPatterns {
        match self {
            Language::Rust => CommentPatterns {
                line: Some("//"),
                block_start: Some("/*"),
                block_end: Some("*/"),
                doc_line: Some("///"),
                doc_block_start: Some("/**"),
            },
            Language::Python => CommentPatterns {
                line: Some("#"),
                block_start: Some("\"\"\""),
                block_end: Some("\"\"\""),
                doc_line: None,
                doc_block_start: Some("\"\"\""),
            },
            Language::JavaScript
            | Language::TypeScript
            | Language::Go
            | Language::C
            | Language::Cpp
            | Language::Java => CommentPatterns {
                line: Some("//"),
                block_start: Some("/*"),
                block_end: Some("*/"),
                doc_line: None,
                doc_block_start: Some("/**"),
            },
            Language::Ruby => CommentPatterns {
                line: Some("#"),
                block_start: Some("=begin"),
                block_end: Some("=end"),
                doc_line: None,
                doc_block_start: None,
            },
            Language::Shell => CommentPatterns {
                line: Some("#"),
                block_start: None,
                block_end: None,
                doc_line: None,
                doc_block_start: None,
            },
            Language::Data => CommentPatterns {
                line: None,
                block_start: None,
                block_end: None,
                doc_line: None,
                doc_block_start: None,
            },
            Language::Unknown => CommentPatterns {
                line: Some("//"),
                block_start: Some("/*"),
                block_end: Some("*/"),
                doc_line: None,
                doc_block_start: None,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommentPatterns {
    pub line: Option<&'static str>,
    pub block_start: Option<&'static str>,
    pub block_end: Option<&'static str>,
    pub doc_line: Option<&'static str>,
    pub doc_block_start: Option<&'static str>,
}

pub struct NoFilter;

impl FilterStrategy for NoFilter {
    fn filter(&self, content: &str, _lang: &Language) -> String {
        content.to_string()
    }
}

pub struct MinimalFilter;

lazy_static! {
    static ref MULTIPLE_BLANK_LINES: Regex = Regex::new(r"\n{3,}").unwrap();
    static ref TRAILING_WHITESPACE: Regex = Regex::new(r"[ \t]+$").unwrap();
}

#[derive(Clone, Copy)]
enum LiteralState {
    Quoted {
        quote: u8,
        escaped: bool,
    },
    Backtick {
        honours_escapes: bool,
        escaped: bool,
    },
    RustRaw {
        hashes: usize,
    },
}

#[derive(Default)]
struct CLikeScanState {
    in_block_comment: bool,
    literal: Option<LiteralState>,
}

struct CLikeScanResult {
    code: String,
    brace_delta: i32,
    first_open_brace: Option<usize>,
}

fn uses_c_like_comments(lang: &Language) -> bool {
    matches!(
        lang,
        Language::Rust
            | Language::JavaScript
            | Language::TypeScript
            | Language::Go
            | Language::C
            | Language::Cpp
            | Language::Java
            | Language::Unknown
    )
}

fn char_len_at(text: &str, index: usize) -> usize {
    text[index..].chars().next().map_or(1, char::len_utf8)
}

/// Return `(opening byte length, hash count)` for a Rust `r#"..."#` or
/// `br#"..."#` opener at `index`.
fn rust_raw_string_start(line: &str, index: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let prefix_len = if bytes.get(index) == Some(&b'r') {
        1
    } else if bytes.get(index) == Some(&b'b') && bytes.get(index + 1) == Some(&b'r') {
        2
    } else {
        return None;
    };

    if index > 0 {
        let previous = bytes[index - 1];
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            return None;
        }
    }

    let mut cursor = index + prefix_len;
    let mut hashes = 0usize;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'"') {
        Some((cursor + 1 - index, hashes))
    } else {
        None
    }
}

/// Scan one C-family source line while carrying block-comment and multiline
/// literal state. The returned code has only genuine `/* ... */` spans
/// removed; brace metadata counts braces in executable syntax, not strings or
/// comments. This shared lexer keeps MinimalFilter and AggressiveFilter in
/// agreement about JS/TS templates, Go raw strings, and Rust raw strings.
fn scan_c_like_line(line: &str, lang: &Language, state: &mut CLikeScanState) -> CLikeScanResult {
    let bytes = line.as_bytes();
    let mut code = String::with_capacity(line.len());
    let mut brace_delta = 0i32;
    let mut first_open_brace = None;
    let mut i = 0usize;

    while i < bytes.len() {
        if state.in_block_comment {
            if bytes.get(i) == Some(&b'*') && bytes.get(i + 1) == Some(&b'/') {
                state.in_block_comment = false;
                i += 2;
            } else {
                i += char_len_at(line, i);
            }
            continue;
        }

        if let Some(literal) = state.literal {
            match literal {
                LiteralState::Quoted { quote, escaped } => {
                    let current = bytes[i];
                    let len = char_len_at(line, i);
                    code.push_str(&line[i..i + len]);
                    state.literal = if escaped {
                        Some(LiteralState::Quoted {
                            quote,
                            escaped: false,
                        })
                    } else if current == b'\\' {
                        Some(LiteralState::Quoted {
                            quote,
                            escaped: true,
                        })
                    } else if current == quote {
                        None
                    } else {
                        Some(LiteralState::Quoted {
                            quote,
                            escaped: false,
                        })
                    };
                    i += len;
                }
                LiteralState::Backtick {
                    honours_escapes,
                    escaped,
                } => {
                    let current = bytes[i];
                    let len = char_len_at(line, i);
                    code.push_str(&line[i..i + len]);
                    state.literal = if honours_escapes && escaped {
                        Some(LiteralState::Backtick {
                            honours_escapes,
                            escaped: false,
                        })
                    } else if honours_escapes && current == b'\\' {
                        Some(LiteralState::Backtick {
                            honours_escapes,
                            escaped: true,
                        })
                    } else if current == b'`' {
                        None
                    } else {
                        Some(LiteralState::Backtick {
                            honours_escapes,
                            escaped: false,
                        })
                    };
                    i += len;
                }
                LiteralState::RustRaw { hashes } => {
                    if bytes[i] == b'"'
                        && i + 1 + hashes <= bytes.len()
                        && bytes[i + 1..i + 1 + hashes]
                            .iter()
                            .all(|byte| *byte == b'#')
                    {
                        let end = i + 1 + hashes;
                        code.push_str(&line[i..end]);
                        state.literal = None;
                        i = end;
                    } else {
                        let len = char_len_at(line, i);
                        code.push_str(&line[i..i + len]);
                        i += len;
                    }
                }
            }
            continue;
        }

        if bytes.get(i) == Some(&b'/') && bytes.get(i + 1) == Some(&b'/') {
            // Preserve the line comment for the caller's doc-comment handling,
            // but stop lexical scanning so braces and /* inside it are inert.
            code.push_str(&line[i..]);
            break;
        }

        if bytes.get(i) == Some(&b'/') && bytes.get(i + 1) == Some(&b'*') {
            state.in_block_comment = true;
            i += 2;
            continue;
        }

        if *lang == Language::Rust {
            if let Some((opening_len, hashes)) = rust_raw_string_start(line, i) {
                code.push_str(&line[i..i + opening_len]);
                state.literal = Some(LiteralState::RustRaw { hashes });
                i += opening_len;
                continue;
            }
        }

        let current = bytes[i];
        if current == b'"' || current == b'\'' {
            code.push(current as char);
            state.literal = Some(LiteralState::Quoted {
                quote: current,
                escaped: false,
            });
            i += 1;
            continue;
        }

        if current == b'`'
            && matches!(
                lang,
                Language::JavaScript | Language::TypeScript | Language::Go
            )
        {
            code.push('`');
            state.literal = Some(LiteralState::Backtick {
                honours_escapes: *lang != Language::Go,
                escaped: false,
            });
            i += 1;
            continue;
        }

        if current == b'{' {
            brace_delta += 1;
            first_open_brace.get_or_insert(i);
        } else if current == b'}' {
            brace_delta -= 1;
        }

        let len = char_len_at(line, i);
        code.push_str(&line[i..i + len]);
        i += len;
    }

    // Ordinary quoted strings cannot span a physical line unless the final
    // backslash escapes its newline. Reset malformed/unclosed quotes here so a
    // stray quote cannot suppress comment handling for the rest of the file.
    if let Some(LiteralState::Quoted { quote, escaped }) = state.literal {
        state.literal = if escaped {
            Some(LiteralState::Quoted {
                quote,
                escaped: false,
            })
        } else {
            None
        };
    }
    if let Some(LiteralState::Backtick {
        honours_escapes: true,
        escaped: true,
    }) = state.literal
    {
        state.literal = Some(LiteralState::Backtick {
            honours_escapes: true,
            escaped: false,
        });
    }

    CLikeScanResult {
        code,
        brace_delta,
        first_open_brace,
    }
}

fn python_docstring_delimiter(line: &str) -> Option<&'static str> {
    let bytes = line.as_bytes();
    let mut prefix_len = 0usize;
    while prefix_len < 2
        && bytes
            .get(prefix_len)
            .is_some_and(|byte| matches!(byte.to_ascii_lowercase(), b'r' | b'f' | b'u' | b'b'))
    {
        prefix_len += 1;
    }

    let rest = &line[prefix_len..];
    if rest.starts_with("\"\"\"") {
        Some("\"\"\"")
    } else if rest.starts_with("'''") {
        Some("'''")
    } else {
        None
    }
}

impl FilterStrategy for MinimalFilter {
    fn filter(&self, content: &str, lang: &Language) -> String {
        let patterns = lang.comment_patterns();
        let mut result = String::with_capacity(content.len());
        let mut c_like_state = CLikeScanState::default();
        let mut in_block_comment = false;
        let mut in_docstring: Option<&'static str> = None;

        // C-style `/* ... */` block comments get the quote-aware span scanner.
        // Other "block" markers (`"""` for Python, `=begin`/`=end` for Ruby)
        // are handled by their own dedicated paths below.
        let c_style_block = patterns.block_start == Some("/*") && patterns.block_end == Some("*/");

        for line in content.lines() {
            let trimmed = line.trim();

            // --- Python docstrings (prefixed triple quotes, kept in minimal mode) ---
            if *lang == Language::Python {
                if let Some(delimiter) = in_docstring {
                    if line.matches(delimiter).count() % 2 == 1 {
                        in_docstring = None;
                    }
                    result.push_str(line);
                    result.push('\n');
                    continue;
                }

                if let Some(delimiter) = python_docstring_delimiter(trimmed) {
                    // A one-line triple-quoted string has two delimiters and
                    // therefore does not latch multiline state.
                    if trimmed.matches(delimiter).count() % 2 == 1 {
                        in_docstring = Some(delimiter);
                    }
                    result.push_str(line);
                    result.push('\n');
                    continue;
                }
            }

            // --- Ruby block comments (=begin/=end, line-anchored) ---
            if patterns.block_start == Some("=begin") {
                if !in_block_comment && trimmed.starts_with("=begin") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.starts_with("=end") {
                        in_block_comment = false;
                    }
                    continue;
                }
            }

            // --- Doc block comments (`/** ... */`): preserve verbatim ---
            // These carry API documentation; matching prior behaviour we keep
            // the whole line rather than scanning it as a strippable comment.
            if c_style_block && !in_block_comment {
                if let Some(doc_start) = patterns.doc_block_start {
                    if trimmed.starts_with(doc_start) {
                        result.push_str(line);
                        result.push('\n');
                        continue;
                    }
                }
            }

            // --- C-style block comments: strip only the commented span ---
            let effective = if c_style_block {
                let scan = scan_c_like_line(line, lang, &mut c_like_state);
                in_block_comment = c_like_state.in_block_comment;
                scan.code
            } else {
                line.to_string()
            };
            let eff_trimmed = effective.trim();

            // Nothing survived the strip.
            if eff_trimmed.is_empty() {
                if !trimmed.is_empty() {
                    // The line was entirely block comment — drop it.
                    continue;
                }
                // Genuine blank line — normalize later.
                result.push('\n');
                continue;
            }

            // Skip single-line comments (but keep doc comments)
            if let Some(line_comment) = patterns.line {
                if eff_trimmed.starts_with(line_comment) {
                    // Keep doc comments
                    if let Some(doc) = patterns.doc_line {
                        if eff_trimmed.starts_with(doc) {
                            result.push_str(&effective);
                            result.push('\n');
                        }
                    }
                    continue;
                }
            }

            result.push_str(&effective);
            result.push('\n');
        }

        // Normalize multiple blank lines to max 2
        let result = MULTIPLE_BLANK_LINES.replace_all(&result, "\n\n");
        result.trim().to_string()
    }
}

pub struct AggressiveFilter;

lazy_static! {
    static ref IMPORT_PATTERN: Regex =
        Regex::new(r"^(use |import |from |require\(|#include)").unwrap();
    static ref FUNC_SIGNATURE: Regex = Regex::new(
        r"^(pub\s+)?(async\s+)?(?:(fn|def|function|class|struct|enum|trait|interface|type)\s+\w+|func\s+(?:\([^)]*\)\s*)?\w+)"
    )
    .unwrap();
}

impl FilterStrategy for AggressiveFilter {
    fn filter(&self, content: &str, lang: &Language) -> String {
        // Data formats (JSON, YAML, etc.) must never be code-filtered
        if *lang == Language::Data {
            return MinimalFilter.filter(content, lang);
        }

        let minimal = MinimalFilter.filter(content, lang);
        let mut result = String::with_capacity(minimal.len() / 2);
        let mut brace_depth = 0;
        let mut in_impl_body = false;
        let mut brace_state = CLikeScanState::default();

        for line in minimal.lines() {
            let trimmed = line.trim();
            let brace_scan =
                uses_c_like_comments(lang).then(|| scan_c_like_line(line, lang, &mut brace_state));
            let brace_delta = brace_scan.as_ref().map_or(0, |scan| scan.brace_delta);

            // Always keep imports
            if IMPORT_PATTERN.is_match(trimmed) {
                result.push_str(line);
                result.push('\n');
                continue;
            }

            // Always keep function/struct/class signatures
            if FUNC_SIGNATURE.is_match(trimmed) {
                let first_open = brace_scan.as_ref().and_then(|scan| scan.first_open_brace);
                let has_inline_body = first_open
                    .is_some_and(|open| line[open + 1..].trim().chars().any(|ch| ch != '}'));
                if has_inline_body {
                    let open = first_open.unwrap_or(line.len().saturating_sub(1));
                    result.push_str(&line[..open + 1]);
                } else {
                    result.push_str(line);
                }
                result.push('\n');
                brace_depth = brace_delta;
                in_impl_body = brace_depth > 0 || first_open.is_none();
                if has_inline_body && brace_depth <= 0 {
                    result.push_str("    // ... implementation\n}\n");
                    in_impl_body = false;
                }
                continue;
            }

            // Track brace depth for implementation bodies
            if in_impl_body {
                brace_depth += brace_delta;

                // Only keep the opening and closing braces
                if brace_depth <= 1 && (trimmed == "{" || trimmed == "}" || trimmed.ends_with('{'))
                {
                    result.push_str(line);
                    result.push('\n');
                }

                if brace_depth <= 0 {
                    in_impl_body = false;
                    if !trimmed.is_empty() && trimmed != "}" {
                        result.push_str("    // ... implementation\n");
                    }
                }
                continue;
            }

            // Keep type definitions, constants, etc.
            if trimmed.starts_with("const ")
                || trimmed.starts_with("static ")
                || trimmed.starts_with("let ")
                || trimmed.starts_with("pub const ")
                || trimmed.starts_with("pub static ")
            {
                result.push_str(line);
                result.push('\n');
            }
        }

        result.trim().to_string()
    }
}

pub fn get_filter(level: FilterLevel) -> Box<dyn FilterStrategy> {
    match level {
        FilterLevel::None => Box::new(NoFilter),
        FilterLevel::Minimal => Box::new(MinimalFilter),
        FilterLevel::Aggressive => Box::new(AggressiveFilter),
    }
}

pub fn smart_truncate(content: &str, max_lines: usize, _lang: &Language) -> String {
    let (content, byte_truncated) = crate::core::utils::bounded_filter_blob(content);
    let total_lines = content.lines().count();
    if !byte_truncated && total_lines <= max_lines {
        return content.to_string();
    }

    // Clamp to a minimum of 1: max_lines is config/CLI-reachable and a value
    // of 0 would underflow `max_lines - 1` below.
    let max_lines = max_lines.max(1);

    let mut result = Vec::with_capacity(max_lines + 1);
    let mut kept_lines = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Prioritize structurally important lines so the visible window stays useful.
        // The old approach interleaved "// ... N lines omitted" markers which AI agents
        // treated as code, causing parsing confusion and extra retry loops.
        let is_important = FUNC_SIGNATURE.is_match(trimmed)
            || IMPORT_PATTERN.is_match(trimmed)
            || trimmed.starts_with("pub ")
            || trimmed.starts_with("export ")
            || trimmed == "}"
            || trimmed == "{";

        if is_important || kept_lines < max_lines / 2 {
            result.push(line.to_string());
            kept_lines += 1;
        }
        // Non-important lines beyond max_lines/2 are silently skipped —
        // no inline markers that could be mistaken for file content.

        if kept_lines >= max_lines - 1 {
            break;
        }
    }

    // Single end-of-output marker: not code syntax, unambiguous to AI agents.
    // Invariant: kept_lines + N == lines.len() (N = lines not shown)
    if byte_truncated {
        result.push(format!(
            "[output truncated at {} bytes]",
            crate::core::utils::FILTER_BLOB_BYTE_LIMIT
        ));
    } else {
        result.push(format!("[{} more lines]", total_lines - kept_lines));
    }

    result.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_level_parsing() {
        assert_eq!(FilterLevel::from_str("none").unwrap(), FilterLevel::None);
        assert_eq!(
            FilterLevel::from_str("minimal").unwrap(),
            FilterLevel::Minimal
        );
        assert_eq!(
            FilterLevel::from_str("aggressive").unwrap(),
            FilterLevel::Aggressive
        );
    }

    #[test]
    fn test_language_detection() {
        assert_eq!(Language::from_extension("rs"), Language::Rust);
        assert_eq!(Language::from_extension("py"), Language::Python);
        assert_eq!(Language::from_extension("js"), Language::JavaScript);
    }

    #[test]
    fn test_language_detection_data_formats() {
        assert_eq!(Language::from_extension("json"), Language::Data);
        assert_eq!(Language::from_extension("xcstrings"), Language::Data);
        assert_eq!(Language::from_extension("geojson"), Language::Data);
        assert_eq!(Language::from_extension("ipynb"), Language::Data);
        assert_eq!(Language::from_extension("webmanifest"), Language::Data);
        assert_eq!(Language::from_extension("code-workspace"), Language::Data);
        assert_eq!(Language::from_extension("yaml"), Language::Data);
        assert_eq!(Language::from_extension("yml"), Language::Data);
        assert_eq!(Language::from_extension("toml"), Language::Data);
        assert_eq!(Language::from_extension("xml"), Language::Data);
        assert_eq!(Language::from_extension("csv"), Language::Data);
        assert_eq!(Language::from_extension("md"), Language::Data);
        assert_eq!(Language::from_extension("lock"), Language::Data);
    }

    #[test]
    fn test_json_no_comment_stripping() {
        // Reproduces #464: package.json with "packages/*" was corrupted
        // because /* was treated as block comment start
        let json = r#"{
  "workspaces": {
    "packages": [
      "packages/*"
    ]
  },
  "scripts": {
    "build": "bun run --workspaces build"
  },
  "lint-staged": {
    "**/package.json": [
      "sort-package-json"
    ]
  }
}"#;
        let filter = MinimalFilter;
        let result = filter.filter(json, &Language::Data);
        // All fields must be preserved — no comment stripping on JSON
        assert!(
            result.contains("packages/*"),
            "packages/* should not be treated as block comment start"
        );
        assert!(
            result.contains("scripts"),
            "scripts section must not be stripped"
        );
        assert!(
            result.contains("lint-staged"),
            "lint-staged section must not be stripped"
        );
        assert!(
            result.contains("**/package.json"),
            "**/package.json should not be treated as block comment end"
        );
    }

    #[test]
    fn test_json_aggressive_filter_preserves_structure() {
        let json = r#"{
  "name": "my-app",
  "dependencies": {
    "react": "^18.0.0"
  },
  "scripts": {
    "dev": "next dev /* not a comment */"
  }
}"#;
        let filter = AggressiveFilter;
        let result = filter.filter(json, &Language::Data);
        assert!(
            result.contains("/* not a comment */"),
            "Aggressive filter must not strip comment-like patterns in JSON"
        );
    }

    #[test]
    fn test_minimal_filter_removes_comments() {
        let code = r#"
// This is a comment
fn main() {
    println!("Hello");
}
"#;
        let filter = MinimalFilter;
        let result = filter.filter(code, &Language::Rust);
        assert!(!result.contains("// This is a comment"));
        assert!(result.contains("fn main()"));
    }

    // --- block-comment content-loss regressions (issue #471) ---

    #[test]
    fn test_inline_block_comment_preserves_code() {
        // BUG 1: `let x = compute(); /* note */` previously dropped the whole
        // line because it contained both /* and */. The code must survive.
        let code = "let x = compute(); /* note */\nlet y = 2;";
        let out = MinimalFilter.filter(code, &Language::Rust);
        assert!(
            out.contains("let x = compute();"),
            "inline /* */ must not drop the code before it; got:\n{}",
            out
        );
        assert!(
            !out.contains("/* note */"),
            "the inline comment span itself should be stripped; got:\n{}",
            out
        );
        assert!(out.contains("let y = 2;"), "following line must survive");
    }

    #[test]
    fn test_slash_star_in_string_does_not_start_block_comment() {
        // BUG 2 (the empirical repro): `/*` inside a string literal latched
        // in_block_comment=true and swallowed the rest of the file.
        let code = "\
fn main() {
    let glob = \"/*.txt\";
    let a = 1;
    let b = 2;
    let c = 3;
    println!(\"{a} {b} {c}\");
}";
        let out = MinimalFilter.filter(code, &Language::Rust);
        // Every code line must survive — nothing latched.
        for needle in [
            "fn main()",
            "let glob = \"/*.txt\";",
            "let a = 1;",
            "let b = 2;",
            "let c = 3;",
            "println!(\"{a} {b} {c}\");",
        ] {
            assert!(
                out.contains(needle),
                "line `{}` was lost — /* in a string literal latched block-comment state; got:\n{}",
                needle,
                out
            );
        }
    }

    #[test]
    fn test_multiline_block_comment_is_stripped() {
        // Genuine multi-line /* ... */ comments must still be removed.
        let code = "\
let before = 1;
/* this is
   a real multi-line
   block comment */
let after = 2;";
        let out = MinimalFilter.filter(code, &Language::Rust);
        assert!(out.contains("let before = 1;"));
        assert!(out.contains("let after = 2;"));
        assert!(
            !out.contains("real multi-line"),
            "multi-line block comment body must be stripped; got:\n{}",
            out
        );
    }

    #[test]
    fn test_code_after_block_comment_close_survives() {
        // Code trailing the */ on the closing line must be preserved.
        let code = "\
/* opening
   middle */ let kept = 42;
let also = 1;";
        let out = MinimalFilter.filter(code, &Language::Rust);
        assert!(
            out.contains("let kept = 42;"),
            "code after the closing */ must survive; got:\n{}",
            out
        );
        assert!(out.contains("let also = 1;"));
    }

    #[test]
    fn test_star_slash_in_string_on_code_line_best_effort() {
        // best-effort: a `*/` living inside a string literal on a normal code
        // line must not corrupt the scan or lose following lines.
        let code = "let p = \"*/\";\nlet keep = 1;";
        let out = MinimalFilter.filter(code, &Language::Rust);
        assert!(out.contains("let p ="), "string containing */ preserved");
        assert!(out.contains("let keep = 1;"), "following line survives");
    }

    #[test]
    fn test_python_one_line_docstring_does_not_latch() {
        // LOW bug: a one-line `"""doc"""` flipped in_docstring true and stuck,
        // disabling comment stripping for the rest of the file.
        let code = "\
\"\"\"module docstring\"\"\"
x = 1
# this comment must still be stripped
y = 2";
        let out = MinimalFilter.filter(code, &Language::Python);
        assert!(out.contains("\"\"\"module docstring\"\"\""));
        assert!(out.contains("x = 1"));
        assert!(out.contains("y = 2"));
        assert!(
            !out.contains("must still be stripped"),
            "in_docstring latched on after a one-line docstring; got:\n{}",
            out
        );
    }

    #[test]
    fn test_js_template_literal_preserves_block_comment_markers() {
        let code =
            "const template = `first line\n/* literal marker */\nlast line`;\nconst after = 1;";
        let out = MinimalFilter.filter(code, &Language::JavaScript);
        assert_eq!(out, code, "template literal was mangled:\n{out}");
    }

    #[test]
    fn test_rust_multiline_raw_string_preserves_block_comment_markers() {
        let code = r##"let value = r#"first line
/* literal marker */
last line"#;
let after = 1;"##;
        let out = MinimalFilter.filter(code, &Language::Rust);
        assert_eq!(out, code, "Rust raw string was mangled:\n{out}");
    }

    #[test]
    fn test_go_multiline_raw_string_preserves_block_comment_markers() {
        let code = "var value = `first line\n/* literal marker */\nlast line`\nvar after = 1";
        let out = MinimalFilter.filter(code, &Language::Go);
        assert_eq!(out, code, "Go raw string was mangled:\n{out}");
    }

    #[test]
    fn test_python_prefixed_and_single_quote_docstrings_round_trip() {
        let cases = [
            (
                "r\"\"\"raw doc\n# inside raw doc\n\"\"\"\n# outside comment\nx = 1",
                "r\"\"\"raw doc\n# inside raw doc\n\"\"\"\nx = 1",
            ),
            (
                "f\"\"\"formatted {value}\n# inside formatted doc\n\"\"\"\n# outside comment\ny = 2",
                "f\"\"\"formatted {value}\n# inside formatted doc\n\"\"\"\ny = 2",
            ),
            (
                "'''single-quoted doc\n# inside single doc\n'''\n# outside comment\nz = 3",
                "'''single-quoted doc\n# inside single doc\n'''\nz = 3",
            ),
        ];

        for (code, expected) in cases {
            let out = MinimalFilter.filter(code, &Language::Python);
            assert_eq!(out, expected, "Python docstring was mistracked:\n{out}");
        }
    }

    #[test]
    fn test_aggressive_filter_keeps_go_receiver_method_signature() {
        let code = "func (r *Rcvr) F() {\n    r.call()\n}\nconst After = 1";
        let out = AggressiveFilter.filter(code, &Language::Go);
        assert!(
            out.contains("func (r *Rcvr) F()"),
            "Go receiver method signature was stripped:\n{out}"
        );
    }

    #[test]
    fn test_aggressive_filter_does_not_leak_later_function_body_secrets() {
        let code = "fn f() {\n    call();\n    let api_key = \"LATER_SECRET\";\n}\nconst AFTER: usize = 1;";
        let out = AggressiveFilter.filter(code, &Language::Rust);
        assert!(
            !out.contains("LATER_SECRET"),
            "function secret leaked:\n{out}"
        );
        assert!(
            out.contains("const AFTER"),
            "code after function was lost:\n{out}"
        );
    }

    #[test]
    fn test_aggressive_filter_does_not_leak_inline_function_body_secrets() {
        let code = "fn f() { call(); let api_key = \"INLINE_SECRET\"; }";
        let out = AggressiveFilter.filter(code, &Language::Rust);
        assert!(
            !out.contains("INLINE_SECRET"),
            "inline function secret leaked:\n{out}"
        );
    }

    #[test]
    fn test_aggressive_brace_depth_ignores_strings_and_comments() {
        let code = "fn f() {\n    let brace = \"{\";\n    call(); // {\n}\nconst AFTER: usize = 1;";
        let out = AggressiveFilter.filter(code, &Language::Rust);
        assert!(
            out.contains("const AFTER"),
            "braces inside strings/comments corrupted body depth:\n{out}"
        );
    }

    #[test]
    fn test_doc_block_comment_preserved() {
        // Rust /** ... */ doc comments are kept verbatim (prior behaviour).
        let code = "/** API docs */\npub fn f() {}";
        let out = MinimalFilter.filter(code, &Language::Rust);
        assert!(out.contains("/** API docs */"), "doc block must be kept");
        assert!(out.contains("pub fn f()"));
    }

    // --- truncation accuracy ---

    #[test]
    fn test_smart_truncate_overflow_count_exact() {
        // 200 plain-text lines (no function signatures/imports) with max_lines=20.
        // Smart selection keeps up to max_lines/2=10 non-important lines then stops.
        // The overflow message "[N more lines]" must satisfy:
        //   kept_count + N == total_lines
        let total_lines = 200usize;
        let max_lines = 20usize;
        let content: String = (0..total_lines)
            .map(|i| format!("plain text line number {}", i))
            .collect::<Vec<_>>()
            .join("\n");

        let output = smart_truncate(&content, max_lines, &Language::Rust);

        // Extract the overflow message
        let overflow_line = output
            .lines()
            .find(|l| l.contains("more lines"))
            .unwrap_or_else(|| panic!("No overflow message found in:\n{}", output));

        // Parse "[N more lines]"
        let reported_more: usize = overflow_line
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("Could not parse overflow count from: {}", overflow_line));

        let kept_count = output
            .lines()
            .filter(|l| !l.contains("more lines") && !l.contains("omitted"))
            .count();

        assert_eq!(
            kept_count + reported_more,
            total_lines,
            "kept ({}) + reported_more ({}) must equal total ({})",
            kept_count,
            reported_more,
            total_lines
        );
    }

    #[test]
    fn test_smart_truncate_no_annotations() {
        // 10 plain-text lines, max_lines=3: smart logic keeps first max_lines/2=1 line.
        // (None of the lines match FUNC_SIGNATURE or IMPORT_PATTERN patterns.)
        let input = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n";
        let output = smart_truncate(input, 3, &Language::Unknown);
        // Must NOT contain old-style "// ... N lines omitted" annotations
        assert!(
            !output.contains("// ..."),
            "smart_truncate must not insert synthetic comment annotations"
        );
        // Must contain clean end-of-output marker (1 kept + 9 omitted = 10 total)
        assert!(output.contains("[9 more lines]"));
        // Only the first line is kept (plain-text, no important signatures)
        assert!(output.starts_with("line1\n"));
    }

    #[test]
    fn test_smart_truncate_no_truncation_when_under_limit() {
        let input = "a\nb\nc\n";
        let output = smart_truncate(input, 10, &Language::Unknown);
        assert_eq!(output, input);
        assert!(!output.contains("more lines"));
    }

    #[test]
    fn test_smart_truncate_exact_limit() {
        let input = "a\nb\nc";
        let output = smart_truncate(input, 3, &Language::Unknown);
        assert_eq!(output, input);
    }

    #[test]
    fn test_smart_truncate_caps_one_huge_line_utf8_safely() {
        let mut input = "é".repeat(600_000);
        input.push_str("SECRET_AFTER_LIMIT");

        let output = smart_truncate(&input, 100, &Language::Unknown);

        assert!(!output.contains("SECRET_AFTER_LIMIT"));
        assert!(
            output.len() <= 1_048_700,
            "bounded output unexpectedly large: {} bytes",
            output.len()
        );
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
    }
}
