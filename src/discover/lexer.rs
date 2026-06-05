#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Arg,
    Operator,
    Pipe,
    Redirect,
    Shellism,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToken {
    pub kind: TokenKind,
    pub value: String,
    pub offset: usize,
}

pub fn tokenize(input: &str) -> Vec<ParsedToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut current_start: usize = 0;
    let mut byte_pos: usize = 0;
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        let char_len = c.len_utf8();

        if escaped {
            current.push('\\');
            current.push(c);
            byte_pos += char_len;
            escaped = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            if current.is_empty() {
                current_start = byte_pos;
            }
            byte_pos += char_len;
            continue;
        }

        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            current.push(c);
            byte_pos += char_len;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            if current.is_empty() {
                current_start = byte_pos;
            }
            current.push(c);
            byte_pos += char_len;
            continue;
        }

        match c {
            '$' => {
                flush_arg(&mut tokens, &mut current, current_start);
                let start = byte_pos;
                byte_pos += char_len;
                if chars
                    .peek()
                    .is_some_and(|&nc| nc.is_ascii_alphabetic() || nc == '_')
                {
                    let mut name = String::from("$");
                    while let Some(&nc) = chars.peek() {
                        if !nc.is_ascii_alphanumeric() && nc != '_' {
                            break;
                        }
                        chars.next();
                        byte_pos += nc.len_utf8();
                        name.push(nc);
                    }
                    tokens.push(ParsedToken {
                        kind: TokenKind::Arg,
                        value: name,
                        offset: start,
                    });
                } else {
                    tokens.push(ParsedToken {
                        kind: TokenKind::Shellism,
                        value: "$".into(),
                        offset: start,
                    });
                }
                current_start = byte_pos;
            }
            '*' | '?' | '`' | '(' | ')' | '{' | '}' | '!' => {
                flush_arg(&mut tokens, &mut current, current_start);
                tokens.push(ParsedToken {
                    kind: TokenKind::Shellism,
                    value: c.to_string(),
                    offset: byte_pos,
                });
                byte_pos += char_len;
                current_start = byte_pos;
            }
            '|' => {
                flush_arg(&mut tokens, &mut current, current_start);
                let start = byte_pos;
                byte_pos += char_len;
                if chars.peek() == Some(&'|') {
                    chars.next();
                    byte_pos += 1;
                    tokens.push(ParsedToken {
                        kind: TokenKind::Operator,
                        value: "||".into(),
                        offset: start,
                    });
                } else {
                    tokens.push(ParsedToken {
                        kind: TokenKind::Pipe,
                        value: "|".into(),
                        offset: start,
                    });
                }
                current_start = byte_pos;
            }
            ';' => {
                flush_arg(&mut tokens, &mut current, current_start);
                tokens.push(ParsedToken {
                    kind: TokenKind::Operator,
                    value: ";".into(),
                    offset: byte_pos,
                });
                byte_pos += char_len;
                current_start = byte_pos;
            }
            '&' => {
                flush_arg(&mut tokens, &mut current, current_start);
                let start = byte_pos;
                byte_pos += char_len;
                if chars.peek() == Some(&'&') {
                    chars.next();
                    byte_pos += 1;
                    tokens.push(ParsedToken {
                        kind: TokenKind::Operator,
                        value: "&&".into(),
                        offset: start,
                    });
                } else if chars.peek() == Some(&'>') {
                    chars.next();
                    byte_pos += 1;
                    let mut val = String::from("&>");
                    if chars.peek() == Some(&'>') {
                        chars.next();
                        byte_pos += 1;
                        val.push('>');
                    }
                    tokens.push(ParsedToken {
                        kind: TokenKind::Redirect,
                        value: val,
                        offset: start,
                    });
                } else {
                    tokens.push(ParsedToken {
                        kind: TokenKind::Shellism,
                        value: "&".into(),
                        offset: start,
                    });
                }
                current_start = byte_pos;
            }
            '>' => {
                let fd_prefix =
                    if !current.is_empty() && current.chars().all(|ch| ch.is_ascii_digit()) {
                        Some(std::mem::take(&mut current))
                    } else {
                        flush_arg(&mut tokens, &mut current, current_start);
                        None
                    };
                let redir_start = if fd_prefix.is_some() {
                    current_start
                } else {
                    byte_pos
                };
                let mut val = fd_prefix.unwrap_or_default();
                val.push('>');
                byte_pos += char_len;
                if chars.peek() == Some(&'>') {
                    chars.next();
                    byte_pos += 1;
                    val.push('>');
                }
                if chars.peek() == Some(&'&') {
                    chars.next();
                    byte_pos += 1;
                    val.push('&');
                    while let Some(&nc) = chars.peek() {
                        if !nc.is_ascii_digit() && nc != '-' {
                            break;
                        }
                        chars.next();
                        val.push(nc);
                        byte_pos += nc.len_utf8();
                    }
                }
                tokens.push(ParsedToken {
                    kind: TokenKind::Redirect,
                    value: val,
                    offset: redir_start,
                });
                current_start = byte_pos;
            }
            '<' => {
                flush_arg(&mut tokens, &mut current, current_start);
                let start = byte_pos;
                let mut val = String::from("<");
                byte_pos += char_len;
                if chars.peek() == Some(&'<') {
                    chars.next();
                    byte_pos += 1;
                    val.push('<');
                }
                tokens.push(ParsedToken {
                    kind: TokenKind::Redirect,
                    value: val,
                    offset: start,
                });
                current_start = byte_pos;
            }
            '\n' | '\r' => {
                // An unquoted newline (or carriage return) is a shell command
                // terminator, semantically equivalent to `;`. We emit it as a
                // Shellism control token (value "\n") so permission segmentation
                // (`split_on_operators`) can treat it as a separator and check
                // each line against deny/ask rules independently. It is NOT an
                // Operator (that would change the rewrite path's classification)
                // and quoted/heredoc newlines never reach here — the quote
                // handling above consumes them first.
                flush_arg(&mut tokens, &mut current, current_start);
                tokens.push(ParsedToken {
                    kind: TokenKind::Shellism,
                    value: "\n".into(),
                    offset: byte_pos,
                });
                byte_pos += char_len;
                current_start = byte_pos;
            }
            c if c.is_whitespace() => {
                flush_arg(&mut tokens, &mut current, current_start);
                byte_pos += c.len_utf8();
                current_start = byte_pos;
            }
            _ => {
                if current.is_empty() {
                    current_start = byte_pos;
                }
                current.push(c);
                byte_pos += char_len;
            }
        }
    }

    if escaped {
        current.push('\\');
    }
    flush_arg(&mut tokens, &mut current, current_start);
    tokens
}

fn flush_arg(tokens: &mut Vec<ParsedToken>, current: &mut String, offset: usize) {
    if !current.is_empty() {
        tokens.push(ParsedToken {
            kind: TokenKind::Arg,
            value: std::mem::take(current),
            offset,
        });
    }
}

/// Split a shell command on operators (`&&`, `||`, `;`) and optionally pipes (`|`),
/// respecting quoted strings via the lexer.
///
/// When `stop_at_pipe` is true, returns only segments before the first `|`
/// (used by command rewriting — only the left side of a pipe gets rewritten).
/// When false, splits through pipes too (used by permission checking —
/// every segment must be validated).
pub fn split_on_operators(cmd: &str, stop_at_pipe: bool) -> Vec<&str> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    let tokens = tokenize(trimmed);
    let mut results = Vec::new();
    let mut seg_start: usize = 0;

    for tok in &tokens {
        match tok.kind {
            TokenKind::Operator => {
                let segment = trimmed[seg_start..tok.offset].trim();
                if !segment.is_empty() {
                    results.push(segment);
                }
                seg_start = tok.offset + tok.value.len();
            }
            TokenKind::Pipe => {
                let segment = trimmed[seg_start..tok.offset].trim();
                if !segment.is_empty() {
                    results.push(segment);
                }
                if stop_at_pipe {
                    return results;
                }
                seg_start = tok.offset + tok.value.len();
            }
            // A standalone background `&` and an unquoted newline are command
            // separators just like `;`/`&&`/`||`. The lexer classifies both as
            // Shellism control tokens (values "&" and "\n"); split on them so
            // permission checking validates each sub-command independently.
            // SECURITY: without this, `echo hi & rm -rf /` and
            // `echo hi\nrm -rf /` collapse into one segment whose prefix is
            // `echo`, so a `rm -rf` deny/ask rule never fires. `&&`/`>&`/`2>&1`
            // are NOT this case — `&&` is an Operator and the redirect forms are
            // Redirect tokens, neither of which has Shellism value "&".
            TokenKind::Shellism if tok.value == "&" || tok.value == "\n" => {
                let segment = trimmed[seg_start..tok.offset].trim();
                if !segment.is_empty() {
                    results.push(segment);
                }
                seg_start = tok.offset + tok.value.len();
            }
            _ => {}
        }
    }

    let tail = trimmed[seg_start..].trim();
    if !tail.is_empty() {
        results.push(tail);
    }

    results
}

/// Strip a single layer of matching surrounding quotes from a token.
///
/// Used by token-aware permission matching so that `"push"` and `push`
/// compare equal. Only strips when the first and last char are the same
/// quote character; mismatched or unquoted strings are returned unchanged.
///
/// Note: `shell_split` already consumes the outer quote layer when it
/// tokenises a command, so a token reaching here is normally unquoted.
/// This "one layer" of stripping therefore runs *on top of* what
/// `shell_split` removed — it catches a residual quote layer (e.g. from
/// a quote nested inside the layer `shell_split` stripped), not the
/// original outer quoting.
pub fn strip_quotes(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() >= 2
        && ((chars[0] == '"' && chars[chars.len() - 1] == '"')
            || (chars[0] == '\'' && chars[chars.len() - 1] == '\''))
    {
        return chars[1..chars.len() - 1].iter().collect();
    }
    s.to_string()
}

pub fn shell_split(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// A command substitution payload extracted from a command string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    /// The inner command text (e.g. `rm -rf /x` from `$(rm -rf /x)`).
    pub inner: String,
    /// True when the construct was malformed (unbalanced) and the inner
    /// text could not be reliably bounded. Callers MUST treat this as
    /// fail-closed: an un-evaluatable substitution may hide anything.
    pub malformed: bool,
}

/// Extract command-substitution payloads from a shell command string.
///
/// Recognises, outside of single/double quotes:
/// - `$(...)`  — modern command substitution
/// - `` `...` `` — legacy backtick substitution
/// - `<(...)` / `>(...)` — process substitution
///
/// Returns one [`Substitution`] per construct found, recursing into
/// nested substitutions so `$(echo $(rm -rf /x))` yields both the outer
/// and inner payloads. Parenthesis nesting is balanced. An unterminated
/// construct yields a `malformed` entry so callers can fail closed.
///
/// Single-quoted regions are skipped entirely (no expansion in bash).
/// Backtick substitution inside double quotes IS still active in bash,
/// so double-quoted regions are scanned; only `$(...)`/process-subst
/// require an unquoted context.
pub fn extract_substitutions(cmd: &str) -> Vec<Substitution> {
    let mut out = Vec::new();
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;

    while i < chars.len() {
        let c = chars[i];

        if c == '\\' && !in_single {
            i += 2; // skip escaped char
            continue;
        }
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if !in_double && c == '\'' {
            in_single = true;
            i += 1;
            continue;
        }

        // `$(...)` is active unquoted or inside double quotes; `<(...)` /
        // `>(...)` process substitution only in an unquoted context.
        // (Single-quoted regions were already skipped above.)
        let next_is_open = i + 1 < chars.len() && chars[i + 1] == '(';
        let is_dollar_paren = c == '$' && next_is_open;
        let is_process_subst = (c == '<' || c == '>') && next_is_open && !in_double;
        let paren_subst = (is_dollar_paren || is_process_subst).then_some(i + 2);

        if let Some(open) = paren_subst {
            // Arithmetic expansion `$((expr))` is NOT command execution —
            // bash evaluates the inner as arithmetic, never as a command.
            // Detect the `$((` form (char after `$(` is another `(`) and
            // skip it entirely, emitting no Substitution. If unbalanced,
            // fail closed like any other malformed construct.
            if is_dollar_paren && open < chars.len() && chars[open] == '(' {
                match find_matching_paren(&chars, open) {
                    Some(close) => {
                        // `find_matching_paren` counts the inner `(` at
                        // `open` as an extra depth level, so the index it
                        // returns is the OUTER `)` that closes `$((`.
                        i = close + 1;
                    }
                    None => {
                        let inner: String = chars[open..].iter().collect();
                        out.push(Substitution {
                            inner,
                            malformed: true,
                        });
                        break;
                    }
                }
                continue;
            }

            match find_matching_paren(&chars, open) {
                Some(close) => {
                    let inner: String = chars[open..close].iter().collect();
                    // Recurse first so nested payloads are also captured.
                    out.extend(extract_substitutions(&inner));
                    out.push(Substitution {
                        inner,
                        malformed: false,
                    });
                    i = close + 1;
                }
                None => {
                    // Unbalanced — fail closed.
                    let inner: String = chars[open..].iter().collect();
                    out.push(Substitution {
                        inner,
                        malformed: true,
                    });
                    break;
                }
            }
            continue;
        }

        // Backtick substitution — active even inside double quotes.
        if c == '`' {
            let start = i + 1;
            let mut j = start;
            let mut found = false;
            while j < chars.len() {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '`' {
                    found = true;
                    break;
                }
                j += 1;
            }
            let inner: String = if found {
                chars[start..j].iter().collect()
            } else {
                chars[start..].iter().collect()
            };
            out.extend(extract_substitutions(&inner));
            out.push(Substitution {
                inner,
                malformed: !found,
            });
            if found {
                i = j + 1;
            } else {
                break;
            }
            continue;
        }

        i += 1;
    }

    out
}

/// Find the index of the `)` matching the `(` whose body starts at `open`.
///
/// Tracks single/double quote regions so a `)` inside a quoted string does
/// not close the substitution. Returns `None` if unbalanced.
fn find_matching_paren(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 1i32;
    let mut i = open;
    let mut in_single = false;
    let mut in_double = false;

    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && !in_single {
            i += 2;
            continue;
        }
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let tokens = tokenize("git status");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].kind, TokenKind::Arg);
        assert_eq!(tokens[0].value, "git");
        assert_eq!(tokens[1].value, "status");
    }

    #[test]
    fn test_command_with_args() {
        let tokens = tokenize("git commit -m message");
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0].value, "git");
        assert_eq!(tokens[1].value, "commit");
        assert_eq!(tokens[2].value, "-m");
        assert_eq!(tokens[3].value, "message");
    }

    #[test]
    fn test_quoted_operator_not_split() {
        let tokens = tokenize(r#"git commit -m "Fix && Bug""#);
        assert!(!tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Operator) && t.value == "&&"));
        assert!(tokens.iter().any(|t| t.value.contains("Fix && Bug")));
    }

    #[test]
    fn test_single_quoted_string() {
        let tokens = tokenize("echo 'hello world'");
        assert!(tokens.iter().any(|t| t.value == "'hello world'"));
    }

    #[test]
    fn test_double_quoted_string() {
        let tokens = tokenize(r#"echo "hello world""#);
        assert!(tokens.iter().any(|t| t.value == "\"hello world\""));
    }

    #[test]
    fn test_empty_quoted_string() {
        let tokens = tokenize("echo \"\"");
        assert!(tokens.iter().any(|t| t.value == "\"\""));
    }

    #[test]
    fn test_nested_quotes() {
        let tokens = tokenize(r#"echo "outer 'inner' outer""#);
        assert!(tokens.iter().any(|t| t.value.contains("'inner'")));
    }

    #[test]
    fn test_escaped_space() {
        let tokens = tokenize("echo hello\\ world");
        assert!(tokens.iter().any(|t| t.value.contains("hello")));
    }

    #[test]
    fn test_backslash_in_single_quotes() {
        let tokens = tokenize(r#"echo 'hello\nworld'"#);
        assert!(tokens.iter().any(|t| t.value.contains(r"\n")));
    }

    #[test]
    fn test_escaped_quote_in_double() {
        let tokens = tokenize(r#"echo "hello\"world""#);
        assert!(tokens.iter().any(|t| t.value.contains("hello")));
    }

    #[test]
    fn test_empty_input() {
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn test_unclosed_single_quote() {
        let tokens = tokenize("'unclosed");
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_unclosed_double_quote() {
        let tokens = tokenize("\"unclosed");
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_unicode_preservation() {
        let tokens = tokenize("echo \"héllo wörld\"");
        assert!(tokens.iter().any(|t| t.value.contains("héllo")));
    }

    #[test]
    fn test_multiple_spaces() {
        let tokens = tokenize("git   status");
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn test_leading_trailing_spaces() {
        let tokens = tokenize("  git status  ");
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn test_and_operator() {
        let tokens = tokenize("cmd1 && cmd2");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Operator && t.value == "&&"));
    }

    #[test]
    fn test_or_operator() {
        let tokens = tokenize("cmd1 || cmd2");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Operator && t.value == "||"));
    }

    #[test]
    fn test_semicolon() {
        let tokens = tokenize("cmd1 ; cmd2");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Operator && t.value == ";"));
    }

    #[test]
    fn test_multiple_and() {
        let tokens = tokenize("a && b && c");
        let ops: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Operator)
            .collect();
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_mixed_operators() {
        let tokens = tokenize("a && b || c");
        let ops: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Operator)
            .collect();
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_operator_at_start() {
        let tokens = tokenize("&& cmd");
        assert!(tokens.iter().any(|t| t.value == "&&"));
    }

    #[test]
    fn test_operator_at_end() {
        let tokens = tokenize("cmd &&");
        assert!(tokens.iter().any(|t| t.value == "&&"));
    }

    #[test]
    fn test_pipe_detection() {
        let tokens = tokenize("cat file | grep pattern");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Pipe));
    }

    #[test]
    fn test_quoted_pipe_not_pipe() {
        let tokens = tokenize("\"a|b\"");
        assert!(!tokens.iter().any(|t| t.kind == TokenKind::Pipe));
    }

    #[test]
    fn test_multiple_pipes() {
        let tokens = tokenize("a | b | c");
        let pipes: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Pipe)
            .collect();
        assert_eq!(pipes.len(), 2);
    }

    #[test]
    fn test_glob_detection() {
        let tokens = tokenize("ls *.rs");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_quoted_glob_not_shellism() {
        let tokens = tokenize("echo \"*.txt\"");
        assert!(!tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_simple_var_is_arg() {
        let tokens = tokenize("echo $HOME");
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Arg && t.value == "$HOME"),
            "Simple $VAR must be Arg — shell expands at execution time"
        );
        assert!(
            !tokens.iter().any(|t| t.kind == TokenKind::Shellism),
            "No Shellism expected for simple $VAR"
        );
    }

    #[test]
    fn test_simple_var_enables_native_routing() {
        let tokens = tokenize("git log $BRANCH");
        assert!(
            !tokens.iter().any(|t| t.kind == TokenKind::Shellism),
            "git log $BRANCH must have no Shellism"
        );
    }

    #[test]
    fn test_dollar_subshell_stays_shellism() {
        let tokens = tokenize("echo $(date)");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_dollar_brace_stays_shellism() {
        let tokens = tokenize("echo ${HOME}");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_dollar_special_vars_stay_shellism() {
        for s in &["echo $?", "echo $$", "echo $!"] {
            let tokens = tokenize(s);
            assert!(
                tokens.iter().any(|t| t.kind == TokenKind::Shellism),
                "{} should produce Shellism",
                s
            );
        }
    }

    #[test]
    fn test_dollar_digit_stays_shellism() {
        let tokens = tokenize("echo $1");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_quoted_variable_not_shellism() {
        let tokens = tokenize("echo \"$HOME\"");
        assert!(!tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_backtick_substitution() {
        let tokens = tokenize("echo `date`");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_subshell_detection() {
        let tokens = tokenize("echo $(date)");
        let shellisms: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Shellism)
            .collect();
        assert!(!shellisms.is_empty());
    }

    #[test]
    fn test_brace_expansion() {
        let tokens = tokenize("echo {a,b}.txt");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Shellism));
    }

    #[test]
    fn test_escaped_glob() {
        let tokens = tokenize("echo \\*.txt");
        assert!(!tokens
            .iter()
            .any(|t| t.kind == TokenKind::Shellism && t.value == "*"));
    }

    #[test]
    fn test_redirect_out() {
        let tokens = tokenize("cmd > file");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Redirect));
    }

    #[test]
    fn test_redirect_append() {
        let tokens = tokenize("cmd >> file");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == ">>"));
    }

    #[test]
    fn test_redirect_in() {
        let tokens = tokenize("cmd < file");
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Redirect));
    }

    #[test]
    fn test_redirect_stderr() {
        let tokens = tokenize("cmd 2> file");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value.starts_with("2>")));
    }

    #[test]
    fn test_redirect_stderr_no_space() {
        let tokens = tokenize("cmd 2>/dev/null");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "2>"));
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Arg && t.value == "/dev/null"));
    }

    #[test]
    fn test_redirect_dev_null() {
        let tokens = tokenize("cmd > /dev/null");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == ">"));
    }

    #[test]
    fn test_redirect_2_to_1_single_token() {
        let tokens = tokenize("cmd 2>&1");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[1].kind, TokenKind::Redirect);
        assert_eq!(tokens[1].value, "2>&1");
        assert!(!tokens
            .iter()
            .any(|t| t.kind == TokenKind::Shellism && t.value == "&"));
    }

    #[test]
    fn test_redirect_1_to_2_single_token() {
        let tokens = tokenize("cmd 1>&2");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "1>&2"));
    }

    #[test]
    fn test_redirect_fd_close() {
        let tokens = tokenize("cmd 2>&-");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "2>&-"));
    }

    #[test]
    fn test_redirect_shorthand_dup() {
        let tokens = tokenize("cmd >&2");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == ">&2"));
    }

    #[test]
    fn test_redirect_amp_gt() {
        let tokens = tokenize("cmd &>/dev/null");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "&>"));
    }

    #[test]
    fn test_redirect_amp_gt_gt() {
        let tokens = tokenize("cmd &>>/dev/null");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "&>>"));
    }

    #[test]
    fn test_combined_redirect_chain() {
        let tokens = tokenize("cmd > /dev/null 2>&1");
        let redirects: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Redirect)
            .collect();
        assert_eq!(redirects.len(), 2);
        assert_eq!(redirects[0].value, ">");
        assert_eq!(redirects[1].value, "2>&1");
    }

    #[test]
    fn test_redirect_append_to_file() {
        let tokens = tokenize("echo hello >> /tmp/output.txt");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == ">>"));
    }

    #[test]
    fn test_redirect_heredoc_marker() {
        let tokens = tokenize("cat <<EOF");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "<<"));
    }

    #[test]
    fn test_redirect_2_to_1_with_pipe() {
        let tokens = tokenize("cargo test 2>&1 | head");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "2>&1"));
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Pipe));
    }

    #[test]
    fn test_redirect_2_to_1_with_and() {
        let tokens = tokenize("cargo test 2>&1 && echo done");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "2>&1"));
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Operator && t.value == "&&"));
    }

    #[test]
    fn test_exclamation_is_shellism() {
        let tokens = tokenize("if ! grep -q pattern file; then echo missing; fi");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Shellism && t.value == "!"));
    }

    #[test]
    fn test_background_job_is_shellism() {
        let tokens = tokenize("sleep 10 &");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Shellism && t.value == "&"));
    }

    #[test]
    fn test_background_not_confused_with_amp_redirect() {
        let tokens = tokenize("cargo test &>/dev/null");
        assert!(!tokens
            .iter()
            .any(|t| t.kind == TokenKind::Shellism && t.value == "&"));
        assert!(tokens.iter().any(|t| t.kind == TokenKind::Redirect));
    }

    #[test]
    fn test_semicolon_no_space() {
        let tokens = tokenize("git status;cargo test");
        assert_eq!(
            tokens
                .iter()
                .filter(|t| t.kind == TokenKind::Operator)
                .count(),
            1
        );
        assert_eq!(
            tokens.iter().filter(|t| t.kind == TokenKind::Arg).count(),
            4
        );
    }

    #[test]
    fn test_offset_tracking() {
        let tokens = tokenize("a && b");
        assert_eq!(tokens[0].offset, 0);
        assert_eq!(tokens[1].offset, 2);
        assert_eq!(tokens[2].offset, 5);
    }

    #[test]
    fn test_offset_segment_extraction() {
        let cmd = "git add . && cargo test";
        let tokens = tokenize(cmd);
        let op = tokens
            .iter()
            .find(|t| t.kind == TokenKind::Operator)
            .unwrap();
        let left = cmd[..op.offset].trim();
        let right_start = op.offset + op.value.len();
        let right = cmd[right_start..].trim();
        assert_eq!(left, "git add .");
        assert_eq!(right, "cargo test");
    }

    #[test]
    fn test_env_prefix_is_arg() {
        let tokens = tokenize("GIT_SSH_COMMAND=ssh git push");
        assert_eq!(tokens[0].kind, TokenKind::Arg);
        assert_eq!(tokens[0].value, "GIT_SSH_COMMAND=ssh");
    }

    #[test]
    fn test_complex_compound() {
        let tokens = tokenize("cargo fmt --all && cargo clippy --all-targets && cargo test");
        let operators: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Operator)
            .collect();
        assert_eq!(operators.len(), 2);
        assert!(operators.iter().all(|t| t.value == "&&"));
    }

    #[test]
    fn test_find_pipe_xargs() {
        let tokens = tokenize("find . -name '*.rs' | xargs grep 'fn run'");
        let pipe_idx = tokens
            .iter()
            .position(|t| t.kind == TokenKind::Pipe)
            .unwrap();
        assert!(pipe_idx > 0);
        let before_pipe: Vec<_> = tokens[..pipe_idx]
            .iter()
            .filter(|t| t.kind == TokenKind::Arg)
            .collect();
        assert!(before_pipe.iter().any(|t| t.value == "find"));
    }

    #[test]
    fn test_fd_redirect_needs_adjacent_digit() {
        let tokens = tokenize("echo 2 > file");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Arg && t.value == "2"));
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == ">"));
    }

    #[test]
    fn test_fd_redirect_no_space() {
        let tokens = tokenize("echo 2>file");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Redirect && t.value == "2>"));
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::Arg && t.value == "file"));
    }

    #[test]
    fn test_shell_split_simple() {
        assert_eq!(
            shell_split("head -50 file.php"),
            vec!["head", "-50", "file.php"]
        );
    }

    #[test]
    fn test_shell_split_double_quotes() {
        assert_eq!(
            shell_split(r#"git log --format="%H %s""#),
            vec!["git", "log", "--format=%H %s"]
        );
    }

    #[test]
    fn test_shell_split_single_quotes() {
        assert_eq!(
            shell_split("grep -r 'hello world' ."),
            vec!["grep", "-r", "hello world", "."]
        );
    }

    #[test]
    fn test_shell_split_single_word() {
        assert_eq!(shell_split("ls"), vec!["ls"]);
    }

    #[test]
    fn test_shell_split_empty() {
        let result: Vec<String> = shell_split("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_shell_split_backslash_escape() {
        assert_eq!(
            shell_split(r"echo hello\ world"),
            vec!["echo", "hello world"]
        );
    }

    #[test]
    fn test_shell_split_unclosed_quote() {
        let result = shell_split("echo 'hello");
        assert_eq!(result, vec!["echo", "hello"]);
    }

    #[test]
    fn test_shell_split_mixed_quotes() {
        assert_eq!(
            shell_split(r#"echo "it's" 'a "test"'"#),
            vec!["echo", "it's", "a \"test\""]
        );
    }

    #[test]
    fn test_shell_split_tabs() {
        assert_eq!(shell_split("a\tb\tc"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_shell_split_multiple_spaces() {
        assert_eq!(shell_split("a   b   c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_strip_quotes_double() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
    }

    #[test]
    fn test_strip_quotes_single() {
        assert_eq!(strip_quotes("'hello'"), "hello");
    }

    #[test]
    fn test_strip_quotes_none() {
        assert_eq!(strip_quotes("hello"), "hello");
    }

    #[test]
    fn test_strip_quotes_mismatched() {
        assert_eq!(strip_quotes("\"hello'"), "\"hello'");
    }

    #[test]
    fn test_split_on_operators_stop_at_pipe() {
        assert_eq!(split_on_operators("a | b | c", true), vec!["a"]);
        assert_eq!(split_on_operators("a && b | c", true), vec!["a", "b"]);
    }

    #[test]
    fn test_split_on_operators_through_pipes() {
        assert_eq!(split_on_operators("a | b | c", false), vec!["a", "b", "c"]);
        assert_eq!(
            split_on_operators("a && b | c ; d", false),
            vec!["a", "b", "c", "d"]
        );
    }

    #[test]
    fn test_split_on_operators_quoted() {
        assert_eq!(
            split_on_operators(r#"echo "a && b" && cargo test"#, false),
            vec![r#"echo "a && b""#, "cargo test"]
        );
    }

    #[test]
    fn test_split_on_operators_empty() {
        assert!(split_on_operators("", false).is_empty());
        assert!(split_on_operators("  ", true).is_empty());
    }

    // --- SEC: background `&` and newline as command separators ---
    // A standalone `&` (background) and an unquoted newline must split a
    // compound command so permission rules check each sub-command. Without
    // this, `echo hi & rm -rf /` is one segment whose prefix is `echo`,
    // letting a `rm -rf` deny rule slip past.

    #[test]
    fn test_background_amp_is_shellism_token() {
        let tokens = tokenize("echo hi & rm -rf /");
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Shellism && t.value == "&"),
            "standalone & must be a Shellism token"
        );
    }

    #[test]
    fn test_newline_is_shellism_token() {
        let tokens = tokenize("echo hi\nrm -rf /");
        assert!(
            tokens
                .iter()
                .any(|t| t.kind == TokenKind::Shellism && t.value == "\n"),
            "unquoted newline must be a Shellism control token"
        );
    }

    #[test]
    fn test_split_on_background_amp() {
        assert_eq!(
            split_on_operators("echo hi & rm -rf /", false),
            vec!["echo hi", "rm -rf /"]
        );
    }

    #[test]
    fn test_split_on_newline() {
        assert_eq!(
            split_on_operators("echo hi\nrm -rf /", false),
            vec!["echo hi", "rm -rf /"]
        );
    }

    #[test]
    fn test_split_on_crlf_newline() {
        // \r\n must split exactly once, not produce an empty middle segment.
        assert_eq!(
            split_on_operators("echo hi\r\nrm -rf /", false),
            vec!["echo hi", "rm -rf /"]
        );
    }

    #[test]
    fn test_split_on_multiple_newlines() {
        assert_eq!(
            split_on_operators("a\nb\nc", false),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn test_amp_split_respects_stop_at_pipe() {
        // `&` still splits even on the rewrite (stop_at_pipe) path.
        assert_eq!(
            split_on_operators("echo a & echo b", true),
            vec!["echo a", "echo b"]
        );
    }

    #[test]
    fn test_redirect_amp_not_split_as_background() {
        // `2>&1`, `>&2`, `&>` are Redirect tokens, NOT a background `&` — they
        // must NOT cause a permission split.
        assert_eq!(
            split_on_operators("cargo test 2>&1", false),
            vec!["cargo test 2>&1"]
        );
        assert_eq!(
            split_on_operators("echo err >&2", false),
            vec!["echo err >&2"]
        );
        assert_eq!(
            split_on_operators("cargo test &>/dev/null", false),
            vec!["cargo test &>/dev/null"]
        );
    }

    #[test]
    fn test_double_amp_not_double_handled() {
        // `&&` is one Operator token, not two background `&` separators.
        assert_eq!(
            split_on_operators("echo a && echo b", false),
            vec!["echo a", "echo b"]
        );
    }

    #[test]
    fn test_quoted_amp_not_split() {
        // `&` inside quotes is literal text, not a separator.
        assert_eq!(
            split_on_operators(r#"echo "a & b""#, false),
            vec![r#"echo "a & b""#]
        );
    }

    #[test]
    fn test_quoted_newline_not_split() {
        // A newline inside double quotes is literal text, not a separator.
        assert_eq!(
            split_on_operators("echo \"a\nb\"", false),
            vec!["echo \"a\nb\""]
        );
    }

    // --- extract_substitutions (SEC-C2) ---

    #[test]
    fn test_extract_dollar_paren() {
        let subs = extract_substitutions("echo $(rm -rf /x)");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner, "rm -rf /x");
        assert!(!subs[0].malformed);
    }

    #[test]
    fn test_extract_backtick() {
        let subs = extract_substitutions("echo `rm -rf /x`");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner, "rm -rf /x");
        assert!(!subs[0].malformed);
    }

    #[test]
    fn test_extract_process_substitution() {
        let subs = extract_substitutions("cat <(rm -rf /x)");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner, "rm -rf /x");

        let subs = extract_substitutions("cat >(rm -rf /x)");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner, "rm -rf /x");
    }

    #[test]
    fn test_extract_nested() {
        let subs = extract_substitutions("echo $(echo $(rm -rf /x))");
        // Inner first (recursion), then outer.
        assert!(subs.iter().any(|s| s.inner == "rm -rf /x"));
        assert!(subs.iter().any(|s| s.inner == "echo $(rm -rf /x)"));
    }

    #[test]
    fn test_extract_none_when_plain() {
        assert!(extract_substitutions("echo hello").is_empty());
    }

    #[test]
    fn test_extract_skips_single_quoted() {
        // Single quotes suppress substitution in bash.
        assert!(extract_substitutions("echo '$(rm -rf /x)'").is_empty());
    }

    #[test]
    fn test_extract_unbalanced_is_malformed() {
        let subs = extract_substitutions("echo $(rm -rf /x");
        assert_eq!(subs.len(), 1);
        assert!(subs[0].malformed);
    }

    #[test]
    fn test_extract_arithmetic_expansion_no_substitution() {
        // `$((expr))` is arithmetic, not command execution — no Substitution.
        assert!(extract_substitutions("echo $((2+2))").is_empty());
        assert!(extract_substitutions("echo $((COUNT+1))").is_empty());
    }

    #[test]
    fn test_extract_arithmetic_then_real_subst() {
        // Arithmetic skipped, but a following real substitution still caught.
        let subs = extract_substitutions("echo $((1+1)) $(rm -rf /x)");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner, "rm -rf /x");
        assert!(!subs[0].malformed);
    }

    #[test]
    fn test_extract_unbalanced_arithmetic_fails_closed() {
        let subs = extract_substitutions("echo $((COUNT+1");
        assert_eq!(subs.len(), 1);
        assert!(subs[0].malformed);
    }

    #[test]
    fn test_extract_paren_inside_quotes_not_closing() {
        // The `)` inside the double-quoted arg must not close the subst early.
        let subs = extract_substitutions(r#"echo $(rm -rf "/x )y")"#);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].inner, r#"rm -rf "/x )y""#);
    }
}
