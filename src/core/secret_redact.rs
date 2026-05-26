//! Redact common secret shapes from a shell command string before it lands in
//! an audit log on disk. Belt-and-braces: the gate logs are user-readable and
//! sit at predictable paths, so any token captured verbatim is a leak.
//!
//! Conservative on purpose. The goal is to scrub obvious credentials
//! (`Authorization` headers, GitHub PATs, env-var assignments to
//! `*TOKEN`/`*KEY`/`*SECRET`/etc., URL basic-auth) without mangling normal
//! shell commands. False negatives are preferred over false positives that
//! corrupt the diagnostic value of the log.

use lazy_static::lazy_static;
use regex::Regex;
use std::borrow::Cow;

lazy_static! {
    /// Each entry is `(pattern, replacement)`. Order matters: more specific
    /// patterns run first so a generic match doesn't shadow a structured one.
    static ref PATTERNS: Vec<(Regex, &'static str)> = vec![
        // 1. URL basic-auth (`https://user:password@host`).
        //    Redact both segments — the username can leak who the request was for.
        (
            Regex::new(r"(?P<scheme>https?://)[^:\s/@]+:[^@\s/]+@").unwrap(),
            "${scheme}<REDACTED>:<REDACTED>@",
        ),
        // 2. `Authorization: token <value>` and `Authorization: Bearer <value>`.
        (
            Regex::new(r"(?i)(?P<hdr>Authorization\s*:\s*(?:token|bearer)\s+)\S+").unwrap(),
            "${hdr}<REDACTED>",
        ),
        // 3. GitHub PATs by prefix shape. Whole match (prefix+value) is the secret.
        (
            Regex::new(r"\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]{16,}").unwrap(),
            "<REDACTED_GH_TOKEN>",
        ),
        // 4. Inline env-var assignment to credential-shaped names. Case-insensitive
        //    to catch `TEA_TOKEN=`, `my_secret=`, `Api_Key=`. Suffix list is the
        //    allow-redact set; anything else (e.g. PATH, HOME) is untouched.
        //    Note: matches `(?:_|^)NAME` to avoid eating substrings like "BROKEN".
        //    Value is anything up to whitespace/quote/semicolon.
        (
            Regex::new(
                r#"(?xi)
                (?P<name>
                    \b
                    [a-z][a-z0-9_]*?
                    _(?:token|key|secret|password|pat|apikey|auth)
                    |
                    \b(?:token|key|secret|password|pat|apikey|auth)
                )
                =
                (?P<val>[^\s'";]+)
                "#
            )
            .unwrap(),
            "${name}=<REDACTED>",
        ),
        // 5. CLI flags carrying credentials.
        //    `--token foo`, `--token=foo`, `--password=foo`, `--api-key foo`, etc.
        //    Space-separated or `=`-attached. Captures the whole flag-name segment
        //    so it's preserved in the replacement.
        (
            Regex::new(
                r#"(?xi)
                (?P<flag>
                    --(?:auth[-_])?(?:token|password|api[-_]?key|secret)
                    [\s=]+
                )
                (?P<val>[^\s'";]+)
                "#
            )
            .unwrap(),
            "${flag}<REDACTED>",
        ),
    ];
}

/// Redact secrets from `cmd`. Returns `Cow::Borrowed` if nothing matched
/// (zero-copy fast path) and `Cow::Owned` if any replacement was applied.
pub fn redact(cmd: &str) -> Cow<'_, str> {
    let mut current: Cow<'_, str> = Cow::Borrowed(cmd);
    for (re, replacement) in PATTERNS.iter() {
        let after = re.replace_all(&current, *replacement);
        if let Cow::Owned(s) = after {
            current = Cow::Owned(s);
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secrets_returns_borrowed() {
        let cmd = "git status -sb && cargo test --workspace";
        match redact(cmd) {
            Cow::Borrowed(s) => assert_eq!(s, cmd),
            Cow::Owned(_) => panic!("expected zero-copy on a benign cmd"),
        }
    }

    #[test]
    fn authorization_token_header_is_redacted() {
        let cmd = r#"curl -H "Authorization: token 147dd871c9edab5848377af412b6575bca133169" https://x/api"#;
        let out = redact(cmd);
        assert!(!out.contains("147dd871"), "token leaked: {}", out);
        assert!(out.contains("Authorization: token <REDACTED>"), "header malformed: {}", out);
    }

    #[test]
    fn authorization_bearer_header_is_redacted() {
        let cmd = r#"curl -H "Authorization: Bearer eyJ.abc.def" https://api"#;
        let out = redact(cmd);
        assert!(!out.contains("eyJ.abc.def"));
        assert!(out.contains("Authorization: Bearer <REDACTED>"));
    }

    #[test]
    fn github_pat_prefixes_are_redacted() {
        for prefix in &["ghp_", "gho_", "ghs_", "ghu_", "github_pat_"] {
            let token = format!("{}abcdef0123456789ABCdef", prefix);
            let cmd = format!("gh auth login --with-token {}", token);
            let out = redact(&cmd);
            assert!(!out.contains(&token), "leaked {}: {}", prefix, out);
            assert!(out.contains("<REDACTED_GH_TOKEN>"));
        }
    }

    #[test]
    fn env_var_token_assignment_is_redacted() {
        let cmd = "TEA_TOKEN=147dd871c9edab5848377af412b6575bca133169 tea repos list";
        let out = redact(cmd);
        assert!(!out.contains("147dd871"), "leaked: {}", out);
        assert!(out.contains("TEA_TOKEN=<REDACTED>"));
        // Rest of the command is preserved.
        assert!(out.contains("tea repos list"));
    }

    #[test]
    fn env_var_bare_token_assignment_is_redacted() {
        let cmd = "TOKEN=abc123 do_thing";
        let out = redact(cmd);
        assert!(!out.contains("abc123"));
        assert!(out.contains("TOKEN=<REDACTED>"));
    }

    #[test]
    fn env_var_lowercase_secret_is_redacted() {
        let cmd = "my_secret=hunter2 ./run";
        let out = redact(cmd);
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn path_and_home_are_not_redacted() {
        let cmd = "PATH=/usr/bin:/bin HOME=/Users/x ./tool";
        let out = redact(cmd);
        assert_eq!(out, cmd, "innocuous env vars must not be touched");
    }

    #[test]
    fn cli_flag_token_space_separated_is_redacted() {
        let cmd = "myapp --token deadbeef123 --verbose";
        let out = redact(cmd);
        assert!(!out.contains("deadbeef123"));
        assert!(out.contains("<REDACTED>"));
        assert!(out.contains("--verbose"));
    }

    #[test]
    fn cli_flag_token_equals_is_redacted() {
        let cmd = "myapp --auth-token=deadbeef123 --verbose";
        let out = redact(cmd);
        assert!(!out.contains("deadbeef123"));
    }

    #[test]
    fn cli_flag_password_is_redacted() {
        let cmd = "psql --password=letmein -h db.example";
        let out = redact(cmd);
        assert!(!out.contains("letmein"));
    }

    #[test]
    fn url_basic_auth_is_redacted() {
        let cmd = "git clone https://user:supersecret@github.com/foo/bar.git";
        let out = redact(cmd);
        assert!(!out.contains("supersecret"));
        assert!(!out.contains("user:supersecret@"));
        assert!(out.contains("<REDACTED>:<REDACTED>@github.com"));
    }

    #[test]
    fn redaction_is_idempotent() {
        let cmd = concat!(
            r#"TEA_TOKEN=147dd871 curl -H "Authorization: token abc" "#,
            r#"https://user:pw@host/x && app --token x ghp_abcdef0123456789ABCDEF"#
        );
        let once = redact(cmd).to_string();
        let twice = redact(&once).to_string();
        assert_eq!(once, twice, "redactor must be idempotent");
        // Smoke-check that every secret was caught at least once.
        for needle in &["147dd871", "abc\"", "supersecret", "pw@", "ghp_abcdef"] {
            assert!(!once.contains(needle), "leaked {:?}: {}", needle, once);
        }
    }

    #[test]
    fn multiple_secrets_in_one_cmd_all_redacted() {
        let cmd = "TEA_TOKEN=aaa MY_API_KEY=bbb curl -H 'Authorization: token ccc' https://x";
        let out = redact(cmd);
        for needle in &["aaa", "bbb", "ccc"] {
            assert!(!out.contains(needle), "leaked {}: {}", needle, out);
        }
    }

    #[test]
    fn benign_text_with_token_word_unchanged() {
        // "token" appearing in prose, not as a credential, must not trigger anything.
        let cmd = "echo 'how token rotation works'";
        let out = redact(cmd);
        assert_eq!(out, cmd);
    }
}
