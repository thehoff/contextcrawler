//! Redact common secret shapes from a shell command string before it lands in
//! an audit log on disk. Belt-and-braces: the gate logs are user-readable and
//! sit at predictable paths, so any token captured verbatim is a leak.
//!
//! Conservative on purpose. The goal is to scrub obvious credentials
//! (`Authorization` headers, GitHub PATs, env-var assignments to
//! `*TOKEN`/`*KEY`/`*SECRET`/etc., URL basic-auth) without mangling normal
//! shell commands. False negatives are preferred over false positives that
//! corrupt the diagnostic value of the log.
//!
//! Known limitations (intentional false negatives):
//! - Bare-shape secrets like `T=<40-hex>` (one-letter alias to a token) are
//!   not redacted: a name-only heuristic can't safely distinguish a token
//!   value from a git SHA without context. If a downstream consumer reuses
//!   the alias in an `Authorization` header within the same cmd string, the
//!   header-side match still scrubs that occurrence.

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
        // 5. git-credential-helper format inside a piped string:
        //    `protocol=http\nhost=...\nusername=...\npassword=<TOKEN>`
        //    The literal `\n` puts the secret name mid-word from the regex
        //    engine's POV, so `\b` (pattern 4) doesn't anchor. Match the
        //    escape-prefix explicitly and preserve it.
        (
            Regex::new(
                r#"(?xi)
                (?P<pfx>\\n|\\r)
                (?P<name>password|token|secret|auth)
                =
                (?P<val>[^\s'";\\]+)
                "#
            )
            .unwrap(),
            "${pfx}${name}=<REDACTED>",
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
        // 6. JSON credential fields in command *output* (API responses, aws cli,
        //    curl). `"password": "v"`, `"SecretString": "..."`, `"SessionToken": ...`.
        //    Tee recovery files carry raw output, so output shapes matter as much
        //    as command shapes. Conservative name list; the value may contain
        //    escaped quotes (nested JSON, e.g. secretsmanager SecretString).
        //    Prefix/suffix around the credential word must be separated by `_`/`-`
        //    so benign fields ("tokenizer", "secretary") keep their values.
        //    camelCase compounds (accessToken, refreshToken, idToken, apiKey…)
        //    are listed explicitly since they have no separator to anchor on.
        (
            Regex::new(
                r#"(?xi)
                "(?P<name>
                    (?: [a-z0-9_-]* [_-] )?
                    (?: password | passwd | secret | token | api[_-]?key
                      | secret[_-]?access[_-]?key | session[_-]?token | private[_-]?key
                      | client[_-]?secret | secret[_-]?string | secret[_-]?binary
                      | access[_-]?token | refresh[_-]?token | id[_-]?token
                      | auth[_-]?token | bearer[_-]?token
                      | credentials?
                    )
                    (?: [_-] [a-z0-9_-]* )?
                )"
                \s* : \s*
                "(?P<val>(?:[^"\\]|\\.)*)"
                "#
            )
            .unwrap(),
            r#""${name}": "<REDACTED>""#,
        ),
        // 7. PEM private key blocks (openssl/ssh-keygen output, leaked key files
        //    cat'd to stdout). Whole block is the secret. Mixed-case label chars
        //    so vendor variants of the BEGIN/END header all match. Body is
        //    non-greedy any-char: encrypted PEMs carry armor headers
        //    (`Proc-Type:`, `DEK-Info:`) that a base64-only body would miss,
        //    and non-greedy + a required END footer means a truncated block
        //    simply doesn't match (no risk of swallowing trailing output).
        //    Known limitation: a truncated block (BEGIN, no END) followed by a
        //    complete block over-redacts the text between them — the regex
        //    crate has no lookaround to refuse crossing a second BEGIN, and
        //    over-redaction of malformed-key output is the safe direction.
        (
            Regex::new(
                r"-----BEGIN [A-Za-z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Za-z0-9 ]*PRIVATE KEY-----"
            )
            .unwrap(),
            "<REDACTED_PRIVATE_KEY>",
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
        assert!(
            out.contains("Authorization: token <REDACTED>"),
            "header malformed: {}",
            out
        );
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
    fn git_credential_helper_password_redacted() {
        // git credential-osxkeychain / credential-store / cache feed a stream
        // like `protocol=...\nhost=...\nusername=...\npassword=<TOKEN>` over a
        // pipe. The literal `\n` defeats `\b`-anchored env-var matching.
        let cmd = r#"printf "protocol=http\nhost=gitea.example\nusername=alice\npassword=147dd871c9edab5848377af412b6575bca133169\n\n" | git credential-store"#;
        let out = redact(cmd);
        assert!(!out.contains("147dd871"), "leaked: {}", out);
        assert!(out.contains(r"\npassword=<REDACTED>"));
        // Preserves benign neighbouring assignments.
        assert!(out.contains(r"\nusername=alice"));
        assert!(out.contains(r"\nhost=gitea.example"));
    }

    #[test]
    fn benign_text_with_token_word_unchanged() {
        // "token" appearing in prose, not as a credential, must not trigger anything.
        let cmd = "echo 'how token rotation works'";
        let out = redact(cmd);
        assert_eq!(out, cmd);
    }

    // --- Output-shaped secrets (tee recovery files carry command *output*,
    //     not just command strings — JSON API responses, aws cli, curl) ---

    #[test]
    fn json_credential_fields_are_redacted() {
        let output = r#"{"username": "admin", "password": "hunter2", "token": "tok_abc123"}"#;
        let out = redact(output);
        assert!(!out.contains("hunter2"), "leaked: {}", out);
        assert!(!out.contains("tok_abc123"), "leaked: {}", out);
        // Benign fields preserved for diagnostic value.
        assert!(
            out.contains(r#""username": "admin""#),
            "benign field mangled: {}",
            out
        );
    }

    #[test]
    fn aws_secretsmanager_payload_is_redacted() {
        // `aws secretsmanager get-secret-value` output: the SecretString value
        // is itself escaped JSON carrying credentials.
        let output = r#"{"ARN": "arn:aws:secretsmanager:ap-southeast-2:123:secret:x", "Name": "prod/db", "SecretString": "{\"user\":\"admin\",\"password\":\"hunter2\"}", "VersionId": "v1"}"#;
        let out = redact(output);
        assert!(!out.contains("hunter2"), "leaked: {}", out);
        assert!(
            out.contains(r#""Name": "prod/db""#),
            "benign field mangled: {}",
            out
        );
    }

    #[test]
    fn aws_sts_credentials_are_redacted() {
        // `aws sts assume-role` / `get-session-token` output shape.
        let output = r#"{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "SessionToken": "FwoGZXIvYXdzEJrLongOpaqueBlob"}"#;
        let out = redact(output);
        assert!(
            !out.contains("wJalrXUtnFEMI"),
            "secret access key leaked: {}",
            out
        );
        assert!(
            !out.contains("FwoGZXIvYXdzEJr"),
            "session token leaked: {}",
            out
        );
    }

    #[test]
    fn pem_private_key_block_is_redacted() {
        let output = "connecting...\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7qqq\nzzz999\n-----END RSA PRIVATE KEY-----\ndone";
        let out = redact(output);
        assert!(
            !out.contains("MIIEpAIBAAKCAQEA7qqq"),
            "private key leaked: {}",
            out
        );
        assert!(
            out.contains("<REDACTED_PRIVATE_KEY>"),
            "marker missing: {}",
            out
        );
        // Surrounding diagnostic output preserved.
        assert!(out.contains("connecting..."));
        assert!(out.contains("done"));
    }

    #[test]
    fn benign_fields_with_credential_substrings_unchanged() {
        // Council review (codex+agy): substring matches must not over-redact.
        let output =
            r#"{"tokenizer": "bert-base", "secretary": "Jane Smith", "tokenization": "bpe"}"#;
        let out = redact(output);
        assert!(
            out.contains(r#""tokenizer": "bert-base""#),
            "over-redacted: {}",
            out
        );
        assert!(
            out.contains(r#""secretary": "Jane Smith""#),
            "over-redacted: {}",
            out
        );
        assert!(
            out.contains(r#""tokenization": "bpe""#),
            "over-redacted: {}",
            out
        );
    }

    #[test]
    fn kebab_case_json_credentials_are_redacted() {
        // Council review (agy): kebab-case keys are common in OAuth/k8s output.
        let output =
            r#"{"client-secret": "s3cr3t", "session-token": "tok123", "client-id": "public-app"}"#;
        let out = redact(output);
        assert!(!out.contains("s3cr3t"), "leaked: {}", out);
        assert!(!out.contains("tok123"), "leaked: {}", out);
        // client-id is an identifier, not a secret.
        assert!(
            out.contains(r#""client-id": "public-app""#),
            "over-redacted: {}",
            out
        );
    }

    #[test]
    fn camelcase_oauth_tokens_are_redacted() {
        // Council review (codex): OAuth response shapes use camelCase keys.
        let output = r#"{"accessToken": "ya29.a0AfB_secret", "refreshToken": "1//0gREFRESH", "idToken": "eyJhbGciOi", "expiresIn": 3599}"#;
        let out = redact(output);
        assert!(!out.contains("ya29.a0AfB_secret"), "leaked: {}", out);
        assert!(!out.contains("1//0gREFRESH"), "leaked: {}", out);
        assert!(!out.contains("eyJhbGciOi"), "leaked: {}", out);
        // Non-credential field preserved.
        assert!(
            out.contains(r#""expiresIn": 3599"#),
            "over-redacted: {}",
            out
        );
    }

    #[test]
    fn openssh_pem_block_is_redacted() {
        // Council review (agy): cover ssh-keygen OpenSSH-format headers.
        let output = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----";
        let out = redact(output);
        assert!(!out.contains("b3BlbnNzaC1rZXk"), "leaked: {}", out);
        assert!(out.contains("<REDACTED_PRIVATE_KEY>"));
    }

    #[test]
    fn encrypted_pem_with_armor_headers_is_redacted() {
        // Council round-4: encrypted private keys carry Proc-Type/DEK-Info
        // armor headers between BEGIN and the base64 body — must still match.
        let output = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,8E2F...\n\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let out = redact(output);
        assert!(
            !out.contains("MIIEowIBAAKCAQEA"),
            "encrypted key body leaked: {}",
            out
        );
        assert!(!out.contains("DEK-Info"), "armor header leaked: {}", out);
        assert!(out.contains("<REDACTED_PRIVATE_KEY>"));
    }

    #[test]
    fn truncated_pem_block_does_not_swallow_output() {
        // A BEGIN with no END (truncated output) must not match at all —
        // non-greedy + required footer means no swallowing of trailing text.
        let output = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n... output truncated, no footer ...\nnext command output here";
        let out = redact(output);
        assert!(
            out.contains("next command output here"),
            "trailing output swallowed: {}",
            out
        );
    }

    #[test]
    fn truncated_pem_before_complete_block_over_redacts_safely() {
        // Known limitation (council round-5, rejected fix): the regex crate
        // has no lookaround, so a truncated block followed by a complete one
        // redacts everything between the first BEGIN and the final END.
        // Over-redaction is the safe direction — assert no key material leaks
        // and the redaction marker is present.
        let output = "-----BEGIN RSA PRIVATE KEY-----\ntruncated-no-end\nsome text between\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIs\n-----END EC PRIVATE KEY-----";
        let out = redact(output);
        assert!(!out.contains("MHcCAQEEIIs"), "key material leaked: {}", out);
        assert!(out.contains("<REDACTED_PRIVATE_KEY>"));
    }

    #[test]
    fn benign_json_output_unchanged() {
        // Ordinary JSON command output must pass through untouched (zero-copy).
        let output =
            r#"{"name": "contextcrawler", "version": "0.1.10", "files": ["a.rs", "b.rs"]}"#;
        match redact(output) {
            Cow::Borrowed(s) => assert_eq!(s, output),
            Cow::Owned(o) => panic!("benign JSON was modified: {}", o),
        }
    }
}
