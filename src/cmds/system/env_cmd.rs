//! Filters environment variables, hiding secrets and noise.

use crate::core::tracking;
use anyhow::Result;
use std::collections::HashSet;
use std::env;
use std::fmt::Write;

/// Show filtered environment variables (hide sensitive data)
pub fn run(filter: Option<&str>, show_all: bool, verbose: u8) -> Result<()> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Environment variables:");
    }

    let sensitive_patterns = get_sensitive_patterns();
    let mut vars: Vec<(String, String)> = env::vars().collect();
    vars.sort_by(|a, b| a.0.cmp(&b.0));

    // Interesting categories
    let mut path_vars = Vec::new();
    let mut lang_vars = Vec::new();
    let mut cloud_vars = Vec::new();
    let mut tool_vars = Vec::new();
    let mut other_vars = Vec::new();

    for (key, value) in &vars {
        // Apply filter if provided
        if let Some(f) = filter {
            if !key.to_lowercase().contains(&f.to_lowercase()) {
                continue;
            }
        }

        // Check if sensitive: by key name (substring) OR by value content.
        // Value-aware detection catches secrets stored under innocuous keys
        // like DATABASE_URL or a connection string (#100, G5#3).
        let is_sensitive = sensitive_patterns
            .iter()
            .any(|p| key.to_lowercase().contains(p))
            || value_looks_sensitive(value);

        let display_value = if is_sensitive && !show_all {
            mask_value(value)
        } else if value.len() > 100 {
            let preview: String = value.chars().take(50).collect();
            format!("{}... ({} chars)", preview, value.chars().count())
        } else {
            value.clone()
        };

        let entry = (key.clone(), display_value);

        // Categorize
        if key.contains("PATH") {
            path_vars.push(entry);
        } else if is_lang_var(key) {
            lang_vars.push(entry);
        } else if is_cloud_var(key) {
            cloud_vars.push(entry);
        } else if is_tool_var(key) {
            tool_vars.push(entry);
        } else if filter.is_some() || is_interesting_var(key) {
            other_vars.push(entry);
        }
    }

    // Print categorized
    if !path_vars.is_empty() {
        println!("PATH Variables:");
        for (k, v) in &path_vars {
            if k == "PATH" {
                // Split PATH for readability
                let paths: Vec<&str> = v.split(':').collect();
                println!("  PATH ({} entries):", paths.len());
                for p in paths.iter().take(5) {
                    println!("    {}", p);
                }
                if paths.len() > 5 {
                    println!("    ... +{} more", paths.len() - 5);
                }
            } else {
                println!("  {}={}", k, v);
            }
        }
    }

    if !lang_vars.is_empty() {
        println!("\nLanguage/Runtime:");
        for (k, v) in &lang_vars {
            println!("  {}={}", k, v);
        }
    }

    if !cloud_vars.is_empty() {
        println!("\nCloud/Services:");
        for (k, v) in &cloud_vars {
            println!("  {}={}", k, v);
        }
    }

    if !tool_vars.is_empty() {
        println!("\nTools:");
        for (k, v) in &tool_vars {
            println!("  {}={}", k, v);
        }
    }

    if !other_vars.is_empty() {
        println!("\nOther:");
        for (k, v) in other_vars.iter().take(20) {
            println!("  {}={}", k, v);
        }
        if other_vars.len() > 20 {
            println!("  ... +{} more", other_vars.len() - 20);
        }
    }

    let total = vars.len();
    let shown = path_vars.len()
        + lang_vars.len()
        + cloud_vars.len()
        + tool_vars.len()
        + other_vars.len().min(20);
    if filter.is_none() {
        println!("\nTotal: {} vars (showing {} relevant)", total, shown);
    }

    let raw: String = vars.iter().fold(String::new(), |mut output, (k, v)| {
        let _ = writeln!(output, "{}={}", k, v);
        output
    });
    let ctxcrl = format!("{} vars -> {} shown", total, shown);
    timer.track("env", "contextcrawler env", &raw, &ctxcrl);
    Ok(())
}

fn get_sensitive_patterns() -> HashSet<&'static str> {
    let mut set = HashSet::new();
    set.insert("key");
    set.insert("secret");
    set.insert("password");
    set.insert("token");
    set.insert("credential");
    set.insert("auth");
    set.insert("private");
    set.insert("api_key");
    set.insert("apikey");
    set.insert("access_key");
    set.insert("jwt");
    set
}

/// Value-aware secret detection. Returns true when the *value* of an env var
/// looks like it carries a credential, regardless of how innocuous the key
/// name is (e.g. `DATABASE_URL=postgres://user:pass@host/db`). This is the
/// second line of defence behind the key-substring check (#100, G5#3).
fn value_looks_sensitive(value: &str) -> bool {
    use lazy_static::lazy_static;
    use regex::Regex;
    lazy_static! {
        // URL with embedded `user:password@` credentials.
        static ref URL_CREDS: Regex =
            Regex::new(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s]+:[^@\s]+@").unwrap();
        // AWS access key id (AKIA / ASIA + 16 chars).
        static ref AWS_KEY: Regex = Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap();
        // GitHub tokens (classic + fine-grained PATs).
        static ref GH_TOKEN: Regex =
            Regex::new(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]+)\b").unwrap();
        // Slack tokens.
        static ref SLACK_TOKEN: Regex = Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap();
        // JWT: three base64url segments separated by dots.
        static ref JWT: Regex =
            Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap();
        // `password=` / `token=` / `secret=` style key/value pairs embedded
        // in a connection string or DSN.
        static ref EMBEDDED_KV: Regex = Regex::new(
            r"(?i)(?:password|passwd|pwd|token|secret|api[-_]?key)\s*[=:]\s*\S+"
        ).unwrap();
    }
    URL_CREDS.is_match(value)
        || AWS_KEY.is_match(value)
        || GH_TOKEN.is_match(value)
        || SLACK_TOKEN.is_match(value)
        || JWT.is_match(value)
        || EMBEDDED_KV.is_match(value)
        || looks_like_high_entropy_secret(value)
}

/// Heuristic: does `value` genuinely look like a filesystem path or URL,
/// rather than a secret that merely contains a `/`?
///
/// The standard base64 alphabet is `A-Za-z0-9+/`, so a bare `/` in the
/// MIDDLE of an otherwise high-entropy token is a common feature of real
/// secrets — it must NOT exclude the value. We only treat a value as a
/// path when it has a structural path/URL marker, and ONLY then:
///   * an absolute / relative / home prefix (`/`, `./`, `../`, `~/`,
///     `.\`, `..\`),
///   * a Windows drive prefix (`C:\`, `D:/`),
///   * a URL scheme (`scheme://`).
///
/// A marker-less multi-segment value (`usr/local/bin`) is deliberately
/// NOT classified as a path here — it is low-entropy, so the downstream
/// entropy gate declines to mask it anyway, and refusing to short-circuit
/// keeps high-entropy two-slash secrets from escaping the gate.
fn looks_like_path(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // Absolute / relative / home-dir prefixes.
    if value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
    {
        return true;
    }
    // Windows drive-letter absolute path: `C:\…` or `D:/…`.
    let bytes = value.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    // URL: `scheme://host/…`.
    if value.contains("://") {
        return true;
    }
    // STRUCTURAL-MARKER-ONLY: a value is classified as a path ONLY when it
    // carries one of the structural markers above (leading `/ ./ ../ ~/`,
    // Windows drive prefix, or a `://` URL scheme). The earlier bare
    // 3-segment heuristic was removed (Codex re-review, fourth pass): a
    // base64 secret containing two `/` chars splits into three short-ish
    // low-entropy-looking segments and was wrongly classified as a path,
    // escaping masking before the entropy gate ran (AWS secret access keys
    // are 40-char base64 and can contain `/`).
    //
    // Dropping the marker-less branch is safe in both directions:
    //   * A genuine marker-less relative path (`usr/local/bin`) is
    //     low-entropy, so the downstream entropy gate declines to mask it
    //     anyway — paths stay unmasked.
    //   * A high-entropy secret containing `/` now reaches the entropy
    //     gate and gets masked.
    false
}

/// Catch-all for bare high-entropy secrets that have NO recognisable vendor
/// prefix — a raw API key, a random hex/base64 blob stored under an innocuous
/// key name (#100, G5#3 follow-up).
///
/// Conservative by design: over-masking an env var is acceptable, leaking a
/// key is not — but we must NOT mask long innocuous values like `PATH`.
/// Exclusions:
///   * anything with whitespace (sentences, multi-token settings)
///   * a value that `looks_like_path` (paths, URLs) AND is itself
///     low-entropy — note the path exclusion is entropy-aware (fifth
///     pass): a marker-prefixed value that independently clears the
///     entropy floor is still treated as a secret, so a high-entropy
///     blob with a leading `/`, `./`, `~/` etc. cannot evade masking.
///     A bare `/` inside a token is likewise not excluded (base64 uses `/`)
///   * filename-ish strings (≥ 2 dots, e.g. `app.config.json`)
///   * values not built mostly from secret-shaped chars `[A-Za-z0-9_\-+/=.]`
///
/// Residual (documented, intentionally not handled): an all-digit value
/// never qualifies — `class_count < 2` filters it out. Masking every long
/// digit string would false-positive on PIDs, timestamps and port lists,
/// and a key-name allowlist proved too noisy to be worth it. A long
/// purely-numeric secret (e.g. a TOTP seed) therefore stays unmasked here;
/// such values are expected to be caught by the key-name substring check
/// (`*secret*`, `*token*`, …) in `value_looks_sensitive`'s caller.
///
/// Core test: a long (≥ 16 char) single token with high Shannon entropy
/// (≥ 3.5 bits/char) and mixed character classes.
fn looks_like_high_entropy_secret(value: &str) -> bool {
    // 16-char floor catches opaque 16-char keys; the entropy + class-count
    // gates keep ordinary 16-char identifiers from over-masking.
    const MIN_LEN: usize = 16;
    const MIN_ENTROPY: f64 = 3.5;

    let raw = value.trim();

    // Strip a single leading structural path marker before the secret-shape
    // and entropy gates run (Codex re-review, fifth pass). A high-entropy
    // secret that merely starts with `/`, `./`, `../` or `~/` must not be
    // disqualified by the marker itself: `~` is not a secret-shaped char,
    // so a `~/`-prefixed blob would otherwise fail the `secret_shaped`
    // gate. Measuring the marker-stripped body keeps the entropy verdict
    // honest while leaving `looks_like_path` untouched. Genuine paths are
    // low-entropy with or without the marker, so they still decline below.
    let token: &str = ["~/", "../", "./", "/"]
        .iter()
        .find_map(|m| raw.strip_prefix(m))
        .unwrap_or(raw);

    if token.chars().count() < MIN_LEN {
        return false;
    }
    // Whitespace → not a bare token; bail.
    if token.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    // Filename-ish (multiple dots) → almost certainly not a secret.
    if token.matches('.').count() >= 2 {
        return false;
    }
    // Must be built almost entirely from secret-shaped characters.
    // `/` is part of the standard base64 alphabet (`A-Za-z0-9+/`), so it
    // is secret-shaped; a path-shaped `/` value was already excluded above.
    let secret_shaped = |c: char| c.is_ascii_alphanumeric() || "_-+=./".contains(c);
    if !token.chars().all(secret_shaped) {
        return false;
    }
    // Require character-class diversity: a long run of one class (e.g. a
    // pure-lowercase identifier or a pure-digit number) is not key-shaped.
    let has_lower = token.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = token.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let class_count =
        [has_lower, has_upper, has_digit].iter().filter(|&&b| b).count();
    if class_count < 2 {
        return false;
    }

    // Final verdict: a value is a secret when it clears the entropy floor.
    let high_entropy = shannon_entropy(token) >= MIN_ENTROPY;

    // Path exclusion is ENTROPY-AWARE (Codex re-review, fifth pass).
    // `looks_like_path` short-circuiting here let a genuinely high-entropy
    // secret that merely *starts* with a structural marker (`/`, `./`,
    // `../`, `~/`, a Windows drive prefix) or contains `://` bypass the
    // entropy gate entirely — a real masking-evasion vector.
    //
    // The path exclusion must NOT override an independently-confirmed
    // high-entropy secret. A real filesystem path is low-entropy, so
    // ordering the entropy determination first costs the genuine path
    // cases nothing: `PATH`, `./relative/path`, `https://example.com/x`
    // and `C:\Users\x` are all low-entropy and still decline below.
    // `looks_like_path` is consulted on the ORIGINAL value — the structural
    // marker that classifies it as a path was stripped from `token` above.
    if !high_entropy && looks_like_path(raw) {
        return false;
    }

    high_entropy
}

/// Shannon entropy in bits per character. ~3.5+ on a long token indicates
/// a random/key-like value; structured English or repetitive strings sit
/// well below that.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut len = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        len += 1;
    }
    if len == 0 {
        return 0.0;
    }
    let len = len as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        "****".to_string()
    } else {
        let prefix: String = chars[..2].iter().collect();
        let suffix: String = chars[chars.len() - 2..].iter().collect();
        format!("{}****{}", prefix, suffix)
    }
}

fn is_lang_var(key: &str) -> bool {
    let patterns = [
        "RUST", "CARGO", "PYTHON", "PIP", "NODE", "NPM", "YARN", "DENO", "BUN", "JAVA", "MAVEN",
        "GRADLE", "GO", "GOPATH", "GOROOT", "RUBY", "GEM", "PERL", "PHP", "DOTNET", "NUGET",
    ];
    patterns.iter().any(|p| key.to_uppercase().contains(p))
}

fn is_cloud_var(key: &str) -> bool {
    let patterns = [
        "AWS",
        "AZURE",
        "GCP",
        "GOOGLE_CLOUD",
        "DOCKER",
        "KUBERNETES",
        "K8S",
        "HELM",
        "TERRAFORM",
        "VAULT",
        "CONSUL",
        "NOMAD",
    ];
    patterns.iter().any(|p| key.to_uppercase().contains(p))
}

fn is_tool_var(key: &str) -> bool {
    let patterns = [
        "EDITOR",
        "VISUAL",
        "SHELL",
        "TERM",
        "GIT",
        "SSH",
        "GPG",
        "BREW",
        "HOMEBREW",
        "XDG",
        "CLAUDE",
        "ANTHROPIC",
    ];
    patterns.iter().any(|p| key.to_uppercase().contains(p))
}

fn is_interesting_var(key: &str) -> bool {
    let patterns = ["HOME", "USER", "LANG", "LC_", "TZ", "PWD", "OLDPWD"];
    patterns.iter().any(|p| key.to_uppercase().starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_value_short() {
        assert_eq!(mask_value("abc"), "****");
        assert_eq!(mask_value(""), "****");
    }

    #[test]
    fn test_mask_value_long() {
        let result = mask_value("supersecrettoken");
        assert!(result.contains("****"), "Masked value should contain ****");
        assert!(result.starts_with("su"), "Should preserve 2-char prefix");
        assert!(result.ends_with("en"), "Should preserve 2-char suffix");
    }

    #[test]
    fn test_mask_value_exactly_four() {
        assert_eq!(mask_value("abcd"), "****");
    }

    #[test]
    fn test_mask_value_five_chars() {
        let result = mask_value("abcde");
        assert!(result.starts_with("ab"));
        assert!(result.ends_with("de"));
    }

    #[test]
    fn test_is_lang_var_rust() {
        assert!(is_lang_var("RUST_LOG"));
        assert!(is_lang_var("CARGO_HOME"));
        assert!(is_lang_var("GOPATH"));
        assert!(is_lang_var("NODE_ENV"));
    }

    #[test]
    fn test_is_lang_var_negative() {
        assert!(!is_lang_var("HOME"));
        assert!(!is_lang_var("PATH"));
        assert!(!is_lang_var("USER"));
    }

    #[test]
    fn test_is_cloud_var() {
        assert!(is_cloud_var("AWS_ACCESS_KEY_ID"));
        assert!(is_cloud_var("AZURE_CLIENT_ID"));
        assert!(is_cloud_var("DOCKER_HOST"));
        assert!(is_cloud_var("KUBERNETES_SERVICE_HOST"));
    }

    #[test]
    fn test_is_cloud_var_negative() {
        assert!(!is_cloud_var("HOME"));
        assert!(!is_cloud_var("RUST_LOG"));
    }

    #[test]
    fn test_is_tool_var() {
        assert!(is_tool_var("EDITOR"));
        assert!(is_tool_var("GIT_AUTHOR_NAME"));
        assert!(is_tool_var("SSH_AUTH_SOCK"));
        assert!(is_tool_var("CLAUDE_API_KEY"));
    }

    #[test]
    fn test_is_interesting_var() {
        assert!(is_interesting_var("HOME"));
        assert!(is_interesting_var("USER"));
        assert!(is_interesting_var("LANG"));
        assert!(is_interesting_var("TZ"));
        assert!(is_interesting_var("PWD"));
    }

    #[test]
    fn test_is_interesting_var_negative() {
        assert!(!is_interesting_var("RANDOM_VAR"));
        assert!(!is_interesting_var("MY_CUSTOM_VAR"));
    }

    // --- #100 G5#3: value-aware secret detection ---

    #[test]
    fn test_value_looks_sensitive_url_credentials() {
        assert!(value_looks_sensitive(
            "postgres://admin:hunter2@db.example.com:5432/app"
        ));
        assert!(value_looks_sensitive("redis://user:pass@cache:6379"));
    }

    #[test]
    fn test_value_looks_sensitive_tokens() {
        assert!(value_looks_sensitive("AKIAIOSFODNN7EXAMPLE"));
        assert!(value_looks_sensitive(
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
        ));
        // Assembled at runtime so the source carries no token-shaped literal
        // (GitHub push-protection pattern-matches a contiguous `xox?-` prefix).
        let slack_shaped = format!("xox{}-1234567890-abcdefghijklmnop", "b");
        assert!(value_looks_sensitive(&slack_shaped));
    }

    #[test]
    fn test_value_looks_sensitive_jwt_and_embedded_kv() {
        assert!(value_looks_sensitive(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123_-"
        ));
        assert!(value_looks_sensitive("host=db;password=secret123"));
    }

    #[test]
    fn test_value_looks_sensitive_negative() {
        assert!(!value_looks_sensitive("/usr/local/bin:/usr/bin"));
        assert!(!value_looks_sensitive("production"));
        assert!(!value_looks_sensitive("https://example.com/path"));
        assert!(!value_looks_sensitive(""));
    }

    // --- #100 G5#3 follow-up: bare high-entropy secret detection ---

    #[test]
    fn test_value_looks_sensitive_bare_api_key() {
        // A random API key with NO vendor prefix, stored under an
        // innocuous key name, must still be masked.
        assert!(
            value_looks_sensitive("k3J9xQ7pL2mN8vR4tW1zB6yD0aC5sF7g"),
            "random 32-char API key should be flagged"
        );
        // A long random hex blob (still mixed-class: digits + letters).
        assert!(
            value_looks_sensitive("9f8a3c7e2b1d6049af3e8c2d7b194a06fe55"),
            "random hex secret should be flagged"
        );
        // base64-ish secret with +/= shaped chars.
        assert!(
            value_looks_sensitive("aGVsbG8td29ybGQtc2VjcmV0LXZhbHVlPT0K"),
            "base64-shaped secret should be flagged"
        );
    }

    #[test]
    fn test_value_looks_sensitive_long_path_not_masked() {
        // A long PATH-like value must NOT be masked — `/` exclusion.
        assert!(!value_looks_sensitive(
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin"
        ));
        // Filename-ish dotted string — not a secret.
        assert!(!value_looks_sensitive("my.application.config.json"));
        // Long but low-entropy / single-class identifier — not a secret.
        assert!(!value_looks_sensitive(
            "this_is_a_very_long_descriptive_setting_name"
        ));
        // Long all-digit value (single class) — not a secret.
        assert!(!value_looks_sensitive("123456789012345678901234567890"));
        // A value with spaces is not a bare token.
        assert!(!value_looks_sensitive(
            "the quick brown fox jumps over the lazy dog again"
        ));
    }

    #[test]
    fn test_value_looks_sensitive_base64_secret_with_slash() {
        // CRITICAL regression (#100, G5 third pass): a base64-encoded
        // secret containing `/` must still be masked. The standard base64
        // alphabet is `A-Za-z0-9+/`, so the old bare `/` exclusion let
        // these leak entirely.
        assert!(
            value_looks_sensitive("dGhpcy9pcy9hL3NlY3JldC92YWx1ZQ=="),
            "base64 secret containing `/` should be flagged"
        );
        assert!(
            value_looks_sensitive("aGVsbG8tbW9yZS1zdHVmZg/x+z1234567890=="),
            "mixed base64 token with a `/` should be flagged"
        );
    }

    #[test]
    fn test_value_looks_sensitive_two_slash_base64_secret() {
        // CRITICAL regression (#100, G5 fourth pass): an AWS-secret-key
        // shaped 40-char base64 token containing TWO `/` chars splits into
        // three short-ish segments. The old bare 3-segment path branch
        // wrongly classified it as a path and let it escape masking. With
        // the structural-marker-only heuristic it now reaches the entropy
        // gate and is masked.
        assert!(
            value_looks_sensitive("wJalr/XUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            "two-slash AWS-shaped base64 secret should be flagged"
        );
        // One-slash 32+ char base64 secret — third-pass regression guard.
        assert!(
            value_looks_sensitive("abcDEF123ghiJKL456mno/PQR789stuVWX"),
            "single-slash base64 secret should still be flagged"
        );
        // Both-directions safety: a marker-less low-entropy relative path
        // must stay UNMASKED — the entropy gate declines it on its own.
        assert!(
            !value_looks_sensitive("usr/share/man"),
            "marker-less low-entropy relative path must not be masked"
        );
    }

    #[test]
    fn test_value_looks_sensitive_marker_prefixed_high_entropy_secret() {
        // IMPORTANT regression (#100, G5 fifth pass): a genuinely
        // high-entropy secret that merely STARTS with a structural path
        // marker (`/`, `./`, `~/`, a Windows drive prefix) used to bypass
        // the entropy gate via the `looks_like_path` short-circuit. The
        // path exclusion is now entropy-aware — entropy wins.
        assert!(
            value_looks_sensitive("/AbItH5K9xQ2vP7mNwR4tZ8sLcU3eY6fGdHjKpL"),
            "leading-`/` high-entropy secret should be flagged"
        );
        assert!(
            value_looks_sensitive("./AbItH5K9xQ2vP7mNwR4tZ8sLcU3eY6fGdHjKpL"),
            "leading-`./` high-entropy secret should be flagged"
        );
        assert!(
            value_looks_sensitive("~/AbItH5K9xQ2vP7mNwR4tZ8sLcU3eY6fGdHjKpL"),
            "leading-`~/` high-entropy secret should be flagged"
        );
        // Genuine low-entropy paths still escape — the path exclusion only
        // declines a value that does NOT independently clear the gate.
        assert!(
            !value_looks_sensitive("/usr/local/bin:/usr/bin:/bin"),
            "PATH-style value must stay unmasked"
        );
        assert!(
            !value_looks_sensitive("./relative/path/to/file"),
            "relative path must stay unmasked"
        );
        assert!(
            !value_looks_sensitive("https://example.com/a/b"),
            "URL must stay unmasked"
        );
        assert!(
            !value_looks_sensitive(r"C:\Users\someuser\projects"),
            "Windows path must stay unmasked"
        );
    }

    #[test]
    fn test_looks_like_path_heuristic() {
        // Genuine paths / URLs are paths.
        assert!(looks_like_path("/usr/local/bin"));
        assert!(looks_like_path("./relative/path"));
        assert!(looks_like_path("../up/one"));
        assert!(looks_like_path("~/home/dir"));
        assert!(looks_like_path(r"C:\windows\path"));
        assert!(looks_like_path("https://example.com/x"));
        // STRUCTURAL-MARKER-ONLY (fourth pass): a marker-less multi-segment
        // value is NOT classified as a path here — it relies on the
        // downstream entropy gate, which declines low-entropy values.
        assert!(!looks_like_path("usr/local/bin"));
        assert!(!looks_like_path("usr/share/man"));
        // A `/` inside a high-entropy token is NOT a path — including the
        // two-slash base64 case that splits into three short segments.
        assert!(!looks_like_path("dGhpcy9pcy1zZWNyZXQtdmFsdWU="));
        assert!(!looks_like_path("k3J9xQ7p/L2mN8vR4tW1zB6yD"));
        assert!(!looks_like_path("wJalr/XUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"));
        assert!(!looks_like_path("plainvalue"));
        assert!(!looks_like_path(""));
    }

    #[test]
    fn test_value_looks_sensitive_paths_not_masked() {
        // PATH-style value: many short path-shaped segments → not a secret.
        assert!(!value_looks_sensitive(
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ));
        assert!(!value_looks_sensitive("./relative/path/to/file"));
        assert!(!value_looks_sensitive("https://example.com/some/path"));
    }

    #[test]
    fn test_shannon_entropy_ordering() {
        // Random key beats a repetitive string in bits/char.
        let random = shannon_entropy("k3J9xQ7pL2mN8vR4tW1zB6yD");
        let repetitive = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(random > repetitive);
        assert!(random >= 3.5, "random token entropy was {}", random);
        assert!(repetitive < 1.0);
    }

    #[test]
    fn test_sensitive_patterns_contains_keys() {
        let patterns = get_sensitive_patterns();
        assert!(patterns.contains("key"));
        assert!(patterns.contains("secret"));
        assert!(patterns.contains("password"));
        assert!(patterns.contains("token"));
    }
}
