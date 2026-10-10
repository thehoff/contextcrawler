//! Detects commands that read credential-bearing files (#206).
//!
//! ContextCrawler's hook auto-allows commands it can rewrite. For a secret
//! file that is worse than doing nothing: `cat .env` was rewritten to
//! `contextcrawler read .env` **and** returned with
//! `permissionDecision: "allow"`, printing the secrets in full. Installing
//! contextcrawler therefore made a read *more* permitted than not installing
//! it — the one outcome a filtering proxy must never produce.
//!
//! This module answers one question: does this command name a path whose
//! contents are, by convention, secret? A match downgrades the hook decision
//! to `ask`. It deliberately does **not** block the read or redact the output:
//! the repo's "never block the user" principle stands, and if the human
//! approves the prompt they have asked for the content on purpose.
//!
//! Downgrading to `ask` rather than omitting the decision is load-bearing. The
//! rewritten command is `contextcrawler read <path>`, so a host with a broad
//! `Bash(contextcrawler:*)` allow rule would auto-run it anyway if no decision
//! were emitted.

use lazy_static::lazy_static;
use regex::Regex;

/// Suffixes that mark a file as a non-secret *sample*, by near-universal
/// convention. `.env.example` is committed to public repos on purpose.
const SAMPLE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist", ".tpl", ".md"];

lazy_static! {
    /// Path shapes whose contents are conventionally credentials.
    ///
    /// Each entry is (regex, human-readable name used in the prompt reason).
    /// Anchored on a path boundary — start of string, whitespace, `/`, `=` or
    /// a quote — so `environment.yml` does not match `.env` and
    /// `mykey.rs` does not match `*.key`.
    static ref SECRET_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"(?i)(^|[\s/'\x22=])\.env($|[\s'\x22.]|\.[a-z0-9_-]+)").unwrap(), "a .env file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])\.envrc($|[\s'\x22])").unwrap(), "a direnv .envrc"),
        (Regex::new(r"(?i)[\w./-]*\.(pem|p12|pfx|jks|keystore)($|[\s'\x22])").unwrap(), "a private key or keystore"),
        (Regex::new(r"(?i)[\w./-]*\.key($|[\s'\x22])").unwrap(), "a .key file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])id_(rsa|dsa|ecdsa|ed25519)($|[\s'\x22])").unwrap(), "an SSH private key"),
        // `.ssh` must be a whole path component: `~/.ssh/` matches, a directory
        // merely NAMED `...has_.ssh` does not. The repo already had an
        // over-match fixture for exactly this.
        (Regex::new(r"(?i)(^|[\s'\x22=/])\.ssh/").unwrap(), "the .ssh directory"),
        (Regex::new(r"(?i)(^|[\s'\x22=/])\.aws/").unwrap(), "AWS credentials"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])[\w./-]*(\.git-)?credentials($|[\s'\x22.])").unwrap(), "a credentials file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])\.?_?netrc($|[\s'\x22])").unwrap(), "a netrc file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])\.(npmrc|pypirc|docker/config\.json)($|[\s'\x22])").unwrap(), "a registry token file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])secrets?\.(json|ya?ml|toml|env)($|[\s'\x22])").unwrap(), "a secrets file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])service[-_]account[\w-]*\.json($|[\s'\x22])").unwrap(), "a service-account key"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])\.htpasswd($|[\s'\x22])").unwrap(), "an .htpasswd file"),
        (Regex::new(r"(?i)(^|[\s/'\x22=])\.pgpass($|[\s'\x22])").unwrap(), "a PostgreSQL password file"),
        // `.kube` must be a whole path component followed by `config`:
        // `~/.kube/config` matches, a directory merely containing "kube" does
        // not, and `.kube/config.example` is left to the sample-suffix skip.
        (Regex::new(r"(?i)(^|[\s'\x22=/])\.kube/config($|[\s'\x22])").unwrap(), "a kubeconfig"),
        (Regex::new(r"(?i)[\w./-]*\.kdbx($|[\s'\x22])").unwrap(), "a KeePass database"),
    ];

    /// A public key is not a secret, and neither is a `.pub`.
    static ref PUBLIC_SUFFIX: Regex = Regex::new(r"(?i)\.pub($|[\s'\x22])").unwrap();
}

/// Flags whose argument is a credential *used to authenticate*, not a file
/// whose contents are being read.
///
/// `scp -i ~/.ssh/id_rsa file host:` hands the key to ssh; it does not print
/// it. Prompting on those is the alarm fatigue that trains a user to click
/// through the prompt that actually matters — and the repo already had tests
/// encoding this distinction, which is how the false positive was caught.
const AUTH_FLAGS: &[&str] = &[
    "-i",
    "--identity",
    "--identity-file",
    "--key",
    "--sslkey",
    "--private-key",
    "--ssh-key",
    "--cert",
    "--sslcert",
    "--cacert",
    "--client-cert",
    "--tlskey",
    "--tlscert",
    "--tlscacert",
    "--keyfile",
];

/// True when the token at `token_start` is the argument of an auth flag, or is
/// embedded in an `IdentityFile=`/`sshCommand=` style option.
fn is_auth_material(cmd: &str, arg_start: usize, arg: &str) -> bool {
    // `-o IdentityFile=~/.ssh/id_rsa` carries the option inside the argument
    // itself, so check the argument as well as what precedes it.
    let arg_lower = arg.to_ascii_lowercase();
    if arg_lower.starts_with("identityfile=")
        || arg_lower.starts_with("sshcommand=")
        || arg_lower.starts_with("certificatefile=")
    {
        return true;
    }
    let before = &cmd[..arg_start];
    let lowered = before.to_ascii_lowercase();
    // ...and inside a quoted sub-command: `-e 'ssh -i ~/.ssh/id_rsa'`.
    if lowered.contains("identityfile=") || lowered.contains("sshcommand=") {
        return true;
    }
    match before.split_whitespace().next_back() {
        Some(prev) => AUTH_FLAGS.contains(
            &prev
                .trim_matches(|c| matches!(c, '\'' | '"'))
                .to_ascii_lowercase()
                .as_str(),
        ),
        None => false,
    }
}

/// Which secret-file convention this command touches, if any.
///
/// Returns the human-readable name for use in the permission prompt, so the
/// user is told *why* they are being asked rather than just being interrupted.
pub fn touches_secret_path(cmd: &str) -> Option<&'static str> {
    for (re, label) in SECRET_PATTERNS.iter() {
        let Some(m) = re.find(cmd) else {
            continue;
        };
        // Expand the match to the whole whitespace-delimited argument.
        //
        // The patterns deliberately match on a path boundary, so the match can
        // BEGIN on that boundary (the space before `.env`) and can land
        // mid-path (`/id_rsa` inside `~/.ssh/id_rsa`). Anchor past any leading
        // boundary characters first — otherwise the expansion walks left into
        // the previous word and judges the wrong token entirely.
        let anchor = m.start()
            + cmd[m.start()..m.end()]
                .find(|c: char| !c.is_whitespace() && !matches!(c, '\'' | '"' | '='))
                .unwrap_or(0);
        let arg_start = cmd[..anchor]
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(0);
        let arg_end = cmd[anchor..]
            .find(char::is_whitespace)
            .map(|i| anchor + i)
            .unwrap_or(cmd.len());
        let arg = cmd[arg_start..arg_end].trim_matches(|c| matches!(c, '\'' | '"'));

        if is_auth_material(cmd, arg_start, arg) {
            continue;
        }
        if PUBLIC_SUFFIX.is_match(arg) || arg.to_ascii_lowercase().ends_with(".pub") {
            continue;
        }
        let lowered = arg.to_ascii_lowercase();
        if SAMPLE_SUFFIXES.iter().any(|sfx| lowered.ends_with(sfx)) {
            continue;
        }
        return Some(label);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reproduced_bug_is_caught() {
        // Exactly the command that was auto-allowed while printing secrets.
        assert!(touches_secret_path("cat .env").is_some());
        assert!(touches_secret_path("contextcrawler read .env").is_some());
        assert!(touches_secret_path("contextcrawler proxy cat .env").is_some());
    }

    #[test]
    fn common_secret_shapes_are_caught() {
        for cmd in [
            "cat .env.production",
            "cat /home/u/app/.env",
            "head -5 ~/.aws/credentials",
            "cat ~/.ssh/id_rsa",
            "cat id_ed25519",
            "cat server.pem",
            "cat tls.key",
            "cat ~/.netrc",
            "cat .npmrc",
            "cat secrets.yaml",
            "cat service-account-prod.json",
            "cat .htpasswd",
            "cat client.p12",
            "cat .git-credentials",
            "cat .envrc",
            "cat \"my app/.env\"",
        ] {
            assert!(
                touches_secret_path(cmd).is_some(),
                "should be treated as secret: {cmd}"
            );
        }
    }

    #[test]
    fn conventional_secret_files_are_caught() {
        // #206 follow-up: three more conventions were slipping through.
        for cmd in [
            "cat ~/.pgpass",
            "cat ~/.kube/config",
            "cat ~/secrets/vault.kdbx",
        ] {
            assert!(
                touches_secret_path(cmd).is_some(),
                "should be treated as secret: {cmd}"
            );
        }
    }

    #[test]
    fn kube_and_key_lookalikes_are_not_secrets() {
        // `.kube/config.example` is the sample skip; a directory merely
        // containing "kube" is not the kube directory.
        for cmd in [
            "cat .kube/config.example",
            "cat environment.yml",
            "cat mykey.rs",
            "cat .env.example",
        ] {
            assert_eq!(
                touches_secret_path(cmd),
                None,
                "must NOT be treated as secret: {cmd}"
            );
        }
    }

    #[test]
    fn sample_and_public_variants_are_not_secrets() {
        // These are committed to public repos on purpose. Prompting on them
        // would train the user to click through the prompt that matters.
        for cmd in [
            "cat .env.example",
            "cat .env.sample",
            "cat .env.template",
            "cat .env.dist",
            "cat ~/.ssh/id_rsa.pub",
            "cat id_ed25519.pub",
        ] {
            assert_eq!(
                touches_secret_path(cmd),
                None,
                "must NOT be treated as secret: {cmd}"
            );
        }
    }

    #[test]
    fn credentials_used_to_authenticate_are_not_reads() {
        // Handing a key to ssh/curl is not printing it. Caught by the repo's
        // existing scp/rsync test, which is exactly what it is there for.
        for cmd in [
            "scp -i ~/.ssh/id_rsa file host:",
            "ssh -i ~/.ssh/id_ed25519 host uptime",
            "rsync -e 'ssh -i ~/.ssh/id_rsa' src host:dst",
            "curl --key client.key --cert client.pem https://api.example",
            "git -c core.sshCommand='ssh -i ~/.ssh/id_rsa' fetch",
            "ssh -o IdentityFile=~/.ssh/id_rsa host",
        ] {
            assert_eq!(
                touches_secret_path(cmd),
                None,
                "auth material must not be treated as a secret READ: {cmd}"
            );
        }
    }

    #[test]
    fn reading_the_same_key_is_still_caught() {
        // The distinction is use-vs-read, so the read must still fire.
        assert!(touches_secret_path("cat ~/.ssh/id_rsa").is_some());
        assert!(touches_secret_path("contextcrawler read client.key").is_some());
    }

    #[test]
    fn lookalike_paths_do_not_over_match() {
        // A directory merely NAMED "...has_.ssh" is not the .ssh directory,
        // and `id_rsa_substring` is not `id_rsa`. The repo's exfil tests
        // already encoded this anchoring requirement.
        for cmd in [
            "cat /tmp/not_secret_but_has_.ssh/id_rsa_substring",
            "cat notes_about_.env_files.md",
            "cat my.keyboard.txt",
        ] {
            assert_eq!(
                touches_secret_path(cmd),
                None,
                "over-matched a lookalike path: {cmd}"
            );
        }
    }

    #[test]
    fn ordinary_commands_are_untouched() {
        // False positives here cost every user on every command, so this is
        // the list that keeps the feature honest.
        for cmd in [
            "git status",
            "cargo test",
            "cat README.md",
            "cat environment.yml",
            "cat src/main.rs",
            "ls -la",
            "cat monkey.rs",
            "cat keyboard.txt",
            "grep -rn env src/",
            "cat docs/environments.md",
            "cargo run -- --key value",
            "cat package.json",
        ] {
            assert_eq!(
                touches_secret_path(cmd),
                None,
                "false positive on an ordinary command: {cmd}"
            );
        }
    }

    #[test]
    fn the_label_explains_why_the_user_is_being_asked() {
        assert_eq!(touches_secret_path("cat .env"), Some("a .env file"));
        assert_eq!(
            touches_secret_path("cat ~/.ssh/id_rsa"),
            Some("an SSH private key")
        );
    }
}
