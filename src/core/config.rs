//! Reads user settings from config.toml.

use super::constants::{
    CONFIG_TOML, DEFAULT_HISTORY_DAYS, DEFAULT_HOST_TRUNCATION_TOKENS, RTK_DATA_DIR,
};
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub tracking: TrackingConfig,
    #[serde(default)]
    pub display: DisplayConfig,
    #[serde(default)]
    pub filters: FilterConfig,
    #[serde(default)]
    pub tee: crate::core::tee::TeeConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub read: ReadConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct HooksConfig {
    /// Commands to exclude from auto-rewrite (e.g. ["curl", "playwright"]).
    /// Survives `ctxcrl init -g` re-runs since config.toml is user-owned.
    #[serde(default)]
    pub exclude_commands: Vec<String>,

    /// Wrapper prefixes that should be transparently stripped before routing
    /// to a filter, then re-prepended on the rewrite. For example, with
    /// `transparent_prefixes = ["docker exec mycontainer"]`, the command
    /// `docker exec mycontainer git status` rewrites to
    /// `docker exec mycontainer ctxcrl git status` instead of passing through
    /// unrewritten.
    ///
    /// Useful for any per-project env wrapper that sits in front of every
    /// command — e.g. `docker exec mycontainer`, `direnv exec .`, `poetry run`,
    /// or `bundle exec`.
    ///
    /// Matching is literal, not pattern-based. Configure the exact concrete
    /// prefix you actually use, such as `docker exec mycontainer`.
    ///
    /// Extends the built-in `SHELL_PREFIX_BUILTINS` list (`noglob`, `command`,
    /// `builtin`, `exec`, `nocorrect`) with user- or organization-specific
    /// wrappers. Matching is strict: a configured prefix `"foo bar"` matches
    /// a command that starts with `"foo bar "` (or strictly equals `"foo bar"`),
    /// not anything else.
    #[serde(default)]
    pub transparent_prefixes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrackingConfig {
    pub enabled: bool,
    pub history_days: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_path: Option<PathBuf>,
    /// #208: the host truncates a Bash command's output at this many estimated
    /// tokens before the model sees it, so `gain`'s effective-savings metric
    /// caps each command's raw input here. Tune to your Claude Code output
    /// limit; defaults to [`DEFAULT_HOST_TRUNCATION_TOKENS`].
    #[serde(default = "default_host_truncation_tokens")]
    pub host_truncation_tokens: usize,
}

fn default_host_truncation_tokens() -> usize {
    DEFAULT_HOST_TRUNCATION_TOKENS
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            history_days: DEFAULT_HISTORY_DAYS as u32,
            database_path: None,
            host_truncation_tokens: DEFAULT_HOST_TRUNCATION_TOKENS,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisplayConfig {
    pub colors: bool,
    pub emoji: bool,
    pub max_width: usize,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            colors: true,
            emoji: true,
            max_width: 120,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterConfig {
    pub ignore_dirs: Vec<String>,
    pub ignore_files: Vec<String>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            ignore_dirs: vec![
                ".git".into(),
                "node_modules".into(),
                "target".into(),
                "__pycache__".into(),
                ".venv".into(),
                "vendor".into(),
            ],
            ignore_files: vec!["*.lock".into(), "*.min.js".into(), "*.min.css".into()],
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_given: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Max total grep results to show (default: 200)
    pub grep_max_results: usize,
    /// Max matches per file in grep output (default: 25)
    pub grep_max_per_file: usize,
    /// Max staged/modified files shown in git status (default: 15)
    pub status_max_files: usize,
    /// Max untracked files shown in git status (default: 10)
    pub status_max_untracked: usize,
    /// Max chars for parser passthrough fallback (default: 2000)
    pub passthrough_max_chars: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            grep_max_results: 200,
            grep_max_per_file: 25,
            status_max_files: 15,
            status_max_untracked: 10,
            passthrough_max_chars: 2000,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadConfig {
    /// Token threshold before the unknown-extension fallback window is used.
    pub token_threshold: usize,
    /// Lines to keep from the start of a large unknown-extension file.
    pub head_lines: usize,
    /// Lines to keep from the end of a large unknown-extension file.
    /// Defaults to 80 so head and tail are symmetric — final assertions,
    /// imports-at-bottom patterns, and result lines deserve equal weight to
    /// the file's opening when only a window is preserved.
    pub tail_lines: usize,
    /// Extensions (with or without leading dot) that bypass the cap even
    /// when they exceed the token threshold. Use for source-code files in
    /// languages contextcrawler hasn't grown a filter for yet, e.g.
    /// `[".svelte", ".astro", ".zig"]`.
    #[serde(default)]
    pub passthrough_extensions: Vec<String>,
}

impl Default for ReadConfig {
    fn default() -> Self {
        Self {
            token_threshold: 5_000,
            head_lines: 80,
            tail_lines: 80,
            passthrough_extensions: Vec::new(),
        }
    }
}

/// Get limits config. Falls back to defaults if config can't be loaded.
pub fn limits() -> LimitsConfig {
    Config::load().map(|c| c.limits).unwrap_or_default()
}

/// Get read config. Falls back to defaults if config can't be loaded.
pub fn read() -> ReadConfig {
    Config::load().map(|c| c.read).unwrap_or_default()
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = get_config_path()?;

        if path.exists() {
            // #222: read-and-validate the SAME fd (TOCTOU-safe). An untrusted
            // config (symlink / foreign-owner / world-writable, e.g. via a
            // hostile XDG_CONFIG_HOME) is ignored — safe defaults rather than
            // attacker-controlled hook policy.
            match read_trusted_config(&path) {
                Some(content) => Ok(toml::from_str(&content)?),
                None => {
                    eprintln!(
                        "[contextcrawler] WARNING: config at {} is not a trusted, readable file \
                         (symlink, foreign owner, or group/world-writable); using defaults",
                        path.display()
                    );
                    Ok(Config::default())
                }
            }
        } else {
            Ok(Config::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = get_config_path()?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    pub fn create_default() -> Result<PathBuf> {
        let config = Config::default();
        config.save()?;
        get_config_path()
    }
}

fn get_config_path() -> Result<PathBuf> {
    // #222: NEVER fall back to the current directory. Config controls
    // security-relevant behaviour (hooks.exclude_commands disables the proxy
    // for those commands; transparent_prefixes), so reading `./ctxcrl/config.toml`
    // from an untrusted project checkout is a policy-injection vector. Fail
    // closed when no user config dir can be resolved.
    let config_dir = dirs::config_dir()
        .context("cannot determine a user config directory; refusing to read config from the current directory")?;
    Ok(config_dir.join(RTK_DATA_DIR).join(CONFIG_TOML))
}

/// #222: read a config file ONLY if it is trusted, validating and reading the
/// SAME open descriptor to avoid a TOCTOU (council HIGH). A hostile environment
/// can point `XDG_CONFIG_HOME` at an attacker-owned directory or commit a
/// symlinked config, and config drives security-relevant hook behaviour, so an
/// untrusted file must be ignored (→ `None`, caller uses defaults) rather than
/// obeyed. `O_NOFOLLOW` refuses a symlinked final component atomically on unix;
/// the fd is fstat-validated (regular file, user-owned, not group/world
/// writable) and the content read from that fd — no path re-resolution between
/// check and read. `None` = don't trust / can't read (fail closed).
fn read_trusted_config(path: &Path) -> Option<String> {
    use std::io::Read;
    // Non-unix (Windows): no `O_NOFOLLOW` and no fd owner/mode check, so this
    // pre-check→open is not fully atomic and can be raced (council #222, codex).
    // Accepted residual, same call as #221: unix (Linux + macOS, the deployment
    // targets) is atomic + owner/mode-validated below; a Windows atomic
    // no-reparse open (`openat2`/reparse-point handling) is a documented
    // follow-up, not a blocker for the unix-correct fix. Best-effort symlink
    // pre-check here; on stat failure, fail closed.
    #[cfg(not(unix))]
    {
        if std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
        {
            return None;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // 0o022 = group-write | other-write.
        if meta.mode() & 0o022 != 0 {
            return None;
        }
        let our_uid = unsafe { libc::geteuid() };
        if meta.uid() != our_uid && meta.uid() != 0 {
            return None;
        }
    }
    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;
    Some(content)
}

pub fn show_config() -> Result<()> {
    let path = get_config_path()?;
    println!("Config: {}", path.display());
    println!();

    if path.exists() {
        let config = Config::load()?;
        println!("{}", toml::to_string_pretty(&config)?);
    } else {
        println!("(default config, file not created)");
        println!();
        let config = Config::default();
        println!("{}", toml::to_string_pretty(&config)?);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn read_trusted_config_rejects_symlink_and_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ctxcrl-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let good = dir.join("config.toml");
        std::fs::write(&good, b"[hooks]\n").unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_trusted_config(&good).as_deref(),
            Some("[hooks]\n"),
            "0600 user-owned file is trusted and read"
        );

        // World-writable → untrusted → None.
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            read_trusted_config(&good).is_none(),
            "world-writable must be rejected"
        );

        // Symlink → untrusted → None (O_NOFOLLOW).
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.toml");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(
            read_trusted_config(&link).is_none(),
            "symlinked config must be rejected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hooks_config_deserialize() {
        let toml = r#"
[hooks]
exclude_commands = ["curl", "gh"]
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert_eq!(config.hooks.exclude_commands, vec!["curl", "gh"]);
    }

    #[test]
    fn test_hooks_config_default_empty() {
        let config = Config::default();
        assert!(config.hooks.exclude_commands.is_empty());
        assert!(config.hooks.transparent_prefixes.is_empty());
    }

    #[test]
    fn test_host_truncation_tokens_defaults_when_absent() {
        // #208: a config that predates the field must still parse and get the
        // default cap, not 0 (which would zero the effective-savings metric).
        let config: Config =
            toml::from_str("[tracking]\nenabled = true\nhistory_days = 90\n").expect("valid toml");
        assert_eq!(
            config.tracking.host_truncation_tokens,
            DEFAULT_HOST_TRUNCATION_TOKENS
        );
    }

    #[test]
    fn test_host_truncation_tokens_override() {
        let config: Config = toml::from_str(
            "[tracking]\nenabled = true\nhistory_days = 90\nhost_truncation_tokens = 15000\n",
        )
        .expect("valid toml");
        assert_eq!(config.tracking.host_truncation_tokens, 15000);
    }

    #[test]
    fn test_hooks_config_transparent_prefixes_deserialize() {
        let toml = r#"
[hooks]
transparent_prefixes = ["direnv exec .", "nix develop --command"]
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert_eq!(
            config.hooks.transparent_prefixes,
            vec!["direnv exec .", "nix develop --command"]
        );
    }

    #[test]
    fn test_hooks_config_transparent_prefixes_missing_is_empty() {
        // Older configs that predate this field must still parse.
        let toml = r#"
[hooks]
exclude_commands = ["curl"]
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert_eq!(config.hooks.exclude_commands, vec!["curl"]);
        assert!(config.hooks.transparent_prefixes.is_empty());
    }

    #[test]
    fn test_config_without_hooks_section_is_valid() {
        let toml = r#"
[tracking]
enabled = true
history_days = 90
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert!(config.hooks.exclude_commands.is_empty());
    }

    #[test]
    fn test_old_toml_without_consent_fields() {
        let toml = r#"
[telemetry]
enabled = true
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert!(config.telemetry.enabled);
        assert!(config.telemetry.consent_given.is_none());
        assert!(config.telemetry.consent_date.is_none());
    }

    #[test]
    fn test_telemetry_default_disabled() {
        let config = Config::default();
        assert!(!config.telemetry.enabled);
        assert!(config.telemetry.consent_given.is_none());
    }

    #[test]
    fn test_telemetry_consent_roundtrip() {
        let toml = r#"
[telemetry]
enabled = true
consent_given = true
consent_date = "2026-04-10T12:00:00Z"
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert_eq!(config.telemetry.consent_given, Some(true));
        assert_eq!(
            config.telemetry.consent_date.as_deref(),
            Some("2026-04-10T12:00:00Z")
        );
    }

    #[test]
    fn test_read_config_default_values() {
        let config = Config::default();
        assert_eq!(config.read.token_threshold, 5_000);
        // Symmetric 80/80 — final assertions and result lines deserve the
        // same surface area as the file's opening.
        assert_eq!(config.read.head_lines, 80);
        assert_eq!(config.read.tail_lines, 80);
        assert!(config.read.passthrough_extensions.is_empty());
    }

    #[test]
    fn test_read_config_deserialize() {
        let toml = r#"
[read]
token_threshold = 1234
head_lines = 12
tail_lines = 34
"#;
        let config: Config = toml::from_str(toml).expect("valid toml");
        assert_eq!(config.read.token_threshold, 1234);
        assert_eq!(config.read.head_lines, 12);
        assert_eq!(config.read.tail_lines, 34);
    }
}
