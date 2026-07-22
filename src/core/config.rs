//! Reads user settings from config.toml.

use super::constants::{
    CONFIG_TOML, DEFAULT_HISTORY_DAYS, DEFAULT_HOST_TRUNCATION_TOKENS, RTK_DATA_DIR,
};
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::path::PathBuf;

/// Permission-gate policy selected by the canonical user configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    Strict,
    #[default]
    Standard,
    Trusted,
    Unrestricted,
}

impl SecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Standard => "standard",
            Self::Trusted => "trusted",
            Self::Unrestricted => "unrestricted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExfilAction {
    #[default]
    Ask,
    Deny,
}

impl ExfilAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PermissionsConfig {
    /// `None` means use the product default (`standard`). Keeping absence
    /// distinct lets the deprecated boolean alias be recognised reliably.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<SecurityProfile>,
    #[serde(default)]
    pub exfil_action: ExfilAction,
    /// Deprecated compatibility alias. Applied only when `profile` is absent.
    #[serde(default)]
    pub trust_unattestable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileTrust {
    Missing,
    CanonicalPrivate,
    CanonicalInsecure,
    Project,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionConfigSource {
    Default,
    CanonicalConfig,
    LegacyAlias,
    EnvironmentOverride,
    TighteningOverride,
    RejectedRelaxation,
    FailClosed,
}

impl PermissionConfigSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CanonicalConfig => "canonical-config",
            Self::LegacyAlias => "legacy-alias",
            Self::EnvironmentOverride => "environment-debug-override",
            Self::TighteningOverride => "untrusted-source-tightening",
            Self::RejectedRelaxation => "rejected-relaxation",
            Self::FailClosed => "fail-closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissions {
    pub profile: SecurityProfile,
    pub exfil_action: ExfilAction,
    pub source: PermissionConfigSource,
    pub warn_legacy_alias: bool,
    pub config_path: Option<PathBuf>,
    pub ownership: String,
}

fn resolve_permissions_config(
    permissions: &PermissionsConfig,
    trust: ConfigFileTrust,
    env_override: Option<&str>,
) -> EffectivePermissions {
    let (requested, mut source, warn_legacy_alias) = if let Some(profile) = permissions.profile {
        (profile, PermissionConfigSource::CanonicalConfig, false)
    } else if permissions.trust_unattestable {
        (
            SecurityProfile::Trusted,
            PermissionConfigSource::LegacyAlias,
            true,
        )
    } else if matches!(env_override, Some("1") | Some("true")) {
        (
            SecurityProfile::Trusted,
            PermissionConfigSource::EnvironmentOverride,
            false,
        )
    } else {
        (
            SecurityProfile::Standard,
            PermissionConfigSource::Default,
            false,
        )
    };

    let relaxation_selected = matches!(
        source,
        PermissionConfigSource::CanonicalConfig
            | PermissionConfigSource::LegacyAlias
            | PermissionConfigSource::EnvironmentOverride
    );
    let relaxes_default = matches!(
        requested,
        SecurityProfile::Trusted | SecurityProfile::Unrestricted
    );
    let profile =
        if relaxation_selected && relaxes_default && trust != ConfigFileTrust::CanonicalPrivate {
            source = PermissionConfigSource::RejectedRelaxation;
            SecurityProfile::Standard
        } else {
            if relaxation_selected
                && requested == SecurityProfile::Strict
                && trust != ConfigFileTrust::CanonicalPrivate
            {
                source = PermissionConfigSource::TighteningOverride;
            }
            requested
        };

    EffectivePermissions {
        profile,
        exfil_action: permissions.exfil_action,
        source,
        warn_legacy_alias: warn_legacy_alias && profile == SecurityProfile::Trusted,
        config_path: None,
        ownership: "not-inspected".to_string(),
    }
}

#[derive(Debug)]
struct LoadedConfig {
    config: Config,
    path: PathBuf,
    trust: ConfigFileTrust,
    ownership: String,
}

/// Resolve the effective permission policy. Parse/read failures fail closed to
/// `strict`; an absent config uses the product default (`standard`).
pub fn effective_permissions() -> EffectivePermissions {
    let env_override = std::env::var("CONTEXTCRAWLER_TRUST_UNATTESTABLE").ok();
    match Config::load_with_source() {
        Ok(loaded) => {
            let mut effective = resolve_permissions_config(
                &loaded.config.permissions,
                loaded.trust,
                env_override.as_deref(),
            );
            effective.config_path = Some(loaded.path);
            effective.ownership = loaded.ownership;
            effective
        }
        Err(error) => EffectivePermissions {
            profile: SecurityProfile::Strict,
            exfil_action: ExfilAction::Ask,
            source: PermissionConfigSource::FailClosed,
            warn_legacy_alias: false,
            config_path: get_config_path().ok(),
            ownership: format!("unavailable: {error:#}"),
        },
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub permissions: PermissionsConfig,
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
        Ok(Self::load_with_source()?.config)
    }

    fn load_with_source() -> Result<LoadedConfig> {
        let path = get_config_path()?;

        if path.exists() {
            // #222: read-and-validate the SAME fd (TOCTOU-safe). An untrusted
            // config (symlink / foreign-owner / world-writable, e.g. via a
            // hostile XDG_CONFIG_HOME) is ignored — safe defaults rather than
            // attacker-controlled hook policy.
            match read_trusted_config_details(&path) {
                Some(read) => Ok(LoadedConfig {
                    config: toml::from_str(&read.content)?,
                    path,
                    trust: read.trust,
                    ownership: read.ownership,
                }),
                None => {
                    eprintln!(
                        "[contextcrawler] WARNING: config at {} is not a trusted, readable file \
                         (symlink, foreign owner, or group/world-writable); using defaults",
                        path.display()
                    );
                    Ok(LoadedConfig {
                        config: Config::default(),
                        path,
                        trust: ConfigFileTrust::Rejected,
                        ownership: "rejected: symlink, owner, mode, or file type".to_string(),
                    })
                }
            }
        } else {
            Ok(LoadedConfig {
                config: Config::default(),
                path,
                trust: ConfigFileTrust::Missing,
                ownership: "absent".to_string(),
            })
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = get_config_path()?;
        let content = toml::to_string_pretty(self)?;
        write_private_config(&path, content.as_bytes())
    }

    pub fn create_default() -> Result<PathBuf> {
        let config = default_file_config();
        config.save()?;
        get_config_path()
    }
}

/// Atomically replace the canonical config without following an existing
/// final-component symlink. `NamedTempFile` creates the temporary entry with
/// create-new/O_EXCL semantics; persisting it renames over the directory entry
/// itself, so an attacker-controlled symlink is replaced rather than followed.
/// The mode is fixed before publication so readers never observe a permissive
/// freshly-written config.
fn write_private_config(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .context("config path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config directory {}", parent.display()))?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary config in {}", parent.display()))?;
    temporary
        .write_all(content)
        .with_context(|| format!("failed to write temporary config for {}", path.display()))?;
    temporary
        .flush()
        .with_context(|| format!("failed to flush temporary config for {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set mode 0600 on {}", path.display()))?;
    }
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary config for {}", path.display()))?;

    let persisted = temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to atomically replace {}", path.display()))?;
    persisted
        .sync_all()
        .with_context(|| format!("failed to sync config {}", path.display()))?;
    Ok(())
}

fn default_file_config() -> Config {
    let mut config = Config::default();
    config.permissions.profile = Some(SecurityProfile::Standard);
    config
}

fn get_config_path() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_CONFIG_PATH.with(|slot| slot.borrow().clone()) {
        return Ok(path);
    }

    // #222: NEVER fall back to the current directory. Config controls
    // security-relevant behaviour (hooks.exclude_commands disables the proxy
    // for those commands; transparent_prefixes), so reading `./ctxcrl/config.toml`
    // from an untrusted project checkout is a policy-injection vector. Fail
    // closed when no user config dir can be resolved.
    let config_dir = dirs::config_dir()
        .context("cannot determine a user config directory; refusing to read config from the current directory")?;
    Ok(config_dir.join(RTK_DATA_DIR).join(CONFIG_TOML))
}

#[cfg(test)]
thread_local! {
    static TEST_CONFIG_PATH: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Debug)]
struct TrustedConfigRead {
    content: String,
    trust: ConfigFileTrust,
    ownership: String,
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
#[cfg(test)]
fn read_trusted_config(path: &Path) -> Option<String> {
    read_trusted_config_details(path).map(|read| read.content)
}

fn read_trusted_config_details(path: &Path) -> Option<TrustedConfigRead> {
    use std::io::Read;
    #[cfg(unix)]
    let project_local_before_open = path_is_project_local(path);
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

    #[cfg(unix)]
    let (trust, ownership) = {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        let uid = meta.uid();
        let our_uid = unsafe { libc::geteuid() };
        // Classify both before and after the descriptor read. Either view
        // being project-local is enough to reject relaxation; a path race may
        // tighten policy, never loosen it.
        let project_local = project_local_before_open || path_is_project_local(path);
        let trust = if uid == our_uid && mode == 0o600 && !project_local {
            ConfigFileTrust::CanonicalPrivate
        } else if project_local {
            ConfigFileTrust::Project
        } else {
            ConfigFileTrust::CanonicalInsecure
        };
        (
            trust,
            format!("uid={uid}, mode={mode:04o}, project_local={project_local}"),
        )
    };

    #[cfg(not(unix))]
    let (trust, ownership) = (
        ConfigFileTrust::CanonicalInsecure,
        "ownership verification unavailable on this platform".to_string(),
    );

    Some(TrustedConfigRead {
        content,
        trust,
        ownership,
    })
}

fn path_is_project_local(path: &Path) -> bool {
    let Some(cwd) = std::env::current_dir().ok() else {
        return true;
    };
    path_is_project_local_from(path, &cwd)
}

fn path_is_project_local_from(path: &Path, cwd: &Path) -> bool {
    let Some(canonical_cwd) = std::fs::canonicalize(cwd).ok() else {
        return true;
    };
    let Some(project_root) = canonical_cwd
        .ancestors()
        .find(|ancestor| std::fs::symlink_metadata(ancestor.join(".git")).is_ok())
    else {
        return false;
    };

    // Do not canonicalize the final config component: a symlink located in a
    // repository remains repository authority even when its target is a
    // private file elsewhere. Canonicalize the parent once to handle symlinked
    // cwd/HOME paths consistently, while retaining the lexical comparison so
    // an in-repo parent symlink can only tighten policy.
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        canonical_cwd.join(path)
    };
    let Some(parent) = absolute.parent() else {
        return true;
    };
    let Some(canonical_parent) = std::fs::canonicalize(parent).ok() else {
        return true;
    };

    parent.starts_with(project_root) || canonical_parent.starts_with(project_root)
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
        let config = default_file_config();
        println!("{}", toml::to_string_pretty(&config)?);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConfigPathGuard;

    impl TestConfigPathGuard {
        fn set(path: PathBuf) -> Self {
            TEST_CONFIG_PATH.with(|slot| {
                let previous = slot.replace(Some(path));
                assert!(previous.is_none(), "test config path override already set");
            });
            Self
        }
    }

    impl Drop for TestConfigPathGuard {
        fn drop(&mut self) {
            TEST_CONFIG_PATH.with(|slot| {
                slot.replace(None);
            });
        }
    }

    #[test]
    fn permissions_config_parses_profile_action_and_legacy_alias() {
        let config: Config = toml::from_str(
            r#"
[permissions]
profile = "trusted"
exfil_action = "deny"
trust_unattestable = true
"#,
        )
        .expect("valid permissions config");

        assert_eq!(config.permissions.profile, Some(SecurityProfile::Trusted));
        assert_eq!(config.permissions.exfil_action, ExfilAction::Deny);
        assert!(config.permissions.trust_unattestable);
    }

    #[test]
    fn generated_default_config_materializes_standard_profile() {
        let config = default_file_config();
        assert_eq!(config.permissions.profile, Some(SecurityProfile::Standard));
        let serialized = toml::to_string_pretty(&config).expect("serialize default config");
        assert!(serialized.contains("profile = \"standard\""));
    }

    #[test]
    #[cfg(unix)]
    fn save_replaces_symlinks_with_private_config_and_honours_trusted_profile() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("temporary config root");
        let config_path = dir.path().join("contextcrawler/config.toml");
        std::fs::create_dir_all(config_path.parent().expect("config parent"))
            .expect("create config parent");
        let victim = dir.path().join("victim.toml");
        std::fs::write(&victim, "victim must survive\n").expect("write symlink target");
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600))
            .expect("make target private");
        std::os::unix::fs::symlink(&victim, &config_path).expect("plant config symlink");
        let _path_guard = TestConfigPathGuard::set(config_path.clone());

        let mut config = Config::default();
        config.permissions.profile = Some(SecurityProfile::Trusted);
        config.save().expect("save private config");

        assert_eq!(
            std::fs::read_to_string(&victim).expect("read untouched target"),
            "victim must survive\n",
            "save followed an attacker-controlled symlink"
        );
        let metadata = std::fs::symlink_metadata(&config_path).expect("saved config metadata");
        assert!(metadata.is_file(), "save did not publish a regular file");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let loaded = Config::load_with_source().expect("load saved config");
        assert_eq!(loaded.trust, ConfigFileTrust::CanonicalPrivate);
        let effective = resolve_permissions_config(&loaded.config.permissions, loaded.trust, None);
        assert_eq!(effective.profile, SecurityProfile::Trusted);
        assert_eq!(effective.source, PermissionConfigSource::CanonicalConfig);
    }

    #[test]
    fn permissions_resolution_is_standard_by_default_and_config_authoritative() {
        let baseline = resolve_permissions_config(
            &PermissionsConfig::default(),
            ConfigFileTrust::Missing,
            None,
        );
        assert_eq!(baseline.profile, SecurityProfile::Standard);
        assert_eq!(baseline.source, PermissionConfigSource::Default);

        let debug_override = resolve_permissions_config(
            &PermissionsConfig::default(),
            ConfigFileTrust::Missing,
            Some("true"),
        );
        assert_eq!(debug_override.profile, SecurityProfile::Standard);
        assert_eq!(
            debug_override.source,
            PermissionConfigSource::RejectedRelaxation
        );

        let authorised_debug_override = resolve_permissions_config(
            &PermissionsConfig::default(),
            ConfigFileTrust::CanonicalPrivate,
            Some("true"),
        );
        assert_eq!(authorised_debug_override.profile, SecurityProfile::Trusted);
        assert_eq!(
            authorised_debug_override.source,
            PermissionConfigSource::EnvironmentOverride
        );

        let explicit = PermissionsConfig {
            profile: Some(SecurityProfile::Strict),
            trust_unattestable: true,
            ..PermissionsConfig::default()
        };
        let resolved =
            resolve_permissions_config(&explicit, ConfigFileTrust::CanonicalPrivate, Some("true"));
        assert_eq!(resolved.profile, SecurityProfile::Strict);
        assert_eq!(resolved.source, PermissionConfigSource::CanonicalConfig);
    }

    #[test]
    fn legacy_alias_maps_to_trusted_but_untrusted_sources_cannot_relax() {
        let legacy = PermissionsConfig {
            trust_unattestable: true,
            ..PermissionsConfig::default()
        };
        let private = resolve_permissions_config(&legacy, ConfigFileTrust::CanonicalPrivate, None);
        assert_eq!(private.profile, SecurityProfile::Trusted);
        assert_eq!(private.source, PermissionConfigSource::LegacyAlias);
        assert!(private.warn_legacy_alias);

        let project = resolve_permissions_config(&legacy, ConfigFileTrust::Project, None);
        assert_eq!(project.profile, SecurityProfile::Standard);
        assert_eq!(project.source, PermissionConfigSource::RejectedRelaxation);

        let tighten = PermissionsConfig {
            profile: Some(SecurityProfile::Strict),
            exfil_action: ExfilAction::Deny,
            ..PermissionsConfig::default()
        };
        let project = resolve_permissions_config(&tighten, ConfigFileTrust::Project, None);
        assert_eq!(project.profile, SecurityProfile::Strict);
        assert_eq!(project.exfil_action, ExfilAction::Deny);
    }

    #[test]
    fn only_private_canonical_config_can_select_relaxed_profiles() {
        for profile in [SecurityProfile::Trusted, SecurityProfile::Unrestricted] {
            let requested = PermissionsConfig {
                profile: Some(profile),
                ..PermissionsConfig::default()
            };
            let accepted =
                resolve_permissions_config(&requested, ConfigFileTrust::CanonicalPrivate, None);
            assert_eq!(accepted.profile, profile);
            assert_eq!(accepted.source, PermissionConfigSource::CanonicalConfig);

            for trust in [ConfigFileTrust::CanonicalInsecure, ConfigFileTrust::Project] {
                let rejected = resolve_permissions_config(&requested, trust, None);
                assert_eq!(rejected.profile, SecurityProfile::Standard);
                assert_eq!(rejected.source, PermissionConfigSource::RejectedRelaxation);
            }
        }
    }

    #[test]
    fn environment_override_cannot_be_the_sole_relaxation_authority() {
        for trust in [
            ConfigFileTrust::Missing,
            ConfigFileTrust::CanonicalInsecure,
            ConfigFileTrust::Project,
            ConfigFileTrust::Rejected,
        ] {
            let resolved =
                resolve_permissions_config(&PermissionsConfig::default(), trust, Some("1"));
            assert_eq!(
                resolved.profile,
                SecurityProfile::Standard,
                "trust={trust:?}"
            );
            assert_eq!(
                resolved.source,
                PermissionConfigSource::RejectedRelaxation,
                "trust={trust:?}"
            );
        }

        let authorised = resolve_permissions_config(
            &PermissionsConfig::default(),
            ConfigFileTrust::CanonicalPrivate,
            Some("1"),
        );
        assert_eq!(authorised.profile, SecurityProfile::Trusted);
        assert_eq!(
            authorised.source,
            PermissionConfigSource::EnvironmentOverride
        );
    }

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
        assert_eq!(
            read_trusted_config_details(&good).map(|read| read.trust),
            Some(ConfigFileTrust::CanonicalPrivate)
        );

        // 0644 remains readable for non-security settings, but cannot opt the
        // permission gate into Trusted/Unrestricted.
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_trusted_config_details(&good).map(|read| read.trust),
            Some(ConfigFileTrust::CanonicalInsecure)
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
    fn repository_paths_are_never_relaxation_sources() {
        let repo_config = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        assert!(path_is_project_local(&repo_config));
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_repository_config_can_only_tighten_policy() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("temporary authority roots");
        let repo = dir.path().join("repo");
        let repo_config_dir = repo.join(".contextcrawler");
        std::fs::create_dir_all(repo.join(".git")).expect("create fake git metadata");
        std::fs::create_dir_all(&repo_config_dir).expect("create repo config directory");

        let private = dir.path().join("private-config.toml");
        std::fs::write(&private, "[permissions]\nprofile = \"trusted\"\n")
            .expect("write private target");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600))
            .expect("make target private");
        let link = repo_config_dir.join("config.toml");
        std::os::unix::fs::symlink(&private, &link).expect("link repo config to private file");

        assert!(path_is_project_local_from(&link, &repo));
        assert!(
            read_trusted_config_details(&link).is_none(),
            "the final-component O_NOFOLLOW check must reject the symlink"
        );
        let requested = PermissionsConfig {
            profile: Some(SecurityProfile::Trusted),
            ..PermissionsConfig::default()
        };
        let effective = resolve_permissions_config(&requested, ConfigFileTrust::Project, None);
        assert_eq!(effective.profile, SecurityProfile::Standard);
        assert_eq!(effective.source, PermissionConfigSource::RejectedRelaxation);

        let real_home = dir.path().join("real-home");
        let real_config_parent = real_home.join(".config/contextcrawler");
        std::fs::create_dir_all(&real_config_parent).expect("create canonical home config parent");
        let home_link = dir.path().join("home-link");
        std::os::unix::fs::symlink(&real_home, &home_link).expect("create HOME symlink");
        let home_config = home_link.join(".config/contextcrawler/config.toml");
        assert!(
            !path_is_project_local_from(&home_config, &repo),
            "a canonical HOME config outside the repo was misclassified as project authority"
        );
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
