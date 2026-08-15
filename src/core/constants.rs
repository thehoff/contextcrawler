/// Canonical on-disk directory segment used under the user config dir
/// (`~/.config/<RTK_DATA_DIR>`) and data dir (`~/.local/share/<RTK_DATA_DIR>`).
/// Renamed from the legacy `rtk`; see `core::path_migrate` for the move.
pub const RTK_DATA_DIR: &str = "ctxcrl";
pub const HISTORY_DB: &str = "history.db";
pub const CONFIG_TOML: &str = "config.toml";
pub const FILTERS_TOML: &str = "filters.toml";
pub const TRUSTED_FILTERS_JSON: &str = "trusted_filters.json";
pub const DEFAULT_HISTORY_DAYS: i64 = 90;

/// #208: the host (Claude Code) truncates a Bash command's output before it
/// reaches the model, so contextcrawler's "effective" savings cap each
/// command's raw input at this many estimated tokens — the counterfactual the
/// model would truly have ingested. Claude Code's default Bash output limit is
/// ~30_000 characters, ~7_500 tokens at contextcrawler's chars/4 estimate.
/// Override via `[tracking] host_truncation_tokens` in config.toml.
pub const DEFAULT_HOST_TRUNCATION_TOKENS: usize = 7_500;

/// #240: size cap for `downgrades.jsonl`. Once the active log exceeds this,
/// it is rotated to `downgrades.jsonl.1` (replacing any older rotated file)
/// and a fresh log starts, bounding disk to ~2× the cap. Records are ~1.9KB
/// each (full tirith verdict embedded), so 5 MiB is ~2,600 events — roughly
/// three weeks at the July 2026 rate, or a year+ at post-suppression rates.
/// Override via `[tracking] downgrade_log_max_bytes` in config.toml.
pub const DEFAULT_DOWNGRADE_LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
