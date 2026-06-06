/// Canonical on-disk directory segment used under the user config dir
/// (`~/.config/<RTK_DATA_DIR>`) and data dir (`~/.local/share/<RTK_DATA_DIR>`).
/// Renamed from the legacy `rtk`; see `core::path_migrate` for the move.
pub const RTK_DATA_DIR: &str = "ctxcrl";
pub const HISTORY_DB: &str = "history.db";
pub const CONFIG_TOML: &str = "config.toml";
pub const FILTERS_TOML: &str = "filters.toml";
pub const TRUSTED_FILTERS_JSON: &str = "trusted_filters.json";
pub const DEFAULT_HISTORY_DAYS: i64 = 90;
