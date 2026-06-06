//! One-shot migration of on-disk **settings** from the legacy `rtk` directory
//! names to the canonical `ctxcrl` names.
//!
//! Scope is deliberately limited to schema-stable user settings:
//! - user config dir:  `config.toml`, `filters.toml`, `trusted_filters.json`
//! - data dir:         (same basenames, in case they live there)
//! - project-local:    `./.rtk`  ->  `./.ctxcrl`
//!
//! The tracking database (`history.db`) is **intentionally NOT migrated**. The
//! DB is a complete reset: a fresh database with the current schema is created
//! at the new `ctxcrl` path on first run, and any old-path/old-schema DB is
//! left orphaned on disk, untouched. No DB back-compat, no `ALTER`.
//!
//! Migration is **per file**, not per directory. Other subsystems (telemetry
//! `.device_salt`, the `tee/` spool, the freshly-created `history.db`) create
//! files under the new `ctxcrl` directory early, so a per-directory "new dir
//! absent" guard would see the directory already present and skip the settings.
//! Instead each target FILE is checked independently: a pre-existing new
//! directory never blocks moving a file whose destination is still absent. An
//! existing destination file is never overwritten. Each move is logged once.

use std::path::Path;
use std::sync::Once;

use super::constants::{CONFIG_TOML, FILTERS_TOML, RTK_DATA_DIR, TRUSTED_FILTERS_JSON};

/// Legacy directory segment that predates the rename.
const LEGACY_DATA_DIR: &str = "rtk";
/// Legacy project-local directory.
const LEGACY_PROJECT_DIR: &str = ".rtk";

/// Schema-stable settings files that migrate from the legacy `rtk` segment.
/// Each basename is checked independently in BOTH the user config dir and the
/// user data dir; a basename absent from a given directory is simply skipped.
/// `history.db` is deliberately absent — see the module docs.
const MIGRATABLE_FILES: &[&str] = &[CONFIG_TOML, FILTERS_TOML, TRUSTED_FILTERS_JSON];

static MIGRATED: Once = Once::new();

/// Run the legacy->canonical settings migration at most once per process.
///
/// Safe (and cheap — a handful of `exists` checks) to call unconditionally.
/// Invoked early from `main()`, before anything reads config/filters.
pub fn migrate_legacy_dirs_once() {
    MIGRATED.call_once(run_migration);
}

fn run_migration() {
    if let Some(config_dir) = dirs::config_dir() {
        migrate_dir_files(
            &config_dir.join(LEGACY_DATA_DIR),
            &config_dir.join(RTK_DATA_DIR),
        );
    }
    if let Some(data_dir) = dirs::data_local_dir() {
        migrate_dir_files(&data_dir.join(LEGACY_DATA_DIR), &data_dir.join(RTK_DATA_DIR));
    }
    let project_new = format!(".{RTK_DATA_DIR}");
    migrate_project_local(Path::new(LEGACY_PROJECT_DIR), Path::new(&project_new));
}

/// Per-file migration of every known settings basename for one `(old, new)` pair.
fn migrate_dir_files(old_dir: &Path, new_dir: &Path) {
    for name in MIGRATABLE_FILES {
        migrate_file(old_dir, new_dir, name);
    }
}

/// Move `old_dir/name` -> `new_dir/name` iff the destination file is **absent**
/// and the source file is **present**. `new_dir` is created on demand, so a
/// pre-existing sibling there (e.g. `.device_salt`, `tee/`, a fresh
/// `history.db`) never blocks the move. An existing destination is never
/// overwritten. Logs each move once.
fn migrate_file(old_dir: &Path, new_dir: &Path, name: &str) -> bool {
    let old = old_dir.join(name);
    let new = new_dir.join(name);
    if new.exists() || !old.exists() {
        return false;
    }
    if let Err(e) = std::fs::create_dir_all(new_dir) {
        eprintln!(
            "[contextcrawler] warning: could not create {}: {e}",
            new_dir.display()
        );
        return false;
    }
    move_path(&old, &new)
}

/// Project-local `.rtk` -> `.ctxcrl`. Moves the whole directory when the
/// destination is absent (the common case — project dirs aren't pre-polluted);
/// otherwise migrates the known per-file payload so a partially-created
/// `.ctxcrl` still gets the project filters.
fn migrate_project_local(old_dir: &Path, new_dir: &Path) {
    if !old_dir.exists() {
        return;
    }
    if !new_dir.exists() {
        move_path(old_dir, new_dir);
    } else {
        migrate_file(old_dir, new_dir, FILTERS_TOML);
    }
}

/// `rename` with success/failure logging. Both endpoints live under the same
/// parent (and therefore the same filesystem), so a plain rename suffices.
fn move_path(old: &Path, new: &Path) -> bool {
    match std::fs::rename(old, new) {
        Ok(()) => {
            eprintln!(
                "[contextcrawler] migrated {} -> {} (legacy rtk path)",
                old.display(),
                new.display()
            );
            true
        }
        Err(e) => {
            eprintln!(
                "[contextcrawler] warning: could not migrate {} -> {}: {e}",
                old.display(),
                new.display()
            );
            false
        }
    }
}

/// Build a unique temp scratch dir for tests (never touches `$HOME`).
#[cfg(test)]
fn unique_tmp() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("ctxcrl-migrate-test-{pid}-{n}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // (a) old settings file present + new dir absent -> migrated.
    #[test]
    fn migrates_when_old_present_new_absent() {
        let root = unique_tmp();
        let old_dir = root.join("rtk");
        let new_dir = root.join("ctxcrl");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join(CONFIG_TOML), b"data").unwrap();

        assert!(migrate_file(&old_dir, &new_dir, CONFIG_TOML), "should migrate");
        assert!(!old_dir.join(CONFIG_TOML).exists(), "old gone after rename");
        assert!(new_dir.join(CONFIG_TOML).exists(), "payload moved");

        std::fs::remove_dir_all(&root).ok();
    }

    // (b) old present + new dir exists with only .device_salt / a fresh
    //     history.db -> settings STILL migrate (the per-file guarantee).
    #[test]
    fn migrates_settings_even_when_new_dir_has_salt_and_fresh_db() {
        let root = unique_tmp();
        let old_dir = root.join("rtk");
        let new_dir = root.join("ctxcrl");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join(CONFIG_TOML), b"cfg").unwrap();
        std::fs::write(old_dir.join(FILTERS_TOML), b"flt").unwrap();
        // Pre-existing new dir containing only unrelated/regenerated files.
        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::write(new_dir.join(".device_salt"), b"salt").unwrap();
        std::fs::write(new_dir.join("history.db"), b"FRESH").unwrap();

        migrate_dir_files(&old_dir, &new_dir);

        assert!(new_dir.join(CONFIG_TOML).exists(), "config migrated");
        assert!(new_dir.join(FILTERS_TOML).exists(), "filters migrated");
        assert!(new_dir.join(".device_salt").exists(), "salt untouched");
        // The freshly-created DB must NOT be disturbed by the settings move.
        assert_eq!(std::fs::read(new_dir.join("history.db")).unwrap(), b"FRESH");

        std::fs::remove_dir_all(&root).ok();
    }

    // (c) new settings file already present -> no-op, never overwrite.
    #[test]
    fn noop_when_new_file_exists() {
        let root = unique_tmp();
        let old_dir = root.join("rtk");
        let new_dir = root.join("ctxcrl");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::write(old_dir.join(CONFIG_TOML), b"OLD").unwrap();
        std::fs::write(new_dir.join(CONFIG_TOML), b"NEW").unwrap();

        assert!(
            !migrate_file(&old_dir, &new_dir, CONFIG_TOML),
            "must not overwrite an existing destination file"
        );
        assert_eq!(std::fs::read(new_dir.join(CONFIG_TOML)).unwrap(), b"NEW");
        assert!(old_dir.join(CONFIG_TOML).exists(), "old left intact");

        std::fs::remove_dir_all(&root).ok();
    }

    // (d) old absent -> no-op, never create the new file.
    #[test]
    fn noop_when_old_absent() {
        let root = unique_tmp();
        let old_dir = root.join("rtk");
        let new_dir = root.join("ctxcrl");
        std::fs::create_dir_all(&root).unwrap();

        assert!(!migrate_file(&old_dir, &new_dir, CONFIG_TOML), "nothing to do");
        assert!(!new_dir.join(CONFIG_TOML).exists());

        std::fs::remove_dir_all(&root).ok();
    }

    // history.db must NEVER be migrated — it is not in the settings set.
    #[test]
    fn history_db_is_not_migrated() {
        let root = unique_tmp();
        let old_dir = root.join("rtk");
        let new_dir = root.join("ctxcrl");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("history.db"), b"olddb").unwrap();
        std::fs::write(old_dir.join(CONFIG_TOML), b"cfg").unwrap();

        migrate_dir_files(&old_dir, &new_dir);

        assert!(
            !new_dir.join("history.db").exists(),
            "history.db must NOT be migrated (complete reset)"
        );
        assert!(
            old_dir.join("history.db").exists(),
            "legacy history.db left orphaned, untouched"
        );
        assert!(new_dir.join(CONFIG_TOML).exists(), "settings still migrate");

        std::fs::remove_dir_all(&root).ok();
    }

    // Per-dir helper migrates each settings file independently; absent ones
    // (and history.db) are skipped, new dir is created on demand.
    #[test]
    fn migrate_dir_files_moves_each_independently() {
        let root = unique_tmp();
        let old_dir = root.join("rtk");
        let new_dir = root.join("ctxcrl");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join(CONFIG_TOML), b"cfg").unwrap();
        std::fs::write(old_dir.join(TRUSTED_FILTERS_JSON), b"{}").unwrap();
        // FILTERS_TOML deliberately absent — must be skipped silently.

        migrate_dir_files(&old_dir, &new_dir);

        assert!(new_dir.join(CONFIG_TOML).exists());
        assert!(new_dir.join(TRUSTED_FILTERS_JSON).exists());
        assert!(!new_dir.join(FILTERS_TOML).exists());

        std::fs::remove_dir_all(&root).ok();
    }

    // Project-local: whole-dir move when the destination is absent.
    #[test]
    fn project_local_moves_whole_dir_when_absent() {
        let root = unique_tmp();
        let old_dir = root.join(".rtk");
        let new_dir = root.join(".ctxcrl");
        std::fs::create_dir_all(old_dir.join("filters")).unwrap();
        std::fs::write(old_dir.join(FILTERS_TOML), b"f").unwrap();
        std::fs::write(old_dir.join("filters").join("a.toml"), b"a").unwrap();

        migrate_project_local(&old_dir, &new_dir);

        assert!(!old_dir.exists());
        assert!(new_dir.join(FILTERS_TOML).exists());
        assert!(new_dir.join("filters").join("a.toml").exists());

        std::fs::remove_dir_all(&root).ok();
    }

    // Project-local: per-file fallback when the destination dir already exists.
    #[test]
    fn project_local_per_file_when_new_dir_exists() {
        let root = unique_tmp();
        let old_dir = root.join(".rtk");
        let new_dir = root.join(".ctxcrl");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::write(old_dir.join(FILTERS_TOML), b"f").unwrap();

        migrate_project_local(&old_dir, &new_dir);

        assert!(new_dir.join(FILTERS_TOML).exists(), "filters.toml migrated");
        assert!(!old_dir.join(FILTERS_TOML).exists());

        std::fs::remove_dir_all(&root).ok();
    }
}
