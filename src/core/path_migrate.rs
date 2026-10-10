//! One-shot migration of on-disk **settings** from the legacy `rtk` directory
//! names to the canonical `ctxcrl` names.
//!
//! Scope is deliberately limited to schema-stable user settings:
//! - user config dir:  `config.toml`, `filters.toml`, `trusted_filters.json`
//! - data dir:         (same basenames, in case they live there)
//! - project-local:    `./.rtk` and `./.ctxcrl` -> `./.contextcrawler`
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

/// Legacy directory segment from the original rtk release.
const LEGACY_DATA_DIR_ORIG: &str = "rtk"; // branding-lint: allow legacy
/// Legacy directory segment from the intermediate rename (rtk -> ctxcrl).
const LEGACY_DATA_DIR_PREV: &str = "ctxcrl"; // branding-lint: allow legacy
/// Legacy project-local directory (original).
const LEGACY_PROJECT_DIR_ORIG: &str = ".rtk";
/// Legacy project-local directory (intermediate rename).
const LEGACY_PROJECT_DIR_PREV: &str = ".ctxcrl";

/// Project-local `filters.toml` the loader should open.
///
/// Canonical is `.contextcrawler/filters.toml`, which is where this module
/// moves a legacy project dir. `.ctxcrl/filters.toml` is returned only when
/// the canonical path has no directory entry. Presence is `symlink_metadata`,
/// not `exists`, so a dangling or unreadable canonical file does not fall
/// through to the legacy file. Trust is the caller's job, on this path.
pub fn project_filters_file(base: &Path) -> Option<std::path::PathBuf> {
    for rel in project_filters_rel_paths() {
        let path = base.join(&rel);
        if path.symlink_metadata().is_ok() {
            return Some(path);
        }
    }
    None
}

fn project_filters_rel_paths() -> [std::path::PathBuf; 2] {
    [
        std::path::PathBuf::from(format!(".{RTK_DATA_DIR}")).join(FILTERS_TOML),
        std::path::PathBuf::from(LEGACY_PROJECT_DIR_PREV).join(FILTERS_TOML),
    ]
}

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
    // Two legacy names migrate to the canonical name (RTK_DATA_DIR):
    //   `rtk`     — the original dir, before the first rename.
    //   `ctxcrl`  — the intermediate dir, after the first rename.
    //
    // Order matters when both legacy dirs coexist: the FIRST migration wins
    // because the destination is created on the first move and the second
    // is then skipped (no overwrite). The intermediate (`ctxcrl`) state is
    // the more recent user intent in the typical upgrade path
    // (rtk→ctxcrl→contextcrawler), so we try `ctxcrl` first and fall back
    // to `rtk` only if the intermediate dir is absent. Per-file moves;
    // never overwrites an existing destination.
    if let Some(config_dir) = dirs::config_dir() {
        migrate_dir_files(
            &config_dir.join(LEGACY_DATA_DIR_PREV),
            &config_dir.join(RTK_DATA_DIR),
        );
        migrate_dir_files(
            &config_dir.join(LEGACY_DATA_DIR_ORIG),
            &config_dir.join(RTK_DATA_DIR),
        );
    }
    if let Some(data_dir) = dirs::data_local_dir() {
        migrate_dir_files(
            &data_dir.join(LEGACY_DATA_DIR_PREV),
            &data_dir.join(RTK_DATA_DIR),
        );
        migrate_dir_files(
            &data_dir.join(LEGACY_DATA_DIR_ORIG),
            &data_dir.join(RTK_DATA_DIR),
        );
    }
    let project_new = format!(".{RTK_DATA_DIR}");
    migrate_project_local(Path::new(LEGACY_PROJECT_DIR_PREV), Path::new(&project_new));
    migrate_project_local(Path::new(LEGACY_PROJECT_DIR_ORIG), Path::new(&project_new));
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
    // Use `symlink_metadata` (does NOT follow symlinks) so a missing path and a
    // dangling symlink are both detected here.
    let Ok(meta) = old_dir.symlink_metadata() else {
        return; // nothing to migrate
    };
    // Symlink guard: never `rename` a symlinked `.rtk` — an attacker could plant
    // a symlink to redirect the move at the new path. Treat a symlinked legacy
    // dir as "do not migrate" (same-user local hardening).
    if meta.file_type().is_symlink() {
        return;
    }
    if !new_dir.exists() {
        move_path(old_dir, new_dir);
    } else {
        migrate_file(old_dir, new_dir, FILTERS_TOML);
        // Also migrate custom project filters under `.rtk/filters/*.toml` into
        // `.ctxcrl/filters/` (per-file, never overwriting an existing one).
        migrate_filters_subdir(old_dir, new_dir);
    }
}

/// Per-file migration of `*.toml` under `old_dir/filters/` into
/// `new_dir/filters/`. Never overwrites an existing destination file. No-op if
/// the source subdir is absent.
fn migrate_filters_subdir(old_dir: &Path, new_dir: &Path) {
    let old_filters = old_dir.join("filters");
    if !old_filters.is_dir() {
        return;
    }
    let new_filters = new_dir.join("filters");
    let Ok(entries) = std::fs::read_dir(&old_filters) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            migrate_file(&old_filters, &new_filters, name);
        }
    }
}

/// `rename` with success/failure logging. Both endpoints live under the same
/// parent (and therefore the same filesystem), so a plain rename suffices.
fn move_path(old: &Path, new: &Path) -> bool {
    match std::fs::rename(old, new) {
        Ok(()) => {
            eprintln!(
                "[contextcrawler] migrated {} -> {} (legacy rtk path)", // branding-lint: allow legacy
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

        assert!(
            migrate_file(&old_dir, &new_dir, CONFIG_TOML),
            "should migrate"
        );
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

        assert!(
            !migrate_file(&old_dir, &new_dir, CONFIG_TOML),
            "nothing to do"
        );
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

    // Project-local: dest exists + `.rtk/filters/*.toml` -> custom project
    // filters migrate per-file into `.ctxcrl/filters/`, never overwriting an
    // existing destination file. (Fix 3)
    #[test]
    fn project_local_migrates_filters_subdir_when_new_dir_exists() {
        let root = unique_tmp();
        let old_dir = root.join(".rtk");
        let new_dir = root.join(".ctxcrl");
        std::fs::create_dir_all(old_dir.join("filters")).unwrap();
        std::fs::create_dir_all(new_dir.join("filters")).unwrap();
        std::fs::write(old_dir.join("filters").join("custom.toml"), b"new").unwrap();
        std::fs::write(old_dir.join("filters").join("keep.toml"), b"src").unwrap();
        // Non-toml files are ignored.
        std::fs::write(old_dir.join("filters").join("README.md"), b"doc").unwrap();
        // Pre-existing dest filter must NOT be overwritten.
        std::fs::write(new_dir.join("filters").join("keep.toml"), b"DEST").unwrap();

        migrate_project_local(&old_dir, &new_dir);

        assert!(
            new_dir.join("filters").join("custom.toml").exists(),
            "custom filter migrated into .ctxcrl/filters/"
        );
        assert_eq!(
            std::fs::read(new_dir.join("filters").join("custom.toml")).unwrap(),
            b"new"
        );
        // Existing dest kept; un-migrated source left intact (never overwritten).
        assert_eq!(
            std::fs::read(new_dir.join("filters").join("keep.toml")).unwrap(),
            b"DEST"
        );
        assert!(
            old_dir.join("filters").join("keep.toml").exists(),
            "source of skipped (already-present) filter left intact"
        );
        assert!(
            !new_dir.join("filters").join("README.md").exists(),
            "non-toml files are not migrated"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    // Project-local: a symlinked `.rtk` is NEVER migrated (symlink guard). (Fix 4)
    #[cfg(unix)]
    #[test]
    fn project_local_skips_symlinked_legacy_dir() {
        use std::os::unix::fs::symlink;
        let root = unique_tmp();
        let real = root.join("real");
        let old_dir = root.join(".rtk");
        let new_dir = root.join(".ctxcrl");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join(FILTERS_TOML), b"f").unwrap();
        symlink(&real, &old_dir).unwrap();

        migrate_project_local(&old_dir, &new_dir);

        assert!(
            !new_dir.exists(),
            "symlinked legacy dir must not be migrated"
        );
        assert!(
            old_dir.symlink_metadata().unwrap().file_type().is_symlink(),
            "the planted symlink is left untouched"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    // When both legacy configs coexist (`rtk/...` and `ctxcrl/...`), the
    // migration must prefer the intermediate (`ctxcrl`) state because it
    // represents the user's intent after the rtk→ctxcrl upgrade. The
    // migration's first-mover wins (no overwrite), so the order of
    // `run_migration` is the policy. This test pins that order.
    #[test]
    fn ctxcrl_legacy_wins_when_both_legacy_configs_coexist() {
        let root = unique_tmp();
        let legacy_orig = root.join(LEGACY_DATA_DIR_ORIG);
        let legacy_prev = root.join(LEGACY_DATA_DIR_PREV);
        let dest = root.join(RTK_DATA_DIR);
        std::fs::create_dir_all(&legacy_orig).unwrap();
        std::fs::create_dir_all(&legacy_prev).unwrap();
        std::fs::create_dir_all(&dest).unwrap();

        std::fs::write(legacy_orig.join(FILTERS_TOML), b"orig-content").unwrap();
        std::fs::write(legacy_prev.join(FILTERS_TOML), b"prev-content").unwrap();

        // Mirrors the order in `run_migration`: ctxcrl (intermediate) first,
        // then the original legacy dir. The first-mover wins.
        migrate_dir_files(&legacy_prev, &dest);
        migrate_dir_files(&legacy_orig, &dest);

        assert_eq!(
            std::fs::read(dest.join(FILTERS_TOML)).unwrap(),
            b"prev-content",
            "intermediate legacy must win when both legacy configs coexist"
        );
        assert!(
            legacy_orig.join(FILTERS_TOML).exists(),
            "original legacy source is left intact when the migration is a no-op"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    // Project-local: when both project-local legacy dirs coexist
    // (`.rtk` and `.ctxcrl`), the intermediate (`.ctxcrl`) state wins.
    #[test]
    fn project_local_ctxcrl_wins_when_both_legacy_dirs_coexist() {
        let root = unique_tmp();
        let legacy_orig = root.join(LEGACY_PROJECT_DIR_ORIG);
        let legacy_prev = root.join(LEGACY_PROJECT_DIR_PREV);
        let dest = root.join(format!(".{RTK_DATA_DIR}"));
        std::fs::create_dir_all(&legacy_orig).unwrap();
        std::fs::create_dir_all(&legacy_prev).unwrap();
        std::fs::write(legacy_orig.join(FILTERS_TOML), b"orig-proj").unwrap();
        std::fs::write(legacy_prev.join(FILTERS_TOML), b"prev-proj").unwrap();

        // Mirrors the order in `run_migration`: ctxcrl (intermediate) first,
        // then the original legacy dir. The first-mover wins.
        migrate_project_local(&legacy_prev, &dest);
        migrate_project_local(&legacy_orig, &dest);

        assert_eq!(
            std::fs::read(dest.join(FILTERS_TOML)).unwrap(),
            b"prev-proj",
            "project-local intermediate state must win when both legacy dirs coexist"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn project_filters_file_prefers_canonical_then_legacy() {
        let root = unique_tmp();
        assert!(project_filters_file(&root).is_none());

        let legacy_dir = root.join(LEGACY_PROJECT_DIR_PREV);
        std::fs::create_dir_all(&legacy_dir).unwrap();
        let legacy = legacy_dir.join(FILTERS_TOML);
        std::fs::write(&legacy, b"old").unwrap();
        assert_eq!(
            project_filters_file(&root).as_deref(),
            Some(legacy.as_path())
        );

        let canonical_dir = root.join(format!(".{RTK_DATA_DIR}"));
        std::fs::create_dir_all(&canonical_dir).unwrap();
        let canonical = canonical_dir.join(FILTERS_TOML);
        std::fs::write(&canonical, b"new").unwrap();
        assert_eq!(
            project_filters_file(&root).as_deref(),
            Some(canonical.as_path()),
            "canonical file wins when both are present"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn project_filters_file_keeps_dangling_canonical_symlink() {
        use std::os::unix::fs::symlink;
        let root = unique_tmp();
        let canonical_dir = root.join(format!(".{RTK_DATA_DIR}"));
        std::fs::create_dir_all(&canonical_dir).unwrap();
        let link = canonical_dir.join(FILTERS_TOML);
        symlink(root.join("missing-target"), &link).unwrap();

        let legacy_dir = root.join(LEGACY_PROJECT_DIR_PREV);
        std::fs::create_dir_all(&legacy_dir).unwrap();
        std::fs::write(legacy_dir.join(FILTERS_TOML), b"old").unwrap();

        assert_eq!(
            project_filters_file(&root).as_deref(),
            Some(link.as_path()),
            "a present canonical entry must not fall through to the legacy file"
        );

        std::fs::remove_dir_all(&root).ok();
    }
}
