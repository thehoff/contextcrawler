//! Raw output recovery -- saves unfiltered output to disk on command failure.

use super::constants::RTK_DATA_DIR;
use crate::core::config::Config;
use std::path::PathBuf;

/// Minimum output size to tee (smaller outputs don't need recovery)
const MIN_TEE_SIZE: usize = 500;

/// Default max files to keep in tee directory
const DEFAULT_MAX_FILES: usize = 20;

/// Default max file size (1MB)
const DEFAULT_MAX_FILE_SIZE: usize = 1_048_576;

/// Sanitize a command slug for use in filenames.
/// Replaces non-alphanumeric chars (except underscore/hyphen) with underscore,
/// truncates at 40 chars.
fn sanitize_slug(slug: &str) -> String {
    let sanitized: String = slug
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.len() > 40 {
        sanitized[..40].to_string()
    } else {
        sanitized
    }
}

/// Confine a tee directory to the user's home directory.
///
/// The directory may not exist yet, so we canonicalise the deepest existing
/// ancestor and re-attach the tail. Paths that escape `$HOME` are rejected
/// (returns None) so a hostile config/env value cannot redirect raw command
/// output — which may contain secrets — to an arbitrary location.
fn confine_tee_dir_to_home(dir: PathBuf) -> Option<PathBuf> {
    let home = dirs::home_dir().and_then(|h| h.canonicalize().ok())?;

    let mut existing = dir.as_path();
    let mut tail = PathBuf::new();
    let resolved = loop {
        if let Ok(c) = existing.canonicalize() {
            break c.join(&tail);
        }
        match existing.parent() {
            Some(p) => {
                if let Some(name) = existing.file_name() {
                    tail = PathBuf::from(name).join(&tail);
                }
                existing = p;
            }
            None => break dir.clone(),
        }
    };

    if resolved.starts_with(&home) {
        Some(resolved)
    } else {
        eprintln!(
            "[contextcrawler] warning: tee directory '{}' resolves outside $HOME — tee disabled",
            dir.display()
        );
        None
    }
}

/// Get the tee directory, respecting config and env overrides.
///
/// Config/env-supplied directories are confined to `$HOME`. The built-in
/// default location is trusted as-is.
fn get_tee_dir(config: &Config) -> Option<PathBuf> {
    // Env var override
    if let Ok(dir) = std::env::var("RTK_TEE_DIR") {
        return confine_tee_dir_to_home(PathBuf::from(dir));
    }

    // Config override
    if let Some(ref dir) = config.tee.directory {
        return confine_tee_dir_to_home(dir.clone());
    }

    // Default: ~/.local/share/rtk/tee/
    dirs::data_local_dir().map(|d| d.join(RTK_DATA_DIR).join("tee"))
}

/// Rotate old tee files: keep only the last `max_files`, delete oldest.
fn cleanup_old_files(dir: &std::path::Path, max_files: usize) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "log"))
        .collect();

    if entries.len() <= max_files {
        return;
    }

    // Sort chronologically by mtime (filename fallback). Filename sort alone
    // misorders across the seconds→milliseconds prefix transition and is a
    // weaker signal than the filesystem timestamp. cached_key: stat each
    // entry exactly once, not per-comparison.
    entries.sort_by_cached_key(|e| {
        let mtime = e.metadata().and_then(|m| m.modified()).ok();
        (mtime, e.file_name())
    });

    let to_remove = entries.len() - max_files;
    for entry in entries.iter().take(to_remove) {
        let _ = std::fs::remove_file(entry.path());
    }
}

/// Check if tee should be skipped based on config, mode, exit code, and size.
/// Returns None if should skip, Some(tee_dir) if should proceed.
fn should_tee(
    config: &TeeConfig,
    raw_len: usize,
    exit_code: i32,
    tee_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    if !config.enabled {
        return None;
    }

    match config.mode {
        TeeMode::Never => return None,
        TeeMode::Failures => {
            if exit_code == 0 {
                return None;
            }
        }
        TeeMode::Always => {}
    }

    if raw_len < MIN_TEE_SIZE {
        return None;
    }

    tee_dir
}

/// Write raw output to a tee file in the given directory.
/// Returns file path on success.
fn write_tee_file(
    raw: &str,
    command_slug: &str,
    tee_dir: &std::path::Path,
    max_file_size: usize,
    max_files: usize,
) -> Option<PathBuf> {
    std::fs::create_dir_all(tee_dir).ok()?;

    // Redact secrets on the FULL raw buffer, before truncation. Truncating
    // first (or pre-trimming with any margin) can cut a secret so the regex
    // never sees a complete match, leaving its prefix on disk in plaintext —
    // a partial private key is still a leak. The cost is a linear regex scan
    // over the whole output; memory stays flat (Cow only allocates on match)
    // and tee only fires on failure paths, so correctness wins over CPU here.
    let raw = crate::core::secret_redact::redact(raw);

    let slug = sanitize_slug(command_slug);
    // Millisecond resolution: parallel commands failing in the same second
    // must not collide on the recovery filename. A pre-1970 system clock
    // degrades to epoch 0 rather than disabling recovery.
    let epoch_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    // Truncate at max_file_size (find a safe UTF-8 char boundary)
    let content = if raw.len() > max_file_size {
        let boundary = raw
            .char_indices()
            .take_while(|(i, _)| *i < max_file_size)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!(
            "{}\n\n--- truncated at {} bytes ---",
            &raw[..boundary],
            max_file_size
        )
    } else {
        raw.into_owned()
    };

    // Write with restricted permissions, never following symlinks and never
    // overwriting an existing recovery file. Retry with a counter suffix
    // ONLY on a name collision (AlreadyExists — same slug, same millisecond,
    // or a planted symlink occupying the path); any other I/O error (disk
    // full, permissions) aborts rather than spraying partial files.
    let mut filepath = tee_dir.join(format!("{}_{}.log", epoch_ms, slug));
    let mut counter = 0u32;
    loop {
        match write_tee_content(&filepath, content.as_bytes()) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && counter < 100 => {
                counter += 1;
                filepath = tee_dir.join(format!("{}_{}_{}.log", epoch_ms, slug, counter));
            }
            Err(_) => return None,
        }
    }

    // Rotate old files
    cleanup_old_files(tee_dir, max_files);

    Some(filepath)
}

/// Create a tee file with owner-only permissions, refusing to follow symlinks
/// and refusing to overwrite an existing file (`create_new` = `O_CREAT|O_EXCL`).
/// Returns the raw I/O error so the caller can distinguish a name collision
/// (`AlreadyExists` — retryable) from disk-full/permission failures (abort).
#[cfg(unix)]
fn write_tee_content(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true)
        // O_EXCL: fail if the path already exists — including when it exists
        // as a symlink (even dangling), so a planted link is never followed.
        .create_new(true)
        .mode(0o600)
        // O_NOFOLLOW: defence in depth alongside O_EXCL.
        .custom_flags(libc::O_NOFOLLOW);
    let mut f = opts.open(path)?;
    // If the write itself fails (disk full mid-write), unlink the partial
    // file so it neither blocks future retries nor masquerades as a
    // complete recovery file. Content is already redacted at this point,
    // so this is hygiene, not leak prevention.
    f.write_all(bytes).inspect_err(|_| {
        let _ = std::fs::remove_file(path);
    })
}

/// Non-Unix fallback: `create_new` gives the same no-overwrite + no-symlink
/// guarantees portably (O_CREAT|O_EXCL semantics). There is no 0o600
/// equivalent without platform-specific ACL crates (new deps are forbidden);
/// the tee directory lives under the user-profile data dir (%LOCALAPPDATA%
/// on Windows), which is owner-private by default ACL, so exposure is
/// directory-scoped rather than world-readable.
#[cfg(not(unix))]
fn write_tee_content(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // Unlink partial files on a failed write (see Unix variant).
    f.write_all(bytes).inspect_err(|_| {
        let _ = std::fs::remove_file(path);
    })
}

/// Write raw output to tee file if conditions are met.
/// Returns file path on success, None if skipped/failed.
pub fn tee_raw(raw: &str, command_slug: &str, exit_code: i32) -> Option<PathBuf> {
    // Check RTK_TEE=0 env override (disable)
    if std::env::var("RTK_TEE").ok().as_deref() == Some("0") {
        return None;
    }

    let config = Config::load().ok()?;
    let tee_dir = get_tee_dir(&config)?;

    let tee_dir = should_tee(&config.tee, raw.len(), exit_code, Some(tee_dir))?;

    write_tee_file(
        raw,
        command_slug,
        &tee_dir,
        config.tee.max_file_size,
        config.tee.max_files,
    )
}

/// Format the hint line with ~ shorthand for home directory.
fn format_hint(path: &std::path::Path) -> String {
    let display = if let Some(home) = dirs::home_dir() {
        if let Ok(relative) = path.strip_prefix(&home) {
            format!("~/{}", relative.display())
        } else {
            path.display().to_string()
        }
    } else {
        path.display().to_string()
    };

    format!("[full output: {}]", display)
}

/// Convenience: tee + format hint in one call.
/// Returns hint string if file was written, None if skipped.
pub fn tee_and_hint(raw: &str, command_slug: &str, exit_code: i32) -> Option<String> {
    let path = tee_raw(raw, command_slug, exit_code)?;
    Some(format_hint(&path))
}

/// Force tee output regardless of exit code (used when filters truncate).
/// Always writes file if size >= MIN_TEE_SIZE and tee is enabled.
/// Returns hint string if file was written, None if skipped/disabled.
///
/// Used by AWS filters when FilterResult.truncated = true, ensuring
/// the LLM has access to full untruncated output via the hint path.
pub fn force_tee_hint(raw: &str, command_slug: &str) -> Option<String> {
    // Check RTK_TEE=0 env override (disable)
    if std::env::var("RTK_TEE").ok().as_deref() == Some("0") {
        return None;
    }

    // Skip if output too small
    if raw.len() < MIN_TEE_SIZE {
        return None;
    }

    let config = Config::load().ok()?;

    // Respect enabled flag but ignore mode (force tee)
    if !config.tee.enabled {
        return None;
    }

    let tee_dir = get_tee_dir(&config)?;
    let tee_dir = std::fs::create_dir_all(&tee_dir).ok().and(Some(tee_dir))?;

    let path = write_tee_file(
        raw,
        command_slug,
        &tee_dir,
        config.tee.max_file_size,
        config.tee.max_files,
    )?;

    Some(format_hint(&path))
}

/// TeeMode controls when tee writes files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TeeMode {
    #[default]
    Failures,
    Always,
    Never,
}

/// Configuration for the tee feature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TeeConfig {
    pub enabled: bool,
    pub mode: TeeMode,
    pub max_files: usize,
    pub max_file_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<PathBuf>,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: TeeMode::default(),
            max_files: DEFAULT_MAX_FILES,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            directory: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_sanitize_slug() {
        assert_eq!(sanitize_slug("cargo_test"), "cargo_test");
        assert_eq!(sanitize_slug("cargo test"), "cargo_test");
        assert_eq!(sanitize_slug("cargo-test"), "cargo-test");
        assert_eq!(sanitize_slug("go/test/./pkg"), "go_test___pkg");
        // Truncate at 40
        let long = "a".repeat(50);
        assert_eq!(sanitize_slug(&long).len(), 40);
    }

    #[test]
    fn test_should_tee_disabled() {
        let config = TeeConfig {
            enabled: false,
            ..TeeConfig::default()
        };
        let dir = PathBuf::from("/tmp/tee");
        assert!(should_tee(&config, 1000, 1, Some(dir)).is_none());
    }

    #[test]
    fn test_should_tee_never_mode() {
        let config = TeeConfig {
            mode: TeeMode::Never,
            ..TeeConfig::default()
        };
        let dir = PathBuf::from("/tmp/tee");
        assert!(should_tee(&config, 1000, 1, Some(dir)).is_none());
    }

    #[test]
    fn test_should_tee_skip_small_output() {
        let config = TeeConfig::default();
        let dir = PathBuf::from("/tmp/tee");
        // Below MIN_TEE_SIZE (500)
        assert!(should_tee(&config, 100, 1, Some(dir)).is_none());
    }

    #[test]
    fn test_should_tee_skip_success_in_failures_mode() {
        let config = TeeConfig::default(); // mode = Failures
        let dir = PathBuf::from("/tmp/tee");
        assert!(should_tee(&config, 1000, 0, Some(dir)).is_none());
    }

    #[test]
    fn test_should_tee_proceed_on_failure() {
        let config = TeeConfig::default(); // mode = Failures
        let dir = PathBuf::from("/tmp/tee");
        assert!(should_tee(&config, 1000, 1, Some(dir)).is_some());
    }

    #[test]
    fn test_should_tee_always_mode_success() {
        let config = TeeConfig {
            mode: TeeMode::Always,
            ..TeeConfig::default()
        };
        let dir = PathBuf::from("/tmp/tee");
        assert!(should_tee(&config, 1000, 0, Some(dir)).is_some());
    }

    #[test]
    fn test_write_tee_file_creates_file() {
        let tmpdir = tempfile::tempdir().unwrap();
        let content = "error: test failed\n".repeat(50);
        let result = write_tee_file(
            &content,
            "cargo_test",
            tmpdir.path(),
            DEFAULT_MAX_FILE_SIZE,
            20,
        );
        assert!(result.is_some());

        let path = result.unwrap();
        assert!(path.exists());
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("error: test failed"));
    }

    #[test]
    fn test_write_tee_file_truncation() {
        let tmpdir = tempfile::tempdir().unwrap();
        let big_output = "x".repeat(2000);
        // Set max_file_size to 1000 bytes
        let result = write_tee_file(&big_output, "test", tmpdir.path(), 1000, 20);
        assert!(result.is_some());

        let path = result.unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("--- truncated at 1000 bytes ---"));
        assert!(content.len() < 2000);
    }

    #[test]
    fn test_write_tee_file_truncation_utf8_boundary() {
        let tmpdir = tempfile::tempdir().unwrap();
        // Create a string where the truncation point falls inside a multi-byte char.
        // Japanese chars are 3 bytes each in UTF-8.
        // 332 chars * 3 bytes = 996 bytes, then one more = 999 bytes.
        // With max_file_size=998, the cut falls mid-character.
        let japanese = "\u{6F22}".repeat(333); // 999 bytes of 3-byte chars
        assert_eq!(japanese.len(), 999);

        // Truncate at 998 — falls in the middle of the 333rd character
        let result = write_tee_file(&japanese, "test_utf8", tmpdir.path(), 998, 20);
        assert!(result.is_some());

        let path = result.unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("--- truncated at 998 bytes ---"));
        // Should contain 332 full characters (996 bytes), not panic
        assert!(content.starts_with(&"\u{6F22}".repeat(332)));
    }

    #[test]
    fn test_write_tee_file_truncation_emoji() {
        let tmpdir = tempfile::tempdir().unwrap();
        // Emoji are 4 bytes each in UTF-8
        let emojis = "\u{1F600}".repeat(100); // 400 bytes
        assert_eq!(emojis.len(), 400);

        // Truncate at 201 — falls mid-emoji (4-byte boundary is at 200, 204)
        let result = write_tee_file(&emojis, "test_emoji", tmpdir.path(), 201, 20);
        assert!(result.is_some());

        let path = result.unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("--- truncated at 201 bytes ---"));
        // The emoji portion should be exactly 200 bytes (50 emojis),
        // rounded down from 201 to the nearest char boundary
        let target = "\u{1F600}".repeat(50);
        assert!(content.starts_with(&target));
    }

    #[test]
    fn test_cleanup_old_files() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();

        // Create 25 .log files
        for i in 0..25 {
            let filename = format!("{:010}_{}.log", 1000000 + i, "test");
            fs::write(dir.join(&filename), "content").unwrap();
        }

        cleanup_old_files(dir, 20);

        let remaining: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(remaining.len(), 20);

        // Oldest 5 should be removed
        for i in 0..5 {
            let filename = format!("{:010}_{}.log", 1000000 + i, "test");
            assert!(!dir.join(&filename).exists());
        }
        // Newest 20 should remain
        for i in 5..25 {
            let filename = format!("{:010}_{}.log", 1000000 + i, "test");
            assert!(dir.join(&filename).exists());
        }
    }

    #[test]
    fn test_format_hint() {
        let path = PathBuf::from("/tmp/rtk/tee/123_cargo_test.log");
        let hint = format_hint(&path);
        assert!(hint.starts_with("[full output: "));
        assert!(hint.ends_with(']'));
        assert!(hint.contains("123_cargo_test.log"));
    }

    #[test]
    fn test_tee_config_default() {
        let config = TeeConfig::default();
        assert!(config.enabled);
        assert_eq!(config.mode, TeeMode::Failures);
        assert_eq!(config.max_files, 20);
        assert_eq!(config.max_file_size, 1_048_576);
        assert!(config.directory.is_none());
    }

    #[test]
    fn test_tee_config_deserialize() {
        let toml_str = r#"
enabled = true
mode = "always"
max_files = 10
max_file_size = 524288
directory = "/tmp/rtk-tee"
"#;
        let config: TeeConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.mode, TeeMode::Always);
        assert_eq!(config.max_files, 10);
        assert_eq!(config.max_file_size, 524288);
        assert_eq!(config.directory, Some(PathBuf::from("/tmp/rtk-tee")));

        // Round-trip
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: TeeConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.mode, TeeMode::Always);
        assert_eq!(deserialized.max_files, 10);
    }

    #[test]
    fn test_tee_mode_serde() {
        // Test all modes via JSON
        let mode: TeeMode = serde_json::from_str(r#""always""#).unwrap();
        assert_eq!(mode, TeeMode::Always);

        let mode: TeeMode = serde_json::from_str(r#""failures""#).unwrap();
        assert_eq!(mode, TeeMode::Failures);

        let mode: TeeMode = serde_json::from_str(r#""never""#).unwrap();
        assert_eq!(mode, TeeMode::Never);
    }

    // --- Council blocker (2026-06-02): tee files must never carry plaintext
    //     secrets, must not silently overwrite, must not follow symlinks ---

    #[test]
    fn test_write_tee_file_redacts_credentials() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let content = format!(
            "{}\nAuthorization: Bearer eyJsecrettoken123\nTEA_TOKEN=147dd871deadbeef\n{}",
            "x".repeat(300),
            "y".repeat(300)
        );
        let result = write_tee_file(
            &content,
            "curl_api",
            tmpdir.path(),
            DEFAULT_MAX_FILE_SIZE,
            20,
        );
        let path = result.expect("tee file written");
        let written = fs::read_to_string(&path).expect("read tee file");
        assert!(
            !written.contains("eyJsecrettoken123"),
            "bearer token leaked to disk: {}",
            written
        );
        assert!(
            !written.contains("147dd871deadbeef"),
            "env-var token leaked to disk: {}",
            written
        );
        assert!(written.contains("<REDACTED>"), "redaction marker missing");
        // Diagnostic padding preserved.
        assert!(written.contains(&"x".repeat(300)));
    }

    #[test]
    fn test_write_tee_file_redacts_json_output_secrets() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let content = format!(
            r#"{}{{"Name": "prod/db", "SecretString": "{{\"password\":\"hunter2\"}}"}}"#,
            "pad ".repeat(200)
        );
        let result = write_tee_file(
            &content,
            "aws_secretsmanager",
            tmpdir.path(),
            DEFAULT_MAX_FILE_SIZE,
            20,
        );
        let path = result.expect("tee file written");
        let written = fs::read_to_string(&path).expect("read tee file");
        assert!(
            !written.contains("hunter2"),
            "secretsmanager payload leaked to disk: {}",
            written
        );
    }

    #[test]
    fn test_write_tee_file_no_silent_overwrite() {
        // Burst of writes with the same slug (parallel commands failing in the
        // same instant) must yield distinct recovery files, never overwrite.
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let mut paths = Vec::new();
        for i in 0..5 {
            let content = format!("write number {} {}", i, "z".repeat(600));
            let path = write_tee_file(
                &content,
                "same_slug",
                tmpdir.path(),
                DEFAULT_MAX_FILE_SIZE,
                20,
            )
            .expect("tee write");
            paths.push((i, path));
        }
        // All paths distinct
        let unique: std::collections::HashSet<_> = paths.iter().map(|(_, p)| p.clone()).collect();
        assert_eq!(
            unique.len(),
            5,
            "tee writes overwrote each other: {:?}",
            paths
        );
        // Each file still holds its own content
        for (i, path) in &paths {
            let written = fs::read_to_string(path).expect("read tee file");
            assert!(
                written.contains(&format!("write number {} ", i)),
                "file {} content clobbered",
                path.display()
            );
        }
    }

    #[test]
    fn test_write_tee_file_redacts_secret_straddling_truncation_boundary() {
        // A secret that starts just before the truncation cut and extends past
        // it must never land on disk, even partially. This is why redaction
        // runs on the full buffer BEFORE truncation (council round-3 blocker).
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let max_size = 1000usize;
        // 950 bytes of padding, then a long bearer token that crosses the
        // 1000-byte boundary, then more output.
        let secret_value = format!("eyJStraddle{}", "S".repeat(200));
        let content = format!(
            "{}\nAuthorization: Bearer {}\ntrailing diagnostic output {}",
            "p".repeat(950),
            secret_value,
            "t".repeat(600)
        );
        let path =
            write_tee_file(&content, "straddle", tmpdir.path(), max_size, 20).expect("tee write");
        let written = fs::read_to_string(&path).expect("read tee file");
        assert!(
            !written.contains("eyJStraddle"),
            "boundary-straddling secret prefix leaked to disk: {}",
            written
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_write_tee_content_refuses_symlink() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = tmpdir.path().join("target.txt");
        fs::write(&target, "original").expect("write target");
        let link = tmpdir.path().join("link.log");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let result = write_tee_content(&link, b"attacker content");
        assert!(result.is_err(), "must refuse to write through a symlink");
        // A planted symlink reports AlreadyExists, so the caller's retry
        // loop steps past it to a counter-suffixed name instead of aborting.
        assert_eq!(
            result.expect_err("symlink write must fail").kind(),
            std::io::ErrorKind::AlreadyExists,
            "symlink occupation must be retryable"
        );
        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "original",
            "symlink target must be untouched"
        );
    }

    #[test]
    fn test_force_tee_hint_skip_small_output() {
        // force_tee_hint should respect MIN_TEE_SIZE
        let small_output = "short error";
        let hint = force_tee_hint(small_output, "test_cmd");
        assert!(hint.is_none(), "Should skip output < MIN_TEE_SIZE");
    }

    #[test]
    fn test_force_tee_hint_respects_env_disable() {
        // When RTK_TEE=0, force_tee_hint should return None
        std::env::set_var("RTK_TEE", "0");
        let large_output = "x".repeat(1000);
        let hint = force_tee_hint(&large_output, "test_cmd");
        std::env::remove_var("RTK_TEE");
        assert!(hint.is_none(), "Should respect RTK_TEE=0");
    }
}
