//! Session-scoped repeat-read elimination for `contextcrawler read` (#236).
//!
//! `read` defaults to `FilterLevel::None`, so a whole-file read is a verbatim
//! passthrough. Across a 153k-command corpus that made `read` the single
//! largest token sink — 4.42M spent, 76% of calls saving exactly nothing — and
//! 1.84M of that was the *same file read again* inside one session
//! (`CODE_WORK_SKILLS.md` 20 times, `src/cli.rs` 5 times at 50,931 tokens).
//!
//! When a session re-reads a file whose content has not changed, this module
//! substitutes a short marker naming the file, its size and its hash, plus the
//! exact command to recover the full text. The content is never *lost* — the
//! agent is told how to get it back — so the worst case is one extra turn
//! rather than a wrong answer.
//!
//! Fail-open by construction: no session id, no cache DB, a small file, a
//! changed hash or `--force` all fall through to emitting the file in full.

use std::path::Path;

/// Env var Claude Code exports for the current session. Absent under other
/// hosts (and in a bare shell), which disables the feature entirely.
const SESSION_ENV: &str = "CLAUDE_CODE_SESSION_ID";

/// Files below this many tokens are never stubbed.
///
/// Measured against the tracking corpus: a 500-token floor recovers 1.79M of
/// the 1.92M theoretical maximum (93%) while stubbing 937 reads instead of
/// 1,601. The 664 reads it declines to touch are worth only 133k between them
/// — not worth spending a recovery turn on a file the agent can re-read for
/// the price of a few hundred tokens.
pub const DEFAULT_MIN_TOKENS: usize = 500;

/// What a previous read of this path recorded, within the current session.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheEntry {
    /// SHA-256 of the file content as it was when last emitted in full.
    pub sha: String,
    /// Token estimate of the content that was emitted.
    pub tokens: usize,
    /// RFC3339 timestamp of the first full emit in this session.
    pub first_seen: String,
}

/// Whether to emit the file or substitute the recovery marker.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Emit the full content, and record this read against the session.
    Emit,
    /// Emit the recovery marker instead; the agent already has this content.
    Stub(CacheEntry),
}

/// The decision itself, kept free of I/O so every branch is directly testable.
///
/// `prior` is the entry recorded earlier in this same session, if any.
pub fn decide(
    prior: Option<&CacheEntry>,
    sha: &str,
    tokens: usize,
    force: bool,
    min_tokens: usize,
) -> Verdict {
    // `--force` is an explicit request for the real thing.
    if force {
        return Verdict::Emit;
    }
    // Too small to be worth a recovery round-trip.
    if tokens < min_tokens {
        return Verdict::Emit;
    }
    match prior {
        // Content changed since the agent last saw it — it must see the new
        // text, and the caller re-records the new hash.
        Some(entry) if entry.sha != sha => Verdict::Emit,
        Some(entry) => Verdict::Stub(entry.clone()),
        None => Verdict::Emit,
    }
}

/// Render the marker shown in place of content the session has already seen.
///
/// Names the file, the size saved and the hash (so a human can confirm it is
/// genuinely the same bytes), and states the exact recovery command. The
/// recovery hint is not optional dressing — it is what keeps the substitution
/// safe after a context compaction.
pub fn render_stub(display_path: &str, entry: &CacheEntry) -> String {
    format!(
        "[contextcrawler] {path} unchanged since your earlier read this session.\n  \
         {tokens} tokens · sha256 {sha:.12}\n  \
         full content: contextcrawler read {path} --force\n",
        path = display_path,
        tokens = entry.tokens,
        sha = entry.sha,
    )
}

/// Current session identifier, or `None` when the host does not provide one
/// (in which case the feature is inert).
pub fn session_id() -> Option<String> {
    match crate::core::env_compat::env_var(SESSION_ENV) {
        Some(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    }
}

/// SHA-256 of the content, hex-encoded.
pub fn content_sha(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Canonical cache key for a path — absolute where possible so `./src/x.rs`
/// and `src/x.rs` are recognised as the same file.
pub fn cache_key(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

/// How a read was rendered. Two reads of the same file only count as the same
/// read when they were rendered the same way.
///
/// The first cut of #236 simply refused to cache anything other than a plain
/// whole-file read. That was too blunt: telemetry shows one file fetched via
/// `nl -ba` (which maps to `--line-numbers`) 84 times, and none of those would
/// have been caught. Folding the mode into the key means every identical
/// repeat is eligible, while a differently-rendered read is still never
/// mistaken for one the agent has already seen.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderMode {
    pub line_numbers: bool,
    pub max_lines: Option<usize>,
    pub tail_lines: Option<usize>,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub intent: Option<String>,
}

impl RenderMode {
    /// Stable discriminator appended to the path in the cache key.
    pub fn discriminator(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.line_numbers {
            parts.push("ln".to_string());
        }
        if let Some(n) = self.max_lines {
            parts.push(format!("max{n}"));
        }
        if let Some(n) = self.tail_lines {
            parts.push(format!("tail{n}"));
        }
        // #207: an explicit range is its own rendering — `--start 1 --end 20`
        // must never be satisfied by a cached `--start 1 --end 200`.
        if let Some(n) = self.start_line {
            parts.push(format!("from{n}"));
        }
        if let Some(n) = self.end_line {
            parts.push(format!("to{n}"));
        }
        if let Some(i) = &self.intent {
            // Hash rather than embed: intent strings are free text and can be
            // long enough to bloat the key.
            parts.push(format!("intent{:.16}", content_sha(i)));
        }
        if parts.is_empty() {
            "plain".to_string()
        } else {
            parts.join("+")
        }
    }
}

/// Full cache key: canonical path plus how it was rendered. The unit separator
/// cannot occur in a path, so the two halves can never collide.
pub fn cache_key_with_mode(path: &Path, mode: &RenderMode) -> String {
    format!("{}\u{1f}{}", cache_key(path), mode.discriminator())
}

/// Env override for the cache DB location (tests, and anyone who wants it
/// elsewhere). Deliberately a *separate* file from the tracking history DB —
/// this feature must never write to the user's usage database.
const CACHE_DB_ENV: &str = "CTXCRL_READ_CACHE_DB";

/// `set_var` is process-global, so any test that points the cache or the
/// session id somewhere private must hold this for its duration or it will
/// trample a parallel test. Shared with `read`'s tests, which drive `run()`
/// against the same two env vars. Same reason `core::tracking` keeps one.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard used by tests in this module and in `read`: points both the
/// cache DB and the session id at throwaway values, restoring on drop.
#[cfg(test)]
pub(crate) struct TestCacheEnv {
    _dir: tempfile::TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
    prior_db: Option<String>,
    prior_session: Option<String>,
}

#[cfg(test)]
impl TestCacheEnv {
    pub(crate) fn new(session: &str) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let prior_db = std::env::var(CACHE_DB_ENV).ok();
        let prior_session = std::env::var(SESSION_ENV).ok();
        std::env::set_var(CACHE_DB_ENV, dir.path().join("read_cache.db"));
        std::env::set_var(SESSION_ENV, session);
        Self {
            _dir: dir,
            _guard: guard,
            prior_db,
            prior_session,
        }
    }

    /// Drop the session id, modelling a host that provides none.
    pub(crate) fn clear_session(&self) {
        std::env::remove_var(SESSION_ENV);
    }
}

#[cfg(test)]
impl Drop for TestCacheEnv {
    fn drop(&mut self) {
        for (key, prior) in [
            (CACHE_DB_ENV, &self.prior_db),
            (SESSION_ENV, &self.prior_session),
        ] {
            match prior {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// Sessions older than this are pruned on write, bounding the file's growth
/// without needing a maintenance command.
const PRUNE_AFTER_DAYS: i64 = 7;

fn cache_db_path() -> Option<std::path::PathBuf> {
    if let Some(custom) = crate::core::env_compat::env_var(CACHE_DB_ENV) {
        return Some(std::path::PathBuf::from(custom));
    }
    let dir = dirs::data_local_dir()?.join(crate::core::constants::RTK_DATA_DIR);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("read_cache.db"))
}

fn open_db() -> Option<rusqlite::Connection> {
    let path = cache_db_path()?;
    let conn = rusqlite::Connection::open(path).ok()?;
    // Match the tracking DB's concurrency posture: several Bash tool calls can
    // run `read` at once. Non-fatal if the filesystem refuses WAL.
    let _ = conn.execute_batch(
        "PRAGMA busy_timeout=2000;
         PRAGMA journal_mode=WAL;",
    );
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS reads (
             session_id TEXT NOT NULL,
             path       TEXT NOT NULL,
             sha        TEXT NOT NULL,
             tokens     INTEGER NOT NULL,
             first_seen TEXT NOT NULL,
             PRIMARY KEY (session_id, path)
         );",
    )
    .ok()?;
    Some(conn)
}

/// What this session recorded for `key`, if anything.
///
/// Every failure path returns `None`, which makes the caller emit the file in
/// full — a broken cache must never withhold content.
pub fn load(session: &str, key: &str) -> Option<CacheEntry> {
    let conn = open_db()?;
    conn.query_row(
        "SELECT sha, tokens, first_seen FROM reads WHERE session_id = ?1 AND path = ?2",
        rusqlite::params![session, key],
        |row| {
            Ok(CacheEntry {
                sha: row.get(0)?,
                tokens: row.get::<_, i64>(1)? as usize,
                first_seen: row.get(2)?,
            })
        },
    )
    .ok()
}

/// Record (or refresh) what this session has been shown for `key`.
pub fn record(session: &str, key: &str, sha: &str, tokens: usize) {
    let Some(conn) = open_db() else {
        return;
    };
    let now = chrono::Utc::now();
    let _ = conn.execute(
        "INSERT INTO reads (session_id, path, sha, tokens, first_seen)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(session_id, path) DO UPDATE SET
             sha = excluded.sha,
             tokens = excluded.tokens,
             first_seen = excluded.first_seen",
        rusqlite::params![session, key, sha, tokens as i64, now.to_rfc3339()],
    );
    let cutoff = (now - chrono::Duration::days(PRUNE_AFTER_DAYS)).to_rfc3339();
    let _ = conn.execute("DELETE FROM reads WHERE first_seen < ?1", [cutoff]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sha: &str, tokens: usize) -> CacheEntry {
        CacheEntry {
            sha: sha.to_string(),
            tokens,
            first_seen: "2026-08-04T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn first_read_emits() {
        assert_eq!(decide(None, "abc", 5000, false, 500), Verdict::Emit);
    }

    #[test]
    fn unchanged_repeat_read_stubs() {
        let prior = entry("abc", 5000);
        assert_eq!(
            decide(Some(&prior), "abc", 5000, false, 500),
            Verdict::Stub(prior.clone())
        );
    }

    #[test]
    fn changed_content_always_emits() {
        let prior = entry("abc", 5000);
        assert_eq!(
            decide(Some(&prior), "different", 5000, false, 500),
            Verdict::Emit,
            "a changed file must never be stubbed — the agent has not seen it"
        );
    }

    #[test]
    fn force_always_emits() {
        let prior = entry("abc", 5000);
        assert_eq!(decide(Some(&prior), "abc", 5000, true, 500), Verdict::Emit);
    }

    #[test]
    fn below_threshold_always_emits() {
        let prior = entry("abc", 499);
        assert_eq!(
            decide(Some(&prior), "abc", 499, false, 500),
            Verdict::Emit,
            "a tiny file is not worth a recovery turn"
        );
    }

    #[test]
    fn exactly_at_threshold_stubs() {
        let prior = entry("abc", 500);
        assert_eq!(
            decide(Some(&prior), "abc", 500, false, 500),
            Verdict::Stub(prior)
        );
    }

    #[test]
    fn stub_names_the_recovery_command() {
        let rendered = render_stub("src/cli.rs", &entry("4f2a1c9b8e7d6543", 50_931));
        assert!(
            rendered.contains("contextcrawler read src/cli.rs --force"),
            "the recovery command is what makes stubbing safe: {rendered}"
        );
        assert!(rendered.contains("50931"), "must state what was withheld");
        assert!(rendered.contains("4f2a1c9b8e7d"), "must state the hash");
    }

    #[test]
    fn stub_is_far_smaller_than_the_content_it_replaces() {
        let rendered = render_stub("src/cli.rs", &entry("4f2a1c9b8e7d6543", 50_931));
        let stub_tokens = crate::core::tracking::estimate_tokens(&rendered);
        assert!(
            stub_tokens < 100,
            "stub must be trivially small, got {stub_tokens} tokens"
        );
    }

    #[test]
    fn content_sha_distinguishes_content() {
        assert_eq!(content_sha("a"), content_sha("a"));
        assert_ne!(content_sha("a"), content_sha("b"));
    }

    // --- render mode ---

    fn mode(
        line_numbers: bool,
        max_lines: Option<usize>,
        tail_lines: Option<usize>,
        intent: Option<&str>,
    ) -> RenderMode {
        RenderMode {
            line_numbers,
            max_lines,
            tail_lines,
            start_line: None,
            end_line: None,
            intent: intent.map(str::to_string),
        }
    }

    /// #207: an explicit range is its own rendering.
    fn range_mode(start: Option<usize>, end: Option<usize>) -> RenderMode {
        RenderMode {
            start_line: start,
            end_line: end,
            ..mode(false, None, None, None)
        }
    }

    #[test]
    fn line_ranges_are_distinct_render_modes() {
        let discriminators: Vec<String> = [
            range_mode(None, None),
            range_mode(Some(1), Some(20)),
            range_mode(Some(1), Some(200)),
            range_mode(Some(30), Some(60)),
            range_mode(Some(1), None),
            range_mode(None, Some(20)),
        ]
        .iter()
        .map(|m| m.discriminator())
        .collect();
        let unique: std::collections::HashSet<&String> = discriminators.iter().collect();
        assert_eq!(
            unique.len(),
            discriminators.len(),
            "a narrower range must never be satisfied by a wider cached one: {discriminators:?}"
        );
    }

    #[test]
    fn plain_read_has_a_stable_discriminator() {
        assert_eq!(mode(false, None, None, None).discriminator(), "plain");
    }

    #[test]
    fn each_render_mode_is_distinct() {
        let modes = [
            mode(false, None, None, None),
            mode(true, None, None, None),
            mode(false, Some(20), None, None),
            mode(false, Some(50), None, None),
            mode(false, None, Some(20), None),
            mode(false, None, None, Some("auth")),
            mode(false, None, None, Some("logging")),
        ];
        let discriminators: Vec<String> = modes.iter().map(|m| m.discriminator()).collect();
        let unique: std::collections::HashSet<&String> = discriminators.iter().collect();
        assert_eq!(
            unique.len(),
            discriminators.len(),
            "every distinct render mode needs its own key: {discriminators:?}"
        );
    }

    #[test]
    fn line_numbered_read_does_not_collide_with_plain_read() {
        let path = Path::new("/tmp/x.rs");
        assert_ne!(
            cache_key_with_mode(path, &mode(false, None, None, None)),
            cache_key_with_mode(path, &mode(true, None, None, None)),
            "a --line-numbers read renders different text than a plain read"
        );
    }

    #[test]
    fn identical_line_numbered_reads_share_a_key() {
        let path = Path::new("/tmp/x.rs");
        assert_eq!(
            cache_key_with_mode(path, &mode(true, None, None, None)),
            cache_key_with_mode(path, &mode(true, None, None, None)),
            "the 84x `nl -ba` case must be cacheable"
        );
    }

    // --- store round-trip ---

    use super::TestCacheEnv;

    #[test]
    fn store_round_trips_within_a_session() {
        let _db = TestCacheEnv::new("sess-roundtrip");
        assert_eq!(load("sess-a", "/x.rs"), None, "nothing recorded yet");

        record("sess-a", "/x.rs", "sha-1", 5000);
        let got = load("sess-a", "/x.rs").expect("entry recorded");
        assert_eq!(got.sha, "sha-1");
        assert_eq!(got.tokens, 5000);
    }

    #[test]
    fn store_is_scoped_per_session() {
        let _db = TestCacheEnv::new("sess-scope");
        record("sess-a", "/x.rs", "sha-1", 5000);
        assert_eq!(
            load("sess-b", "/x.rs"),
            None,
            "a different session must not inherit another's reads"
        );
    }

    #[test]
    fn store_refreshes_on_changed_content() {
        let _db = TestCacheEnv::new("sess-refresh");
        record("sess-a", "/x.rs", "sha-1", 5000);
        record("sess-a", "/x.rs", "sha-2", 6000);
        let got = load("sess-a", "/x.rs").expect("entry present");
        assert_eq!(got.sha, "sha-2", "re-record must overwrite, not duplicate");
        assert_eq!(got.tokens, 6000);
    }

    /// The Hoff's tracking DB is 95MB of real usage history. This feature must
    /// never open it, let alone write to it.
    #[test]
    fn store_never_touches_the_tracking_db() {
        let _db = TestCacheEnv::new("sess-nodb");
        let cache = cache_db_path().expect("cache path");
        assert!(
            !cache.ends_with("history.db"),
            "read cache must not be the tracking DB: {}",
            cache.display()
        );
        record("sess-a", "/x.rs", "sha-1", 5000);
        assert!(cache.exists(), "cache wrote to its own file");
    }

    /// The 7-day prune is what stops the cache growing without bound. Council
    /// (codex) called out that it was asserted only by reading the code.
    #[test]
    fn entries_older_than_the_prune_window_are_dropped() {
        let _db = TestCacheEnv::new("sess-prune");
        record("sess-old", "/stale.rs", "sha-old", 5000);
        record("sess-new", "/fresh.rs", "sha-new", 5000);

        // Backdate one entry past the prune horizon, then trigger a write.
        let conn = open_db().expect("cache db");
        let ancient =
            (chrono::Utc::now() - chrono::Duration::days(PRUNE_AFTER_DAYS + 1)).to_rfc3339();
        conn.execute(
            "UPDATE reads SET first_seen = ?1 WHERE path = '/stale.rs'",
            [ancient],
        )
        .expect("backdate");
        drop(conn);

        record("sess-trigger", "/trigger.rs", "sha-t", 5000);

        assert_eq!(
            load("sess-old", "/stale.rs"),
            None,
            "an entry past the prune window must not survive the next write"
        );
        assert!(
            load("sess-new", "/fresh.rs").is_some(),
            "a recent entry must be left alone"
        );
    }

    /// Fail-open contract: a corrupt cache DB must degrade to "emit the file",
    /// never to a panic and never to a stub. Council (codex) flagged this as
    /// asserted by code review only.
    #[test]
    fn a_corrupt_cache_db_fails_open() {
        let _db = TestCacheEnv::new("sess-corrupt");
        let path = cache_db_path().expect("cache path");
        std::fs::write(&path, b"this is not a sqlite database at all").expect("write garbage");

        assert_eq!(
            load("sess-corrupt", "/x.rs"),
            None,
            "a corrupt DB must read as 'nothing cached', so the caller emits"
        );
        // Must not panic.
        record("sess-corrupt", "/x.rs", "sha", 5000);
    }

    /// A read whose canonical path cannot be resolved (deleted between read and
    /// cache lookup) still produces a usable key rather than panicking.
    #[test]
    fn cache_key_survives_an_unresolvable_path() {
        let missing = Path::new("/definitely/does/not/exist/anywhere.rs");
        let key = cache_key(missing);
        assert!(
            key.contains("anywhere.rs"),
            "falls back to the raw path, got: {key}"
        );
    }

    #[test]
    fn missing_session_id_disables_the_feature() {
        let env = TestCacheEnv::new("sess-present");
        assert_eq!(session_id().as_deref(), Some("sess-present"));
        env.clear_session();
        assert_eq!(
            session_id(),
            None,
            "without a host session id the feature must stay inert"
        );
        std::env::set_var(SESSION_ENV, "   ");
        assert_eq!(session_id(), None, "a blank session id is not a session");
    }
}
