//! Reads Claude Code session logs from disk and streams their command history.

use crate::hooks::constants::CLAUDE_DIR;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

/// A command extracted from a session file.
#[derive(Debug)]
pub struct ExtractedCommand {
    pub command: String,
    /// Character count of the tool output — a token-estimate proxy
    /// (callers do `len / 4`), not a byte offset. Char-based so multibyte
    /// content (CJK, emoji) doesn't inflate the estimate ~3x.
    pub output_len: Option<usize>,
    #[allow(dead_code)]
    pub session_id: String,
    /// Actual output content (first ~1000 chars for error detection)
    pub output_content: Option<String>,
    /// Whether the tool_result indicated an error
    pub is_error: bool,
    /// Chronological sequence index within the session
    #[allow(dead_code)]
    pub sequence_index: usize,
    /// UTC timestamp of the assistant tool_use entry (parsed from the
    /// top-level `timestamp` field on the JSONL line). `None` when the
    /// session entry didn't expose a parseable ISO-8601 timestamp.
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Encoded project directory slug (the JSONL file's parent directory
    /// name under `~/.claude/projects/`). Used by `reconcile::is_runtime_tracked`
    /// as a tie-break when the same command appears in multiple sessions
    /// within the timestamp window.
    pub session_project_slug: Option<String>,
}

/// Trait for session providers (Claude Code, OpenCode, etc.).
///
/// Note: Cursor Agent transcripts use a text-only format without structured
/// tool_use/tool_result blocks, so command extraction is not possible.
/// Use `ctxcrl gain` to track savings for Cursor sessions instead.
pub trait SessionProvider {
    fn discover_sessions(
        &self,
        project_filter: Option<&str>,
        since_days: Option<u64>,
    ) -> Result<Vec<PathBuf>>;
    fn extract_commands(&self, path: &Path) -> Result<Vec<ExtractedCommand>>;
}

pub struct ClaudeProvider;

impl ClaudeProvider {
    /// Get the base directory for Claude Code projects.
    fn projects_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(Self::projects_dir_for_home(&home))
    }

    fn projects_dir_for_home(home: &Path) -> PathBuf {
        home.join(CLAUDE_DIR).join("projects")
    }

    fn discover_sessions_in_projects_dir(
        projects_dir: &Path,
        project_filter: Option<&str>,
        since_days: Option<u64>,
    ) -> Result<Vec<PathBuf>> {
        if !projects_dir
            .try_exists()
            .with_context(|| format!("failed to access {}", projects_dir.display()))?
        {
            return Ok(Vec::new());
        }

        let cutoff = since_days.map(|days| {
            SystemTime::now()
                .checked_sub(Duration::from_secs(days * 86400))
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });

        let mut sessions = Vec::new();

        // List project directories
        let entries = fs::read_dir(projects_dir)
            .with_context(|| format!("failed to read {}", projects_dir.display()))?;

        // Resolve the projects dir once so we can prefix-check each entry's
        // canonical path against it (G7/#100).
        let projects_root = projects_dir.canonicalize().ok();

        for entry in entries.flatten() {
            let path = entry.path();

            // G7/#100: reject symlinked entries — a symlinked project dir
            // under ~/.claude/projects/ would redirect scanning outside the
            // tree. `path.is_dir()` follows symlinks, so check the link type
            // explicitly first.
            match fs::symlink_metadata(&path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if !meta.is_dir() {
                        continue;
                    }
                }
                Err(_) => continue,
            }

            // Defence in depth: even a non-symlink entry's resolved path must
            // stay inside the projects root.
            if let Some(root) = &projects_root {
                match path.canonicalize() {
                    Ok(resolved) if resolved.starts_with(root) => {}
                    _ => continue,
                }
            }

            // Apply project filter: substring match on directory name
            if let Some(filter) = project_filter {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !dir_name.contains(filter) {
                    continue;
                }
            }

            // Walk the project directory recursively (catches subagents/)
            for walk_entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let file_path = walk_entry.path();
                if file_path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                    continue;
                }

                // G7/#100 (Codex follow-up): reject symlinked session files.
                // The directory-level guard above blocks symlinked project
                // dirs, but an attacker who can drop a symlink inside an
                // otherwise-legitimate project dir could still redirect the
                // scanner at a file outside the tree. `symlink_metadata`
                // inspects the link itself (unlike `metadata`, which follows
                // it), so check the link type explicitly before accepting.
                match fs::symlink_metadata(file_path) {
                    Ok(meta) if meta.file_type().is_symlink() => continue,
                    Ok(_) => {}
                    Err(_) => continue,
                }

                // Apply mtime filter
                if let Some(cutoff_time) = cutoff {
                    if let Ok(meta) = fs::metadata(file_path) {
                        if let Ok(mtime) = meta.modified() {
                            if mtime < cutoff_time {
                                continue;
                            }
                        }
                    }
                }

                sessions.push(file_path.to_path_buf());
            }
        }

        Ok(sessions)
    }

    /// Encode a filesystem path to Claude Code's directory name format.
    ///
    /// Claude Code replaces `/`, `.`, `_`, `\`, and any non-ASCII character
    /// with `-` when computing the project directory slug under `~/.claude/projects/`.
    ///
    /// `/Users/foo/bar`          → `-Users-foo-bar`
    /// `/Users/first.last/bar`   → `-Users-first-last-bar`
    /// `/home/chris/2_project`   → `-home-chris-2-project`
    /// `C:\Users\foo\bar`        → `C:-Users-foo-bar`
    pub fn encode_project_path(path: &str) -> String {
        const SANITIZED_CHARS: &[char] = &['/', '.', '_', '\\'];

        path.chars()
            .map(|c| {
                if !c.is_ascii() || SANITIZED_CHARS.contains(&c) {
                    '-'
                } else {
                    c
                }
            })
            .collect()
    }
}

impl SessionProvider for ClaudeProvider {
    fn discover_sessions(
        &self,
        project_filter: Option<&str>,
        since_days: Option<u64>,
    ) -> Result<Vec<PathBuf>> {
        let projects_dir = Self::projects_dir()?;
        Self::discover_sessions_in_projects_dir(&projects_dir, project_filter, since_days)
    }

    fn extract_commands(&self, path: &Path) -> Result<Vec<ExtractedCommand>> {
        let file =
            fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        let reader = BufReader::new(file);

        let session_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // The session JSONL lives at
        //   ~/.claude/projects/<encoded-project-slug>/<session_id>.jsonl
        // (optionally one extra level for subagents). Walk up until we find
        // a parent whose name starts with `-` or `C:-` — the encoded slug
        // format used by `encode_project_path`. Falls back to the immediate
        // parent dir name if no encoded ancestor is found.
        let session_project_slug = path
            .ancestors()
            .skip(1)
            .find_map(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .filter(|name| name.starts_with('-') || name.starts_with("C:-"))
                    .map(|name| name.to_string())
            })
            .or_else(|| {
                path.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
            });

        // First pass: collect all tool_use Bash commands with their IDs and sequence
        // Second pass (same loop): collect tool_result output lengths, content, and error status
        // tool_use payload: (id, command, sequence, timestamp)
        let mut pending_tool_uses: Vec<(
            String,
            String,
            usize,
            Option<chrono::DateTime<chrono::Utc>>,
        )> = Vec::new();
        let mut tool_results: HashMap<String, (usize, String, bool)> = HashMap::new(); // (len, content, is_error)
        let mut commands = Vec::new();
        let mut sequence_counter = 0;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            // Pre-filter: skip lines that can't contain Bash tool_use or tool_result
            if !line.contains("\"Bash\"") && !line.contains("\"tool_result\"") {
                continue;
            }

            let entry: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let entry_type = entry.get("type").and_then(|t| t.as_str()).unwrap_or("");

            // Top-level timestamp on every JSONL entry (Claude Code injects
            // an ISO-8601 `timestamp` field) — used later to reconcile
            // against the runtime tracking DB.
            let entry_ts = entry
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                });

            match entry_type {
                "assistant" => {
                    // Look for tool_use Bash blocks in message.content
                    if let Some(content) =
                        entry.pointer("/message/content").and_then(|c| c.as_array())
                    {
                        for block in content {
                            if block.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                                && block.get("name").and_then(|n| n.as_str()) == Some("Bash")
                            {
                                if let (Some(id), Some(cmd)) = (
                                    block.get("id").and_then(|i| i.as_str()),
                                    block.pointer("/input/command").and_then(|c| c.as_str()),
                                ) {
                                    pending_tool_uses.push((
                                        id.to_string(),
                                        cmd.to_string(),
                                        sequence_counter,
                                        entry_ts,
                                    ));
                                    sequence_counter += 1;
                                }
                            }
                        }
                    }
                }
                "user" => {
                    // Look for tool_result blocks
                    if let Some(content) =
                        entry.pointer("/message/content").and_then(|c| c.as_array())
                    {
                        for block in content {
                            if block.get("type").and_then(|t| t.as_str()) == Some("tool_result") {
                                if let Some(id) = block.get("tool_use_id").and_then(|i| i.as_str())
                                {
                                    // Get content, length, and error status
                                    let content =
                                        block.get("content").and_then(|c| c.as_str()).unwrap_or("");

                                    // Char count, not byte length: this feeds
                                    // a `/4` token estimate, and byte length
                                    // overstates multibyte content ~3x.
                                    let output_len = content.chars().count();
                                    let is_error = block
                                        .get("is_error")
                                        .and_then(|e| e.as_bool())
                                        .unwrap_or(false);

                                    // Store first ~1000 chars of content for error detection
                                    let content_preview: String =
                                        content.chars().take(1000).collect();

                                    tool_results.insert(
                                        id.to_string(),
                                        (output_len, content_preview, is_error),
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Match tool_uses with their results
        for (tool_id, command, sequence_index, timestamp) in pending_tool_uses {
            let (output_len, output_content, is_error) = tool_results
                .get(&tool_id)
                .map(|(len, content, err)| (Some(*len), Some(content.clone()), *err))
                .unwrap_or((None, None, false));

            commands.push(ExtractedCommand {
                command,
                output_len,
                session_id: session_id.clone(),
                output_content,
                is_error,
                sequence_index,
                timestamp,
                session_project_slug: session_project_slug.clone(),
            });
        }

        Ok(commands)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_jsonl(lines: &[&str]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for line in lines {
            writeln!(f, "{}", line).unwrap();
        }
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_extract_assistant_bash() {
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_abc","name":"Bash","input":{"command":"git status"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_abc","content":"On branch master\nnothing to commit"}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "git status");
        assert!(cmds[0].output_len.is_some());
        assert_eq!(
            cmds[0].output_len.unwrap(),
            "On branch master\nnothing to commit".chars().count()
        );
    }

    #[test]
    fn test_output_len_is_char_count_not_byte_len() {
        // Multibyte content: byte length overstates char count ~3x for CJK.
        let multibyte = "日本語のテスト出力";
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_mb","name":"Bash","input":{"command":"echo hi"}}]}}"#,
            &format!(
                r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_mb","content":"{}"}}]}}}}"#,
                multibyte
            ),
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 1);
        // Char count, not byte length.
        assert_eq!(cmds[0].output_len.unwrap(), multibyte.chars().count());
        assert!(
            multibyte.len() > multibyte.chars().count(),
            "fixture must be genuinely multibyte"
        );
    }

    #[test]
    fn test_extract_non_bash_ignored() {
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_abc","name":"Read","input":{"file_path":"/tmp/foo"}}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 0);
    }

    #[test]
    fn test_extract_non_message_ignored() {
        let jsonl =
            make_jsonl(&[r#"{"type":"file-history-snapshot","messageId":"abc","snapshot":{}}"#]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 0);
    }

    #[test]
    fn test_extract_multiple_tools() {
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"git status"}},{"type":"tool_use","id":"toolu_2","name":"Bash","input":{"command":"git diff"}}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "git status");
        assert_eq!(cmds[1].command, "git diff");
    }

    #[test]
    fn test_extract_malformed_line() {
        let jsonl = make_jsonl(&[
            "this is not json at all",
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_ok","name":"Bash","input":{"command":"ls"}}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls");
    }

    #[test]
    fn test_encode_project_path() {
        assert_eq!(
            ClaudeProvider::encode_project_path("/Users/foo/bar"),
            "-Users-foo-bar"
        );
    }

    #[test]
    fn test_encode_project_path_trailing_slash() {
        assert_eq!(
            ClaudeProvider::encode_project_path("/Users/foo/bar/"),
            "-Users-foo-bar-"
        );
    }

    #[test]
    fn test_encode_project_path_dot_in_username() {
        // Claude Code replaces both '/' and '.' with '-'.
        // A cwd like /Users/first.last must produce the same slug as
        // Claude's projects directory (-Users-first-last), otherwise
        // `ctxcrl discover` finds zero sessions for that project.
        assert_eq!(
            ClaudeProvider::encode_project_path("/Users/first.last/my-project"),
            "-Users-first-last-my-project"
        );
    }

    #[test]
    fn test_encode_project_path_multiple_dots() {
        assert_eq!(
            ClaudeProvider::encode_project_path("/Users/a.b.c/proj"),
            "-Users-a-b-c-proj"
        );
    }

    #[test]
    fn test_encode_project_path_underscore() {
        // Claude Code also replaces '_' with '-' (https://github.com/anthropics/claude-code/issues/24067)
        assert_eq!(
            ClaudeProvider::encode_project_path("/home/chris/2_project-files/proj"),
            "-home-chris-2-project-files-proj"
        );
    }

    #[test]
    fn test_encode_project_path_non_ascii() {
        // Non-ASCII characters are each replaced with '-' (https://github.com/anthropics/claude-code/issues/40946)
        // '/home/user/' + '外' + '主' + '/app' -> '-home-user' + '-' + '-' + '-' + '-' + 'app'
        assert_eq!(
            ClaudeProvider::encode_project_path("/home/user/\u{5916}\u{4e3b}/app"),
            "-home-user----app"
        );
    }

    #[test]
    fn test_encode_project_path_windows() {
        // Windows backslashes are also replaced with '-'
        assert_eq!(
            ClaudeProvider::encode_project_path(r"C:\Users\foo\bar"),
            "C:-Users-foo-bar"
        );
    }

    #[test]
    fn test_match_project_filter() {
        let encoded = ClaudeProvider::encode_project_path("/Users/foo/Sites/rtk");
        assert!(encoded.contains("rtk"));
        assert!(encoded.contains("Sites"));
    }

    #[test]
    fn test_discover_sessions_missing_projects_dir_returns_empty() {
        let temp_home = tempfile::tempdir().unwrap();
        let missing_projects_dir = temp_home.path().join(CLAUDE_DIR).join("projects");

        let sessions = ClaudeProvider::discover_sessions_in_projects_dir(
            &missing_projects_dir,
            None,
            Some(30),
        )
        .unwrap();

        assert!(sessions.is_empty());
    }

    #[test]
    fn test_discover_sessions_applies_project_filter() {
        let projects_dir = tempfile::tempdir().unwrap();
        let matching_project = projects_dir.path().join("-Users-test-rtk");
        let other_project = projects_dir.path().join("-Users-test-other");
        std::fs::create_dir_all(&matching_project).unwrap();
        std::fs::create_dir_all(&other_project).unwrap();
        std::fs::write(matching_project.join("matching.jsonl"), "").unwrap();
        std::fs::write(other_project.join("other.jsonl"), "").unwrap();

        let sessions = ClaudeProvider::discover_sessions_in_projects_dir(
            projects_dir.path(),
            Some("rtk"),
            None,
        )
        .unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].file_name().and_then(|name| name.to_str()),
            Some("matching.jsonl")
        );
    }

    #[test]
    fn test_discover_sessions_existing_non_directory_returns_error() {
        let projects_file = tempfile::NamedTempFile::new().unwrap();

        let err =
            ClaudeProvider::discover_sessions_in_projects_dir(projects_file.path(), None, None)
                .unwrap_err();

        assert!(err.to_string().contains("failed to read"));
    }

    // G7/#100: a symlinked project dir must be rejected so scanning cannot be
    // redirected outside the ~/.claude/projects/ tree.
    #[test]
    #[cfg(unix)]
    fn test_discover_sessions_rejects_symlinked_project_dir() {
        let projects_dir = tempfile::tempdir().unwrap();
        // A real project dir inside the tree — should be scanned.
        let real_project = projects_dir.path().join("-Users-test-real");
        std::fs::create_dir_all(&real_project).unwrap();
        std::fs::write(real_project.join("real.jsonl"), "").unwrap();

        // An out-of-tree dir reached via a symlink placed inside the tree.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.jsonl"), "").unwrap();
        let link = projects_dir.path().join("-Users-test-evil");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let sessions = ClaudeProvider::discover_sessions_in_projects_dir(
            projects_dir.path(),
            None,
            None,
        )
        .unwrap();

        // Only the real project's file is found; the symlinked dir is skipped.
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].file_name().and_then(|n| n.to_str()),
            Some("real.jsonl")
        );
    }

    // G7/#100 (Codex follow-up): a symlinked `.jsonl` placed inside an
    // accepted project dir must be skipped so scanning cannot be redirected
    // outside the tree, while a regular `.jsonl` is still collected.
    #[test]
    #[cfg(unix)]
    fn test_discover_sessions_rejects_symlinked_session_file() {
        let projects_dir = tempfile::tempdir().unwrap();
        let project = projects_dir.path().join("-Users-test-real");
        std::fs::create_dir_all(&project).unwrap();
        // A regular session file inside the project — should be collected.
        std::fs::write(project.join("real.jsonl"), "").unwrap();

        // An out-of-tree file reached via a symlink inside the project dir.
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.jsonl");
        std::fs::write(&secret, "").unwrap();
        let link = project.join("evil.jsonl");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let sessions = ClaudeProvider::discover_sessions_in_projects_dir(
            projects_dir.path(),
            None,
            None,
        )
        .unwrap();

        // Only the regular file is found; the symlinked file is skipped.
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].file_name().and_then(|n| n.to_str()),
            Some("real.jsonl")
        );
    }

    #[test]
    fn test_extract_output_content() {
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_abc","name":"Bash","input":{"command":"git commit --ammend"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_abc","content":"error: unexpected argument '--ammend'","is_error":true}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "git commit --ammend");
        assert!(cmds[0].is_error);
        assert!(cmds[0].output_content.is_some());
        assert_eq!(
            cmds[0].output_content.as_ref().unwrap(),
            "error: unexpected argument '--ammend'"
        );
    }

    #[test]
    fn test_extract_is_error_flag() {
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}},{"type":"tool_use","id":"toolu_2","name":"Bash","input":{"command":"invalid_cmd"}}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"file1.txt","is_error":false},{"type":"tool_result","tool_use_id":"toolu_2","content":"command not found","is_error":true}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 2);
        assert!(!cmds[0].is_error);
        assert!(cmds[1].is_error);
    }

    #[test]
    fn test_extract_sequence_ordering() {
        let jsonl = make_jsonl(&[
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"first"}},{"type":"tool_use","id":"toolu_2","name":"Bash","input":{"command":"second"}},{"type":"tool_use","id":"toolu_3","name":"Bash","input":{"command":"third"}}]}}"#,
        ]);

        let provider = ClaudeProvider;
        let cmds = provider.extract_commands(jsonl.path()).unwrap();
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].sequence_index, 0);
        assert_eq!(cmds[1].sequence_index, 1);
        assert_eq!(cmds[2].sequence_index, 2);
        assert_eq!(cmds[0].command, "first");
        assert_eq!(cmds[1].command, "second");
        assert_eq!(cmds[2].command, "third");
    }
}
