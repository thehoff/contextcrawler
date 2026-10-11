//! Compact a native tool result that never went through the bash rewrite.
//!
//! OMP's `read`, `grep`, `glob`, and `find` tools are not shell commands.
//! Replacing them would drop image/sqlite/archive reads, hashline anchors,
//! and the semantic `find` digest (#247). The extension therefore leaves the
//! tool in place and pipes the text it is about to show the model into
//! `contextcrawler observe`. This command filters that text. It does not
//! re-run the tool.
//!
//! `read` and `find` pass through. Read is the file the model asked to see,
//! and find is already a ranked digest. `grep` and `glob` are compacted only
//! when the text has OMP's own shape. `bash`/`shell` reuse the pipe
//! auto-detector for output the rewrite did not claim, except the grep
//! detector: a timestamp (`10:15:11 INFO`) matches `file:line:content` and
//! must not be rewritten into a fake file list.

use anyhow::Result;
use std::io::Read;

use crate::cmds::system::pipe_cmd;
use crate::core::stream::RAW_CAP;
use crate::core::tracking::TimedExecution;
use crate::core::utils::truncate;

const MATCHES_KEPT: usize = 5;
const CONTENT_CHARS: usize = 200;
const FILES_KEPT: usize = 5;
const DIRS_KEPT: usize = 20;

/// Compact `input` for `tool`. `is_error` prints the text unchanged: a failed
/// tool result is the thing the model needs to see.
pub fn compact(tool: &str, input: &str, is_error: bool) -> String {
    if is_error || input.is_empty() {
        return input.to_string();
    }
    let out = match tool.trim().to_ascii_lowercase().as_str() {
        "grep" => compact_grep(input),
        "glob" => compact_glob(input),
        "bash" | "shell" => compact_captured(input),
        _ => input.to_string(),
    };
    prefer_shorter(input, out)
}

pub fn run(tool: &str, command: &str, is_error: bool) -> Result<()> {
    let timer = TimedExecution::start();
    let input = read_stdin()?;
    let output = compact(tool, &input, is_error);
    if output.len() < input.len() {
        timer.track(
            &ledger_label(tool, command),
            &format!("contextcrawler observe --tool {}", tool.trim()),
            &input,
            &output,
        );
    }
    print!("{output}");
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .take((RAW_CAP + 1) as u64)
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("Failed to read stdin: {e}"))?;
    if buf.len() > RAW_CAP {
        anyhow::bail!("stdin exceeds {RAW_CAP} byte limit");
    }
    Ok(buf)
}

fn prefer_shorter(input: &str, out: String) -> String {
    if out.is_empty() || out.len() >= input.len() {
        input.to_string()
    } else {
        out
    }
}

fn ledger_label(tool: &str, command: &str) -> String {
    let tool = tool.trim();
    let cmd: String = command.split_whitespace().collect::<Vec<_>>().join(" ");
    let cmd: String = cmd.chars().take(160).collect();
    if cmd.is_empty() {
        tool.to_string()
    } else {
        format!("{tool} {cmd}")
    }
}

/// Pipe auto-detect. Used for bash output the rewrite missed, and for a
/// glob result that is still a flat path list.
fn compact_captured(input: &str) -> String {
    // sqlite3 `.schema` / `PRAGMA table_info` output lists column identifiers
    // inside a `CREATE TABLE` body or a `cid|name|type|...` header. The pipe
    // auto-detector can misread it as grep-shaped and drop the names (#246).
    // Return it unchanged.
    if pipe_cmd::is_sqlite_schema_text(input) {
        return input.to_string();
    }
    // `10:15:11 INFO` matches the pipe grep detector (`file:line:content`)
    // and comes back as a fake file list. A real grep line has a path
    // (`src/lib.rs:12:`) in that field. Leave the timestamp form alone.
    if bare_colon_triples(input) {
        return input.to_string();
    }
    let filter = pipe_cmd::auto_detect_filter(input);
    pipe_cmd::apply_filter(filter, input)
}

fn bare_colon_triples(input: &str) -> bool {
    let mut saw = false;
    for line in input.lines().filter(|line| !line.trim().is_empty()).take(5) {
        let mut parts = line.splitn(3, ':');
        let Some(file) = parts.next() else {
            continue;
        };
        let Some(mid) = parts.next() else {
            continue;
        };
        if parts.next().is_none() || mid.parse::<usize>().is_err() {
            continue;
        }
        saw = true;
        if file.contains('/') || file.contains('.') {
            return false;
        }
    }
    saw
}

fn compact_grep(input: &str) -> String {
    if let Some(out) = compact_omp_grep(input) {
        return out;
    }
    // An OMP result under the collapse cap is still OMP-shaped. Falling
    // through to the classic filter reads `*1:11:00` as file `*1`, line 11.
    if input
        .lines()
        .any(|line| parse_star_match(line).is_some() || is_grep_header(line))
    {
        return input.to_string();
    }
    compact_captured(input)
}

struct Hit {
    line_no: u32,
    rendered: String,
}

struct Group {
    header: Option<String>,
    hits: Vec<Hit>,
    tail: Vec<String>,
}

fn compact_omp_grep(input: &str) -> Option<String> {
    let mut groups: Vec<Group> = Vec::new();
    let mut current = Group {
        header: None,
        hits: Vec::new(),
        tail: Vec::new(),
    };
    let mut matches = 0usize;
    let mut contexts = 0usize;
    let mut headers = 0usize;
    let mut nonempty = 0usize;
    let mut truncated = false;

    for line in input.lines() {
        if line.is_empty() {
            continue;
        }
        nonempty += 1;
        if is_grep_header(line) {
            if current.header.is_some() || !current.hits.is_empty() || !current.tail.is_empty() {
                groups.push(current);
                current = Group {
                    header: None,
                    hits: Vec::new(),
                    tail: Vec::new(),
                };
            }
            current.header = Some(line.to_string());
            headers += 1;
        } else if let Some((line_no, content)) = parse_star_match(line) {
            let rendered_content = truncate(content, CONTENT_CHARS);
            if rendered_content != content {
                truncated = true;
            }
            current.hits.push(Hit {
                line_no,
                rendered: format!("*{line_no}:{rendered_content}"),
            });
            matches += 1;
        } else if is_context_line(line) {
            contexts += 1;
        } else {
            current.tail.push(line.to_string());
        }
    }
    if current.header.is_some() || !current.hits.is_empty() || !current.tail.is_empty() {
        groups.push(current);
    }

    // Not this shape. A prose file that happens to contain one `*12:` line
    // must not be rewritten.
    let structural = headers + matches + contexts;
    if matches == 0 || structural * 2 < nonempty {
        return None;
    }
    let collapsed = groups.iter().any(|g| g.hits.len() > MATCHES_KEPT);
    if contexts == 0 && !collapsed && !truncated {
        return None;
    }

    let mut out = String::new();
    for group in &groups {
        if let Some(header) = &group.header {
            out.push_str(header);
            out.push('\n');
        }
        for hit in group.hits.iter().take(MATCHES_KEPT) {
            out.push_str(&hit.rendered);
            out.push('\n');
        }
        if group.hits.len() > MATCHES_KEPT {
            let rest: Vec<String> = group.hits[MATCHES_KEPT..]
                .iter()
                .map(|h| h.line_no.to_string())
                .collect();
            out.push_str(&format!(
                "  +{} more at L: {}\n",
                group.hits.len() - MATCHES_KEPT,
                rest.join(",")
            ));
        }
        for line in &group.tail {
            out.push_str(line);
            out.push('\n');
        }
    }
    if input.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

fn is_grep_header(line: &str) -> bool {
    if let Some(rest) = line.strip_prefix('#') {
        let depth_rest = rest.trim_start_matches('#');
        let label = depth_rest.trim_start();
        return !label.is_empty() && depth_rest.starts_with(|c: char| c.is_whitespace());
    }
    let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    inner
        .rsplit_once('#')
        .is_some_and(|(_, tag)| tag.len() == 4 && tag.chars().all(|c| c.is_ascii_hexdigit()))
}

fn parse_star_match(line: &str) -> Option<(u32, &str)> {
    let rest = line.strip_prefix('*')?.trim_start();
    split_numbered(rest)
}

fn is_context_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.len() == line.len() {
        return false;
    }
    split_numbered(trimmed).is_some()
}

fn split_numbered(s: &str) -> Option<(u32, &str)> {
    let digits = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits >= s.len() {
        return None;
    }
    let sep = s.as_bytes()[digits];
    if sep != b':' && sep != b'|' {
        return None;
    }
    let line_no: u32 = s[..digits].parse().ok()?;
    Some((line_no, &s[digits + 1..]))
}

fn compact_glob(input: &str) -> String {
    if input.lines().any(is_glob_dir_header) {
        return compact_glob_tree(input).unwrap_or_else(|| input.to_string());
    }
    compact_captured(input)
}

fn compact_glob_tree(input: &str) -> Option<String> {
    struct Dir {
        header: String,
        files: Vec<String>,
    }
    let mut dirs: Vec<Dir> = Vec::new();
    let mut notices: Vec<String> = Vec::new();
    let mut loose: Vec<String> = Vec::new();

    for line in input.lines() {
        if line.is_empty() {
            continue;
        }
        if is_glob_dir_header(line) {
            dirs.push(Dir {
                header: line.to_string(),
                files: Vec::new(),
            });
            continue;
        }
        if is_glob_notice(line) {
            notices.push(line.to_string());
            continue;
        }
        if looks_like_prose(line) {
            return None;
        }
        if let Some(dir) = dirs.last_mut() {
            dir.files.push(line.trim().to_string());
        } else {
            loose.push(line.trim().to_string());
        }
    }

    let over_files = dirs.iter().any(|d| d.files.len() > FILES_KEPT) || loose.len() > FILES_KEPT;
    let over_dirs = dirs.len() > DIRS_KEPT;
    if !over_files && !over_dirs {
        return None;
    }

    let mut out = String::new();
    emit_names(&mut out, None, &loose);
    for dir in dirs.iter().take(DIRS_KEPT) {
        emit_names(&mut out, Some(&dir.header), &dir.files);
    }
    if dirs.len() > DIRS_KEPT {
        out.push_str(&format!("\n+{} more dirs\n", dirs.len() - DIRS_KEPT));
    }
    for notice in &notices {
        out.push_str(notice);
        out.push('\n');
    }
    if input.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

fn emit_names(out: &mut String, header: Option<&str>, names: &[String]) {
    if names.is_empty() {
        if let Some(header) = header {
            out.push_str(header);
            out.push('\n');
        }
        return;
    }
    if let Some(header) = header {
        out.push_str(header);
        out.push('\n');
    }
    for name in names.iter().take(FILES_KEPT) {
        out.push_str(name);
        out.push('\n');
    }
    if names.len() > FILES_KEPT {
        out.push_str(&format!("  +{}\n", names.len() - FILES_KEPT));
    }
}

fn is_glob_dir_header(line: &str) -> bool {
    let hashes = line.bytes().take_while(|b| *b == b'#').count();
    if hashes == 0 || hashes > 8 {
        return false;
    }
    let rest = line[hashes..].trim();
    !rest.is_empty() && rest.ends_with('/') && !rest.contains('\t')
}

fn is_glob_notice(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('+')
        || t.starts_with("No files found")
        || t.starts_with("Skipped missing")
        || t.starts_with("Requested limit")
        || t.starts_with("Incomplete")
        || t.contains("NOT proof of absence")
}

fn looks_like_prose(line: &str) -> bool {
    let t = line.trim();
    t.contains(". ") || t.split_whitespace().count() > 8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn omp_grep() -> String {
        let mut s = String::from("# src/\n## hooks/\n### hook_cmd.rs#C143\n");
        for n in 1..=12 {
            s.push_str(&format!("*{n}:    pub fn item_{n}() {{}}\n"));
            s.push_str(&format!(" {n}:    // context for {n}\n"));
        }
        s.push_str("Use skip=20 for the next page\n");
        s
    }

    #[test]
    fn omp_grep_keeps_headers_and_collapses_matches() {
        let input = omp_grep();
        let out = compact("grep", &input, false);
        assert!(out.len() < input.len(), "out={out}");
        assert!(out.contains("### hook_cmd.rs#C143"), "{out}");
        assert!(out.contains("*1:"), "{out}");
        assert!(out.contains("*5:"), "{out}");
        assert!(!out.contains("*6:"), "sixth match should collapse: {out}");
        assert!(out.contains("+7 more at L: 6,7,8,9,10,11,12"), "{out}");
        assert!(
            !out.contains("context for"),
            "context lines must drop: {out}"
        );
        assert!(out.contains("Use skip=20 for the next page"), "{out}");
    }

    #[test]
    fn single_file_grep_without_headers_still_compacts() {
        let mut input = String::new();
        for n in 1..=8 {
            input.push_str(&format!("*{n}:match {n}\n"));
            input.push_str(&format!(" {n}:ctx {n}\n"));
        }
        let out = compact("grep", &input, false);
        assert!(out.contains("+3 more at L: 6,7,8"), "{out}");
        assert!(!out.contains("ctx "), "{out}");
    }

    #[test]
    fn prose_is_not_grep() {
        let input = "# Notes\n\nThis is a paragraph about *12: something in prose.\n".repeat(40);
        let out = compact("grep", &input, false);
        assert_eq!(out, input);
    }

    #[test]
    fn bash_timestamps_are_not_grep() {
        let input: String = (0..40)
            .map(|n| format!("10:15:{n:02} INFO tick {n}\n"))
            .collect();
        assert_eq!(compact("bash", &input, false), input);
    }

    #[test]
    fn omp_grep_under_the_cap_stays_omp() {
        let mut input = String::from("# src/\n[src/login.ts#1F2A]\n");
        for file in 0..30 {
            input.push_str(&format!("# f{file}/\n"));
            for n in 1..=3 {
                input.push_str(&format!("*{n}:11:00 tick\n"));
            }
        }
        assert_eq!(compact("grep", &input, false), input);
    }

    #[test]
    fn bash_unified_diff_compacts_and_keeps_the_commit_header() {
        let input = "\
commit abc1234\n\
Author: Ada <ada@example.com>\n\
\n\
    keep this message\n\
\n\
diff --git a/src/a.rs b/src/a.rs\n\
--- a/src/a.rs\n\
+++ b/src/a.rs\n\
@@ -1,6 +1,6 @@\n\
 LEAD_CTX\n\
-old line\n\
+new line\n\
 trail\n\
";
        let out = compact("bash", input, false);
        assert!(out.len() < input.len(), "{out}");
        assert!(out.contains("keep this message"), "{out}");
        assert!(out.contains("+new line"), "{out}");
        assert!(!out.contains("LEAD_CTX"), "{out}");
    }

    #[test]
    fn bash_path_grep_still_compacts() {
        let mut input = String::new();
        for n in 1..=30 {
            input.push_str(&format!("src/lib.rs:{n}:    handler.dispatch(request);\n"));
        }
        let out = compact("bash", &input, false);
        assert!(out.len() < input.len(), "{out}");
        assert!(out.contains("matches"), "{out}");
    }

    #[test]
    fn classic_grep_lines_still_compact() {
        let mut input = String::new();
        for n in 1..=30 {
            input.push_str(&format!("src/lib.rs:{n}:    handler.dispatch(request);\n"));
        }
        let out = compact("grep", &input, false);
        assert!(out.len() < input.len(), "{out}");
        assert!(out.contains("matches"), "{out}");
    }

    #[test]
    fn glob_tree_collapses_a_fat_directory() {
        let mut input = String::from("# src/hooks/\n");
        for n in 0..12 {
            input.push_str(&format!("file_{n}.rs\n"));
        }
        input.push_str("Skipped missing paths: gone/\n");
        let out = compact("glob", &input, false);
        assert!(out.contains("# src/hooks/"), "{out}");
        assert!(out.contains("file_0.rs"), "{out}");
        assert!(out.contains("file_4.rs"), "{out}");
        assert!(!out.contains("file_5.rs"), "{out}");
        assert!(out.contains("  +7\n"), "{out}");
        assert!(out.contains("Skipped missing paths: gone/"), "{out}");
    }

    #[test]
    fn small_glob_tree_is_unchanged() {
        let input = "# src/\nlib.rs\nmain.rs\n";
        assert_eq!(compact("glob", input, false), input);
    }

    #[test]
    fn glob_prose_is_unchanged() {
        let input =
            "# src/\nThis is a sentence about the directory listing and should stay.\n".repeat(30);
        assert_eq!(compact("glob", &input, false), input);
    }

    #[test]
    fn flat_path_list_uses_the_find_filter() {
        let mut input = String::new();
        for n in 0..40 {
            input.push_str(&format!("src/cmds/system/file_{n}.rs\n"));
        }
        let out = compact("glob", &input, false);
        assert!(out.len() < input.len(), "{out}");
        assert!(out.contains("files in"), "{out}");
    }

    #[test]
    fn bash_cargo_test_output_compacts() {
        // Summary must sit in the first 1 KiB so the pipe auto-detector claims it.
        // The noise lines are not part of the summary, so the cargo filter drops them.
        let input = format!(
            "test result: ok. 40 passed; 0 failed; 0 ignored; finished in 1s\n{}",
            "    some noisy test line that is not a failure\n".repeat(80)
        );
        let out = compact("bash", &input, false);
        assert!(out.len() < input.len(), "out={out}");
    }

    #[test]
    fn read_and_find_pass_through() {
        let input = "# src/\n".to_string() + &"*1:keep me\n 2:context\n".repeat(40);
        assert_eq!(compact("read", &input, false), input);
        assert_eq!(compact("find", &input, false), input);
    }

    #[test]
    fn errors_pass_through() {
        let input = omp_grep();
        assert_eq!(compact("grep", &input, true), input);
    }

    #[test]
    fn second_pass_does_not_shrink_again() {
        let once = compact("grep", &omp_grep(), false);
        let twice = compact("grep", &once, false);
        assert_eq!(twice, once);
    }

    const SQLITE_SCHEMA_FIXTURE: &str = "CREATE TABLE commands (\n  \
        original_cmd TEXT NOT NULL,\n  \
        saved_tokens INTEGER NOT NULL,\n  \
        savings_pct REAL NOT NULL\n);\n";

    #[test]
    fn sqlite_schema_dump_survives_bash_compaction() {
        let out = compact("bash", SQLITE_SCHEMA_FIXTURE, false);
        assert_eq!(out, SQLITE_SCHEMA_FIXTURE);
        assert!(out.contains("original_cmd"), "{out}");
        assert!(out.contains("saved_tokens"), "{out}");
    }

    #[test]
    fn sqlite_pragma_output_survives_bash_compaction() {
        let input = "PRAGMA table_info(commands);\n\
                     cid|name|type|notnull|dflt_value|pk\n\
                     0|original_cmd|TEXT|1||0\n\
                     1|saved_tokens|INTEGER|1||0\n";
        let out = compact("bash", input, false);
        assert_eq!(out, input);
        assert!(out.contains("original_cmd"), "{out}");
        assert!(out.contains("saved_tokens"), "{out}");
    }
}
