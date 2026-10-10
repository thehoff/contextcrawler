//! Compares two files and shows only the changed lines.

use crate::core::tracking;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Above this many lines *on both sides* the O(n·m) LCS table is skipped and
/// a raw (uncondensed) unified diff is emitted instead.
const MAX_LCS_LINES: usize = 4000;

/// Compare two files.
///
/// Returns `0` when the files are byte-identical, `1` when they differ, and
/// `2` when a path could not be read. Byte equality — not line equality — is
/// the only definition of "identical": a changed line, a CRLF→LF rewrite, or
/// any other byte difference is a difference.
pub fn run(file1: &Path, file2: &Path, verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Comparing: {} vs {}", file1.display(), file2.display());
    }

    let bytes1 = match fs::read(file1) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[contextcrawler: cannot read {}: {e}]", file1.display());
            return Ok(2);
        }
    };
    let bytes2 = match fs::read(file2) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[contextcrawler: cannot read {}: {e}]", file2.display());
            return Ok(2);
        }
    };

    let name1 = file1.display().to_string();
    let name2 = file2.display().to_string();
    let cmd_label = format!("diff {} {}", name1, name2);

    match compare(&bytes1, &bytes2, &name1, &name2) {
        Comparison::Identical => {
            println!("[ok] Files are identical");
            // The diff filter has no meaningful raw baseline (byte equality
            // short-circuits before any diffing), so record timing only —
            // never fabricate a token baseline.
            timer.track_passthrough(&cmd_label, "contextcrawler diff");
            Ok(0)
        }
        Comparison::Binary => {
            println!("Binary files {} and {} differ", name1, name2);
            timer.track_passthrough(&cmd_label, "contextcrawler diff");
            Ok(1)
        }
        Comparison::TooLarge {
            lines1,
            lines2,
            raw,
        } => {
            println!(
                "diff too large ({} and {} lines) — showing raw unified diff",
                lines1, lines2
            );
            print!("{}", raw);
            timer.track_passthrough(&cmd_label, "contextcrawler diff");
            Ok(1)
        }
        Comparison::Lines(diff) => {
            if diff.added == 0 && diff.removed == 0 && diff.modified == 0 {
                // Bytes differ but the line splitter found nothing to report.
                // Defensive only (the split is injective for valid UTF-8):
                // never claim equality when the bytes are not equal.
                println!("Files differ (byte-level difference; no line changes)");
                timer.track_passthrough(&cmd_label, "contextcrawler diff");
                return Ok(1);
            }

            let mut ctxcrl = String::new();
            ctxcrl.push_str(&format!("{} → {}\n", name1, name2));
            ctxcrl.push_str(&format!(
                "   +{} added, -{} removed, ~{} modified\n\n",
                diff.added, diff.removed, diff.modified
            ));
            ctxcrl.push_str(&format_diff_changes(&diff));

            print!("{}", ctxcrl);
            timer.track_passthrough(&cmd_label, "contextcrawler diff");
            Ok(1)
        }
    }
}

/// Run diff from stdin (piped command output, already a unified diff).
///
/// Returns `0` when the piped diff shows no changes, `1` when it does, and
/// `2` when stdin could not be read.
pub fn run_stdin(_verbose: u8) -> Result<i32> {
    use std::io::{self, Read};
    let timer = tracking::TimedExecution::start();

    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("[contextcrawler: cannot read stdin: {e}]");
        return Ok(2);
    }

    // Parse unified diff format
    let condensed = condense_unified_diff(&input);
    println!("{}", condensed);

    // The piped unified diff is the genuine raw baseline here (not a
    // concatenation of two files), so token savings can be tracked honestly.
    timer.track(
        "diff (stdin)",
        "contextcrawler diff (stdin)",
        &input,
        &condensed,
    );

    // A non-empty condensation means the diff carried changes.
    Ok(if condensed.is_empty() { 0 } else { 1 })
}

/// Result of comparing two byte buffers.
#[derive(Debug)]
enum Comparison {
    /// Bytes are equal.
    Identical,
    /// Bytes differ and at least one side is not UTF-8 text.
    Binary,
    /// Both sides are too large for the LCS table; `raw` is a unified diff.
    TooLarge {
        lines1: usize,
        lines2: usize,
        raw: String,
    },
    /// Both sides are UTF-8; this is the line-level diff.
    Lines(DiffResult),
}

/// Compare two byte buffers, deciding identity, binary-ness and diffability.
fn compare(bytes1: &[u8], bytes2: &[u8], name1: &str, name2: &str) -> Comparison {
    if bytes1 == bytes2 {
        return Comparison::Identical;
    }

    let (text1, text2) = match (std::str::from_utf8(bytes1), std::str::from_utf8(bytes2)) {
        (Ok(a), Ok(b)) => (a, b),
        // Bytes differ and cannot be decoded as text — report a binary
        // difference rather than guessing at a line diff.
        _ => return Comparison::Binary,
    };

    let lines1 = split_lines(text1);
    let lines2 = split_lines(text2);

    if lines1.len() > MAX_LCS_LINES && lines2.len() > MAX_LCS_LINES {
        let raw = raw_unified_diff(&lines1, &lines2, name1, name2);
        return Comparison::TooLarge {
            lines1: lines1.len(),
            lines2: lines2.len(),
            raw,
        };
    }

    Comparison::Lines(compute_diff(&lines1, &lines2))
}

/// Split text into lines. Unlike `str::lines`, this keeps the `\r` of a CRLF
/// terminator and the trailing empty segment, so CRLF-vs-LF and trailing
/// newline differences survive as line-level changes.
fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n').collect()
}

/// A raw, unaligned unified diff: one hunk that replaces the whole file.
/// Used only when both sides are too large for the LCS table.
fn raw_unified_diff(a: &[&str], b: &[&str], name1: &str, name2: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("--- {}\n", name1));
    out.push_str(&format!("+++ {}\n", name2));
    out.push_str(&format!("@@ -1,{} +1,{} @@\n", a.len(), b.len()));
    for line in a {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in b {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[derive(Debug)]
enum DiffChange {
    Added(usize, String),
    Removed(usize, String),
    Modified(usize, String, String),
}

#[derive(Debug)]
struct DiffResult {
    added: usize,
    removed: usize,
    modified: usize,
    changes: Vec<DiffChange>,
}

fn format_diff_changes(diff: &DiffResult) -> String {
    let mut out = String::new();
    for change in &diff.changes {
        match change {
            DiffChange::Added(ln, c) => out.push_str(&format!("+{:4} {}\n", ln, c)),
            DiffChange::Removed(ln, c) => out.push_str(&format!("-{:4} {}\n", ln, c)),
            DiffChange::Modified(ln, old, new) => {
                out.push_str(&format!("~{:4} {} → {}\n", ln, old, new))
            }
        }
    }
    out
}

/// Edit-script step produced by the LCS walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Line-level diff via a local longest-common-subsequence table.
///
/// Unlike a positional comparison, one inserted line yields exactly one
/// addition — later lines are not cascaded into "modified".
fn compute_diff(lines1: &[&str], lines2: &[&str]) -> DiffResult {
    let n = lines1.len();
    let m = lines2.len();
    let stride = m + 1;

    // dp[i * stride + j] = LCS length of lines1[i..] and lines2[j..].
    // u16 is enough: the LCS length is at most min(n, m) <= MAX_LCS_LINES.
    let mut dp = vec![0u16; (n + 1) * stride];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i * stride + j] = if lines1[i] == lines2[j] {
                dp[(i + 1) * stride + j + 1] + 1
            } else {
                dp[(i + 1) * stride + j].max(dp[i * stride + j + 1])
            };
        }
    }

    // Walk forward, emitting an edit script that mirrors the table.
    let mut ops: Vec<Op> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if lines1[i] == lines2[j] {
            ops.push(Op::Equal);
            i += 1;
            j += 1;
        } else if dp[(i + 1) * stride + j] >= dp[i * stride + j + 1] {
            ops.push(Op::Delete);
            i += 1;
        } else {
            ops.push(Op::Insert);
            j += 1;
        }
    }
    while i < n {
        ops.push(Op::Delete);
        i += 1;
    }
    while j < m {
        ops.push(Op::Insert);
        j += 1;
    }

    // Turn the script into reported changes. A run of deletes followed by a
    // run of inserts is paired positionally into `modified` entries when the
    // lines are similar; otherwise they are reported as separate lines.
    let mut changes = Vec::new();
    let mut added = 0;
    let mut removed = 0;
    let mut modified = 0;

    let mut i = 0usize;
    let mut j = 0usize;
    let mut k = 0usize;
    while k < ops.len() {
        if ops[k] == Op::Equal {
            i += 1;
            j += 1;
            k += 1;
            continue;
        }

        // Collect the maximal block of non-equal steps.
        let mut deletes = 0usize;
        let mut inserts = 0usize;
        while k < ops.len() && ops[k] != Op::Equal {
            match ops[k] {
                Op::Delete => deletes += 1,
                Op::Insert => inserts += 1,
                Op::Equal => {}
            }
            k += 1;
        }

        let paired = deletes.min(inserts);
        for p in 0..paired {
            let old = lines1[i + p];
            let new = lines2[j + p];
            if similarity(old, new) > 0.5 {
                changes.push(DiffChange::Modified(
                    i + p + 1,
                    old.to_string(),
                    new.to_string(),
                ));
                modified += 1;
            } else {
                changes.push(DiffChange::Removed(i + p + 1, old.to_string()));
                changes.push(DiffChange::Added(j + p + 1, new.to_string()));
                removed += 1;
                added += 1;
            }
        }
        for p in paired..deletes {
            changes.push(DiffChange::Removed(i + p + 1, lines1[i + p].to_string()));
            removed += 1;
        }
        for p in paired..inserts {
            changes.push(DiffChange::Added(j + p + 1, lines2[j + p].to_string()));
            added += 1;
        }

        i += deletes;
        j += inserts;
    }

    DiffResult {
        added,
        removed,
        modified,
        changes,
    }
}

fn similarity(a: &str, b: &str) -> f64 {
    let a_chars: std::collections::HashSet<char> = a.chars().collect();
    let b_chars: std::collections::HashSet<char> = b.chars().collect();

    let intersection = a_chars.intersection(&b_chars).count();
    let union = a_chars.union(&b_chars).count();

    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Emit one file's header and its change lines.
///
/// Every collected change line is printed — the condenser strips diff
/// *metadata* (headers, `@@` hunks), never content. Change lines stay at
/// column 0 so `+`/`-` keep their diff column. There is deliberately no
/// overflow marker: nothing is hidden, so claiming otherwise sends agents
/// chasing lines that are already on screen (issue #202).
fn push_file_block(
    result: &mut Vec<String>,
    file: &str,
    added: usize,
    removed: usize,
    changes: &[String],
) {
    result.push(format!("[file] {} (+{} -{})", file, added, removed));
    for c in changes {
        result.push(c.clone());
    }
}

/// Reset the accumulator for the current file, emitting its block first.
fn flush_file(
    result: &mut Vec<String>,
    current_file: &mut String,
    added: &mut usize,
    removed: &mut usize,
    changes: &mut Vec<String>,
) {
    if !current_file.is_empty() && (*added > 0 || *removed > 0) {
        push_file_block(result, current_file.as_str(), *added, *removed, changes);
    }
    *added = 0;
    *removed = 0;
    changes.clear();
}

/// Condense a unified diff into per-file change blocks.
///
/// `+++`/`---` lines are only file headers when they appear *before* the
/// first `@@` hunk of a section. Inside a hunk they are content (an added
/// line whose text starts with `++ ` becomes `+++ ...`), so they are counted
/// as changes. A plain `diff -u` boundary (`--- name` followed by `+++ name`)
/// met while a hunk is open cannot be distinguished from two content lines —
/// when the parse is unsure the original diff is returned untouched.
fn condense_unified_diff(diff: &str) -> String {
    let lines: Vec<&str> = diff.lines().collect();
    let mut result = Vec::new();
    let mut current_file = String::new();
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changes: Vec<String> = Vec::new();
    let mut in_hunk = false;
    // True when the current section was opened by a `diff --git` marker, so
    // its file boundaries are unambiguous and `--- `/`+++ ` inside a hunk can
    // safely be treated as content.
    let mut git_section = false;
    let mut pending_git = false;

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];

        if line.starts_with("diff --git") {
            flush_file(
                &mut result,
                &mut current_file,
                &mut added,
                &mut removed,
                &mut changes,
            );
            current_file.clear();
            in_hunk = false;
            pending_git = true;
            i += 1;
            continue;
        }

        if line.starts_with("@@") {
            in_hunk = true;
            i += 1;
            continue;
        }

        if !in_hunk && (line.starts_with("--- ") || line.starts_with("+++ ")) {
            if line.starts_with("+++ ") {
                flush_file(
                    &mut result,
                    &mut current_file,
                    &mut added,
                    &mut removed,
                    &mut changes,
                );
                current_file = line
                    .trim_start_matches("+++ ")
                    .trim_start_matches("b/")
                    .to_string();
                in_hunk = false;
                git_section = pending_git;
                pending_git = false;
            }
            i += 1;
            continue;
        }

        // Without a `diff --git` marker, a `--- ` line inside an open hunk
        // that is immediately followed by `+++ ` is genuinely ambiguous
        // (plain-diff file boundary vs two content lines). Do not guess —
        // hand back the original diff.
        if in_hunk
            && !git_section
            && line.starts_with("--- ")
            && lines
                .get(i + 1)
                .is_some_and(|next| next.starts_with("+++ "))
        {
            return diff.to_string();
        }

        if line.starts_with('+') {
            added += 1;
            changes.push(line.to_string());
        } else if line.starts_with('-') {
            removed += 1;
            changes.push(line.to_string());
        }

        i += 1;
    }

    flush_file(
        &mut result,
        &mut current_file,
        &mut added,
        &mut removed,
        &mut changes,
    );

    result.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- similarity ---

    #[test]
    fn test_similarity_identical() {
        assert_eq!(similarity("hello", "hello"), 1.0);
    }

    #[test]
    fn test_similarity_completely_different() {
        assert_eq!(similarity("abc", "xyz"), 0.0);
    }

    #[test]
    fn test_similarity_empty_strings() {
        // Both empty: union is 0, returns 1.0 by convention
        assert_eq!(similarity("", ""), 1.0);
    }

    #[test]
    fn test_similarity_partial_overlap() {
        let s = similarity("abcd", "abef");
        // Shared: a, b. Union: a, b, c, d, e, f = 6. Jaccard = 2/6
        assert!((s - 2.0 / 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_similarity_threshold_for_modified() {
        // "let x = 1;" vs "let x = 2;" should be > 0.5 (treated as modification)
        assert!(similarity("let x = 1;", "let x = 2;") > 0.5);
    }

    // --- compute_diff ---

    #[test]
    fn test_compute_diff_identical() {
        let a = vec!["line1", "line2", "line3"];
        let b = vec!["line1", "line2", "line3"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
        assert_eq!(result.modified, 0);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn test_compute_diff_added_lines() {
        let a = vec!["line1"];
        let b = vec!["line1", "line2", "line3"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.added, 2);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn test_compute_diff_removed_lines() {
        let a = vec!["line1", "line2", "line3"];
        let b = vec!["line1"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.removed, 2);
        assert_eq!(result.added, 0);
    }

    #[test]
    fn test_compute_diff_modified_line() {
        // Similar lines (>0.5 similarity) are classified as modified
        let a = vec!["let x = 1;"];
        let b = vec!["let x = 2;"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.modified, 1);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn test_compute_diff_completely_different_line() {
        // Dissimilar lines (<= 0.5 similarity) are added+removed, not modified
        let a = vec!["aaaa"];
        let b = vec!["zzzz"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.modified, 0);
        assert_eq!(result.added, 1);
        assert_eq!(result.removed, 1);
    }

    #[test]
    fn test_compute_diff_empty_inputs() {
        let result = compute_diff(&[], &[]);
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn test_compute_diff_single_insertion_is_one_addition() {
        // A positional diff would cascade the insertion and mark "l3" as
        // modified. LCS must report exactly one addition and nothing else.
        let a = vec!["l1", "l2", "l3"];
        let b = vec!["l1", "l2", "inserted", "l3"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.added, 1);
        assert_eq!(result.removed, 0);
        assert_eq!(result.modified, 0);
    }

    #[test]
    fn test_compute_diff_single_deletion_is_one_removal() {
        let a = vec!["l1", "l2", "l3"];
        let b = vec!["l1", "l3"];
        let result = compute_diff(&a, &b);
        assert_eq!(result.removed, 1);
        assert_eq!(result.added, 0);
        assert_eq!(result.modified, 0);
    }

    #[test]
    fn test_compute_diff_crlf_lines_are_modified_not_identical() {
        // `lines()` would strip the `\r` and report equality; the diff split
        // keeps it so the CRLF↔LF rewrite surfaces as changes.
        let a = vec!["line1\r", "line2\r", ""];
        let b = vec!["line1", "line2", ""];
        let result = compute_diff(&a, &b);
        assert!(result.added + result.removed + result.modified > 0);
    }

    // --- compare (byte identity / binary) ---

    #[test]
    fn test_compare_identical_bytes_even_non_utf8() {
        let bytes = [0xffu8, 0x00, 0xfe, 0x80];
        assert!(matches!(
            compare(&bytes, &bytes, "a", "b"),
            Comparison::Identical
        ));
    }

    #[test]
    fn test_compare_binary_differing_bytes() {
        let a = [0xffu8, 0x00];
        let b = [0xffu8, 0x01];
        assert!(matches!(compare(&a, &b, "a", "b"), Comparison::Binary));
    }

    #[test]
    fn test_compare_crlf_vs_lf_differs() {
        let a = b"line1\r\nline2\r\n";
        let b = b"line1\nline2\n";
        match compare(a, b, "a", "b") {
            Comparison::Lines(d) => {
                assert!(
                    d.added + d.removed + d.modified > 0,
                    "CRLF vs LF must not be treated as identical"
                );
            }
            other => panic!("expected line diff, got {:?}", other),
        }
    }

    #[test]
    fn test_compare_too_large_emits_raw_unified_diff() {
        let a: String = (0..(MAX_LCS_LINES + 1))
            .map(|i| format!("a{}\n", i))
            .collect();
        let b: String = (0..(MAX_LCS_LINES + 1))
            .map(|i| format!("b{}\n", i))
            .collect();
        match compare(a.as_bytes(), b.as_bytes(), "one.txt", "two.txt") {
            Comparison::TooLarge {
                lines1,
                lines2,
                raw,
            } => {
                assert!(lines1 > MAX_LCS_LINES);
                assert!(lines2 > MAX_LCS_LINES);
                assert!(raw.contains("--- one.txt"));
                assert!(raw.contains("+++ two.txt"));
                assert!(raw.contains("@@"));
            }
            other => panic!("expected TooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_split_lines_keeps_carriage_return() {
        assert_eq!(split_lines("a\r\nb\r\n"), vec!["a\r", "b\r", ""]);
    }

    // --- condense_unified_diff ---

    #[test]
    fn test_condense_unified_diff_single_file() {
        let diff = r#"diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,3 +1,4 @@
 fn main() {
+    println!("hello");
     println!("world");
 }
"#;
        let result = condense_unified_diff(diff);
        assert!(result.contains("src/main.rs"));
        assert!(result.contains("+1"));
        assert!(result.contains("println"));
    }

    #[test]
    fn test_condense_unified_diff_multiple_files() {
        let diff = r#"diff --git a/a.rs b/a.rs
--- a/a.rs
+++ b/a.rs
+added line
diff --git a/b.rs b/b.rs
--- a/b.rs
+++ b/b.rs
-removed line
"#;
        let result = condense_unified_diff(diff);
        assert!(result.contains("a.rs"));
        assert!(result.contains("b.rs"));
    }

    #[test]
    fn test_condense_unified_diff_empty() {
        let result = condense_unified_diff("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_condense_hunk_content_not_treated_as_header() {
        // `+++ ...` / `--- ...` after the `@@` header are added/removed
        // content, not file headers.
        let diff = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1,4 +1,4 @@\n context\n+new\n+++ look-ish\n--- look-ish\n";
        let result = condense_unified_diff(diff);
        assert!(result.contains("[file] src/a.rs"));
        assert!(result.contains("+++ look-ish"));
        assert!(result.contains("--- look-ish"));
    }

    #[test]
    fn test_condense_git_hunk_dash_plus_adjacent_lines_are_content() {
        // With a `diff --git` marker the boundaries are known, so adjacent
        // `--- ...` / `+++ ...` lines inside a hunk are content, not headers.
        let diff = "diff --git a/f.rs b/f.rs\n--- a/f.rs\n+++ b/f.rs\n@@ -1,2 +1,2 @@\n--- removed-dashes\n+++ added-pluses\n";
        let result = condense_unified_diff(diff);
        assert_ne!(result, diff, "git sections must be condensed, not bailed");
        assert!(result.contains("[file] f.rs"));
        assert!(result.contains("--- removed-dashes"));
        assert!(result.contains("+++ added-pluses"));
    }

    #[test]
    fn test_condense_ambiguous_plain_diff_returns_original() {
        // Plain `diff -u` output for two files: a `--- name` line inside an
        // open hunk followed by `+++ name` is indistinguishable from content,
        // so the original diff is returned untouched.
        let diff = "--- a/one\n+++ b/one\n@@ -1,2 +1,2 @@\n-a\n+b\n--- a/two\n+++ b/two\n@@ -1 +1 @@\n-c\n+d\n";
        assert_eq!(condense_unified_diff(diff), diff);
    }

    #[test]
    fn test_push_file_block_change_lines_at_column_zero() {
        let mut out = Vec::new();
        push_file_block(&mut out, "f.rs", 1, 0, &["+hello".to_string()]);
        assert_eq!(out[0], "[file] f.rs (+1 -0)");
        assert_eq!(out[1], "+hello");
    }

    // --- truncation accuracy ---

    fn make_large_unified_diff(added: usize, removed: usize) -> String {
        let mut lines = vec![
            "diff --git a/config.yaml b/config.yaml".to_string(),
            "--- a/config.yaml".to_string(),
            "+++ b/config.yaml".to_string(),
            "@@ -1,200 +1,200 @@".to_string(),
        ];
        for i in 0..removed {
            lines.push(format!("-old_value_{}", i));
        }
        for i in 0..added {
            lines.push(format!("+new_value_{}", i));
        }
        lines.join("\n")
    }

    #[test]
    fn test_condense_unified_diff_emits_every_change_line() {
        // Policy: diff content is never truncated. 200 changes in, 200 changes out.
        let diff = make_large_unified_diff(100, 100);
        let result = condense_unified_diff(&diff);
        for i in 0..100 {
            assert!(
                result.contains(&format!("+new_value_{}", i)),
                "addition {} was dropped from the condensed diff",
                i
            );
            assert!(
                result.contains(&format!("-old_value_{}", i)),
                "removal {} was dropped from the condensed diff",
                i
            );
        }
    }

    #[test]
    fn test_condense_unified_diff_no_false_overflow_marker() {
        // #202: every change line is printed, so an overflow marker always lies.
        let diff = make_large_unified_diff(100, 100);
        let result = condense_unified_diff(&diff);
        assert!(
            !result.contains("more"),
            "False overflow marker on a fully-shown diff:\n{}",
            result
        );
    }

    #[test]
    fn test_condense_unified_diff_no_false_overflow_marker_multi_file() {
        // The last-file tail path had its own copy of the marker logic (#202).
        let mut diff = make_large_unified_diff(20, 20);
        diff.push('\n');
        diff.push_str(&make_large_unified_diff(30, 30).replace("config.yaml", "second.yaml"));
        let result = condense_unified_diff(&diff);
        assert!(
            result.contains("second.yaml"),
            "second file missing:\n{}",
            result
        );
        assert!(
            !result.contains("more"),
            "False overflow marker on a fully-shown multi-file diff:\n{}",
            result
        );
    }

    #[test]
    fn test_condense_unified_diff_small_diff_has_no_marker() {
        let diff = make_large_unified_diff(4, 4);
        let result = condense_unified_diff(&diff);
        assert!(
            !result.contains("more"),
            "No overflow message expected for 8 changes, got:\n{}",
            result
        );
    }

    #[test]
    fn test_no_truncation_large_diff() {
        // Verify compute_diff returns all changes without truncation
        let mut a = Vec::new();
        let mut b = Vec::new();
        for i in 0..500 {
            a.push(format!("line_{}", i));
            if i % 3 == 0 {
                b.push(format!("CHANGED_{}", i));
            } else {
                b.push(format!("line_{}", i));
            }
        }
        let a_refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        let b_refs: Vec<&str> = b.iter().map(|s| s.as_str()).collect();
        let result = compute_diff(&a_refs, &b_refs);

        assert!(
            result.changes.len() > 100,
            "Expected 100+ changes, got {}",
            result.changes.len()
        );
        assert!(!result.changes.is_empty());
    }

    #[test]
    fn test_format_diff_shows_all_changes() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        for i in 0..100 {
            a.push(format!("old_line_{}", i));
            b.push(format!("new_line_{}", i));
        }
        let a_refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        let b_refs: Vec<&str> = b.iter().map(|s| s.as_str()).collect();
        let diff = compute_diff(&a_refs, &b_refs);
        let output = format_diff_changes(&diff);

        assert!(output.contains("old_line_0"), "should contain first change");
        assert!(output.contains("new_line_99"), "should contain last change");
    }

    #[test]
    fn test_long_lines_not_truncated() {
        let long_line = "x".repeat(500);
        let a = vec![long_line.as_str()];
        let b = vec!["short"];
        let result = compute_diff(&a, &b);
        match &result.changes[0] {
            DiffChange::Removed(_, content) | DiffChange::Added(_, content) => {
                assert_eq!(content.len(), 500, "Line was truncated!");
            }
            DiffChange::Modified(_, old, _) => {
                assert_eq!(old.len(), 500, "Line was truncated!");
            }
        }
    }
}
