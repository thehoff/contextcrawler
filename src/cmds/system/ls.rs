//! Filters directory listings into a compact tree format.

use super::constants::NOISE_DIRS;
use crate::core::runner::{self, RunOptions};
use crate::core::utils::resolved_command;
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use std::io::IsTerminal;

lazy_static! {
    /// Matches the date+time portion in `ls -la` output, which serves as a
    /// stable anchor regardless of owner/group column width.
    /// E.g.: " Mar 31 16:18 " or " Dec 25  2024 "
    static ref LS_DATE_RE: Regex = Regex::new(
        r"\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+(?:\d{4}|\d{2}:\d{2})\s+"
    )
    .unwrap();
}

/// Parse user `ls` arguments into `(flags to forward, path operands, show_all,
/// show_long, preserve_order)`.
///
/// The proxy always runs `ls -la` internally, so `-l`/`-a` are dropped from
/// what we forward; `-h` is dropped too because it would corrupt the size
/// column we parse. Flags that must still reach the real `ls` (e.g. `-I`,
/// `-t`, `--sort`) are preserved.
///
/// `-A`/`--almost-all` reveal hidden entries just like `-a` for our purposes
/// (`.` and `..` are always dropped by the parser, so the two forms compact
/// identically). `-I PATTERN` and its attached form `-Ipattern` consume the
/// pattern — it is never treated as a path operand. `-t` (or `--sort=time`) is
/// remembered so compaction can preserve ls's ordering instead of grouping
/// directories first. Per `man ls`, the long listing is triggered by `-l` and
/// also implied by `-g`, `-n`, `-o`, `--full-time`, or GNU `--format=long` /
/// `--format=verbose` — in any of those cases we preserve permission info as
/// octal.
fn parse_args(args: &[String]) -> (Vec<String>, Vec<String>, bool, bool, bool) {
    let mut forwarded: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut show_all = false;
    let mut show_long = false;
    let mut preserve_order = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        // Everything after an explicit `--` is a path operand.
        if arg == "--" {
            paths.extend(args[i + 1..].iter().cloned());
            break;
        }

        if let Some(long) = arg.strip_prefix("--") {
            match long {
                // Already implied by the proxy's internal `-la`.
                "all" | "almost-all" => show_all = true,
                "full-time" | "format=long" | "format=verbose" => {
                    show_long = true;
                    forwarded.push(arg.clone());
                }
                "sort=time" => {
                    preserve_order = true;
                    forwarded.push(arg.clone());
                }
                "ignore" => {
                    // `--ignore PATTERN` takes the following argument as its value.
                    forwarded.push(arg.clone());
                    if i + 1 < args.len() {
                        i += 1;
                        forwarded.push(args[i].clone());
                    }
                }
                _ => forwarded.push(arg.clone()),
            }
            i += 1;
            continue;
        }

        if arg.starts_with('-') && arg.len() > 1 {
            let cluster = &arg[1..];
            let mut forward = String::new();
            let mut value_follows = false;
            for (idx, c) in cluster.char_indices() {
                match c {
                    'a' | 'A' => show_all = true,
                    'l' | 'g' | 'n' | 'o' => show_long = true,
                    'h' => {} // proxy renders its own human sizes
                    't' => {
                        preserve_order = true;
                        forward.push('t');
                    }
                    'I' => {
                        // Whatever follows `I` in the cluster is its pattern;
                        // otherwise the pattern is the following argument.
                        forward.push('I');
                        let rest = &cluster[idx + c.len_utf8()..];
                        if rest.is_empty() {
                            value_follows = true;
                        } else {
                            forward.push_str(rest);
                        }
                        break;
                    }
                    other => forward.push(other),
                }
            }
            if !forward.is_empty() {
                forwarded.push(format!("-{}", forward));
            }
            if value_follows && i + 1 < args.len() {
                i += 1;
                forwarded.push(args[i].clone());
            }
            i += 1;
            continue;
        }

        paths.push(arg.clone());
        i += 1;
    }

    (forwarded, paths, show_all, show_long, preserve_order)
}

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    let (extra_flags, paths, show_all, show_long, preserve_order) = parse_args(args);

    let mut cmd = resolved_command("ls");
    cmd.env("LC_ALL", "C");
    cmd.arg("-la");
    for flag in &extra_flags {
        cmd.arg(flag);
    }

    // Insert a `--` boundary so a user path that begins with `-` (e.g. a file
    // literally named `-la`) is treated as an operand, not an `ls` option
    // (#100, G5#1).
    cmd.arg("--");
    if paths.is_empty() {
        cmd.arg(".");
    } else {
        for p in &paths {
            cmd.arg(p);
        }
    }

    let target_display = if paths.is_empty() {
        ".".to_string()
    } else {
        paths.join(" ")
    };

    runner::run_filtered(
        cmd,
        "ls",
        &format!("-la {}", target_display),
        |raw| {
            let (entries, summary, parsed_count) =
                compact_ls_inner(raw, show_all, show_long, preserve_order);

            // If no lines were parsed (e.g., unrecognized locale), fall back to raw output.
            // This is safer than returning "(empty)" for a non-empty directory.
            let has_real_content = raw
                .lines()
                .any(|l| !l.starts_with("total ") && !l.is_empty() && !is_dotdir(l));
            if parsed_count == 0 && has_real_content {
                return raw.to_string();
            }

            // Only show summary in interactive mode (not when piped)
            let is_tty = std::io::stdout().is_terminal();
            let filtered = if is_tty {
                format!("{}{}", entries, summary)
            } else {
                entries
            };

            if verbose > 0 {
                eprintln!(
                    "Chars: {} → {} ({}% reduction)",
                    raw.len(),
                    filtered.len(),
                    if !raw.is_empty() {
                        100 - (filtered.len() * 100 / raw.len())
                    } else {
                        0
                    }
                );
            }
            filtered
        },
        RunOptions::stdout_only()
            .early_exit_on_failure()
            .no_trailing_newline(),
    )
}

/// Format bytes into human-readable size
fn human_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1}M", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

/// Parse a single `ls -la` line, returning `(file_type_char, perms, size, name)`.
///
/// `perms` is the raw 10-char string from ls (e.g. `-rw-r--r--`); use
/// [`perms_to_octal`] to render it.
///
/// Uses the date field as a stable anchor — the date format in `ls -la` is
/// always three tokens (`Mon DD HH:MM` or `Mon DD  YYYY`), so we locate it
/// with a regex, then extract size (rightmost number before the date) and
/// filename (everything after the date). This handles owner/group names that
/// contain spaces, which break the old fixed-column approach.
fn parse_ls_line(line: &str) -> Option<(char, String, u64, String)> {
    // Skip . and .. entries before date parsing (works for non-English locales too)
    if is_dotdir(line) {
        return None;
    }

    let date_match = LS_DATE_RE.find(line)?;
    let name = line[date_match.end()..].to_string();

    let before_date = &line[..date_match.start()];
    let before_parts: Vec<&str> = before_date.split_whitespace().collect();
    if before_parts.len() < 4 {
        return None;
    }

    let perms = before_parts[0].to_string();
    let file_type = perms.chars().next()?;

    // Size is the rightmost parseable number before the date.
    // nlinks is also numeric but appears earlier; scanning from the end
    // guarantees we hit the size field first.
    let mut size: u64 = 0;
    for part in before_parts.iter().rev() {
        if let Ok(s) = part.parse::<u64>() {
            size = s;
            break;
        }
    }

    Some((file_type, perms, size, name))
}

/// Convert an `ls`-style permission string (e.g. `-rw-r--r--`, `drwxr-xr-x`,
/// `-rwsr-xr-t`) into octal notation (e.g. `644`, `755`, `4755`).
///
/// Returns `None` if the input does not look like a permission field.
/// Special bits (setuid/setgid/sticky) are encoded as a leading 4th digit when
/// any are set; otherwise we emit a 3-digit value to stay compact.
fn perms_to_octal(perms: &str) -> Option<String> {
    if perms.len() < 10 || !perms.is_ascii() {
        return None;
    }
    let b = perms.as_bytes();

    fn perm_value(read: bool, write: bool, exec: bool) -> u32 {
        ((read as u32) << 2) | ((write as u32) << 1) | (exec as u32)
    }

    let owner_x = matches!(b[3], b'x' | b's');
    let group_x = matches!(b[6], b'x' | b's');
    let other_x = matches!(b[9], b'x' | b't');

    let owner = perm_value(b[1] == b'r', b[2] == b'w', owner_x);
    let group = perm_value(b[4] == b'r', b[5] == b'w', group_x);
    let other = perm_value(b[7] == b'r', b[8] == b'w', other_x);

    let setuid = matches!(b[3], b's' | b'S');
    let setgid = matches!(b[6], b's' | b'S');
    let sticky = matches!(b[9], b't' | b'T');
    let special = perm_value(setuid, setgid, sticky);

    if special > 0 {
        Some(format!("{}{}{}{}", special, owner, group, other))
    } else {
        Some(format!("{}{}{}", owner, group, other))
    }
}

/// Returns true if the line represents a . or .. directory entry.
///
/// POSIX.1-2017 (IEEE Std 1003.1) specifies that each directory contains
/// entries for "." (the directory itself) and ".." (its parent). These entries
/// always appear in `ls -la` output and are skipped during parsing since they
/// carry no meaningful content for token reduction.
fn is_dotdir(line: &str) -> bool {
    line.trim().ends_with('.') || line.trim().ends_with("..")
}

/// A single entry produced from `ls -la` output, kept in encounter order.
enum Entry {
    Dir(String, Option<String>),
    File(String, String, Option<String>),
}

/// Append one compact entry to `out`.
fn push_entry(out: &mut String, entry: &Entry) {
    match entry {
        Entry::Dir(name, octal) => {
            if let Some(octal) = octal {
                out.push_str(octal);
                out.push_str("  ");
            }
            out.push_str(name);
            out.push_str("/\n");
        }
        Entry::File(name, size, octal) => {
            if let Some(octal) = octal {
                out.push_str(octal);
                out.push_str("  ");
            }
            out.push_str(name);
            out.push_str("  ");
            out.push_str(size);
            out.push('\n');
        }
    }
}

/// Parse ls -la output into compact format.
///
/// Without `show_long`:
///   name/        (dirs)
///   name  size   (files)
///
/// With `show_long` (user passed `-l`):
///   755  name/        (dirs)
///   644  name  size   (files)
///
/// With `preserve_order` (user passed `-t` / `--sort=time`) entries are emitted
/// in the order `ls` produced them, so the timestamp ordering is not destroyed
/// by grouping directories first.
///
/// Returns (entries, summary, parsed_count) so caller can suppress summary when piped.
/// parsed_count tracks how many non-header lines were successfully parsed.
/// If parsed_count == 0 but raw had content, caller should fall back to raw output.
fn compact_ls_inner(
    raw: &str,
    show_all: bool,
    show_long: bool,
    preserve_order: bool,
) -> (String, String, usize) {
    use std::collections::HashMap;

    let mut ordered: Vec<Entry> = Vec::new();
    let mut dir_count: usize = 0;
    let mut file_count: usize = 0;
    let mut by_ext: HashMap<String, usize> = HashMap::new();
    let mut lines_seen: usize = 0;
    let mut parsed_count: usize = 0;
    let mut dotdirs: usize = 0;

    for line in raw.lines() {
        if line.starts_with("total ") || line.is_empty() {
            continue;
        }
        lines_seen += 1;

        let Some((file_type, perms, size, name)) = parse_ls_line(line) else {
            if is_dotdir(line) {
                dotdirs += 1;
            }
            continue;
        };
        parsed_count += 1;

        // Filter noise dirs unless -a / -A
        if !show_all && NOISE_DIRS.iter().any(|noise| name == *noise) {
            continue;
        }

        // Only parse perms when the user actually wants the long listing —
        // skip the work otherwise.
        let octal = if show_long {
            perms_to_octal(&perms)
        } else {
            None
        };

        if file_type == 'd' {
            dir_count += 1;
            ordered.push(Entry::Dir(name, octal));
        } else {
            // Regular files, symlinks, character/block devices, pipes, sockets
            let ext = if let Some(pos) = name.rfind('.') {
                name[pos..].to_string()
            } else {
                "no ext".to_string()
            };
            *by_ext.entry(ext).or_insert(0) += 1;
            file_count += 1;
            ordered.push(Entry::File(name, human_size(size), octal));
        }
    }

    if ordered.is_empty() {
        if lines_seen > 0 && parsed_count == 0 {
            if dotdirs == lines_seen {
                // Only . and .. entries (empty directory)
                return ("(empty)\n".to_string(), String::new(), 0);
            }
            // Real content that couldn't be parsed (e.g., non-English locale)
            return (String::new(), String::new(), 0);
        }
        return ("(empty)\n".to_string(), String::new(), 0);
    }

    let mut entries = String::new();

    if preserve_order {
        // Keep ls's ordering (e.g. `-t` by mtime) intact.
        for entry in &ordered {
            push_entry(&mut entries, entry);
        }
    } else {
        // Dirs first, then files with size.
        for entry in &ordered {
            if matches!(entry, Entry::Dir(..)) {
                push_entry(&mut entries, entry);
            }
        }
        for entry in &ordered {
            if matches!(entry, Entry::File(..)) {
                push_entry(&mut entries, entry);
            }
        }
    }

    // Summary line (separate so caller can suppress when piped)
    let mut summary = format!("\nSummary: {} files, {} dirs", file_count, dir_count);
    if !by_ext.is_empty() {
        let mut ext_counts: Vec<_> = by_ext.iter().collect();
        ext_counts.sort_by(|a, b| b.1.cmp(a.1));
        let ext_parts: Vec<String> = ext_counts
            .iter()
            .take(5)
            .map(|(ext, count)| format!("{} {}", count, ext))
            .collect();
        summary.push_str(" (");
        summary.push_str(&ext_parts.join(", "));
        if ext_counts.len() > 5 {
            summary.push_str(&format!(", +{} more", ext_counts.len() - 5));
        }
        summary.push(')');
    }
    summary.push('\n');

    (entries, summary, parsed_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shim for the pre-`preserve_order` tests: default compaction groups
    /// directories before files.
    fn compact_ls(raw: &str, show_all: bool, show_long: bool) -> (String, String, usize) {
        compact_ls_inner(raw, show_all, show_long, false)
    }

    #[test]
    fn test_compact_basic() {
        let input = "total 48\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 .\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 ..\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 src\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 Cargo.toml\n\
                     -rw-r--r--  1 user  staff  5678 Jan  1 12:00 README.md\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(entries.contains("src/"));
        assert!(entries.contains("Cargo.toml"));
        assert!(entries.contains("README.md"));
        assert!(entries.contains("1.2K")); // 1234 bytes
        assert!(entries.contains("5.5K")); // 5678 bytes
        assert!(!entries.contains("drwx")); // no permissions
        assert!(!entries.contains("staff")); // no group
        assert!(!entries.contains("total")); // no total
        assert!(!entries.contains("\n.\n")); // no . entry
        assert!(!entries.contains("\n..\n")); // no .. entry
    }

    #[test]
    fn test_compact_filters_noise() {
        let input = "total 8\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 node_modules\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 .git\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 target\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 src\n\
                     -rw-r--r--  1 user  staff  100 Jan  1 12:00 main.rs\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(!entries.contains("node_modules"));
        assert!(!entries.contains(".git"));
        assert!(!entries.contains("target"));
        assert!(entries.contains("src/"));
        assert!(entries.contains("main.rs"));
    }

    #[test]
    fn test_compact_shows_dotenv_file_but_hides_env_dir() {
        // `.env` is intentionally visible to agents; `env/` (Python venv) stays
        // hidden as noise even without -a.
        let input = "total 8\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 env\n\
                     -rw-r--r--  1 user  staff  100 Jan  1 12:00 .env\n\
                     -rw-r--r--  1 user  staff  100 Jan  1 12:00 main.rs\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(entries.contains(".env"), "`.env` should be visible");
        assert!(!entries.contains("env/"), "`env/` dir should stay hidden");
        assert!(entries.contains("main.rs"));
    }

    #[test]
    fn test_compact_show_all() {
        let input = "total 8\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 .git\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 src\n";
        let (entries, _summary, _) = compact_ls(input, true, false);
        assert!(entries.contains(".git/"));
        assert!(entries.contains("src/"));
    }

    #[test]
    fn test_compact_empty() {
        let input = "total 0\n";
        let (entries, summary, _) = compact_ls(input, false, false);
        assert_eq!(entries, "(empty)\n");
        assert!(summary.is_empty());
    }

    #[test]
    fn test_compact_empty_chinese_locale() {
        let input = "total 8\n\
                     drwxr-xr-x  2 user user  4096  1月  1 12:00 .\n\
                     drwxr-xr-x 16 user user 20480  1月  1 12:00 ..\n";
        let (entries, summary, parsed_count) = compact_ls(input, false, false);
        assert_eq!(parsed_count, 0);
        assert_eq!(entries, "(empty)\n");
        assert!(summary.is_empty());
    }

    #[test]
    fn test_compact_empty_english_locale() {
        let input = "total 0\n\
                     drwxr-xr-x  2 lumin  wheel  64 Apr 23 00:37 .\n\
                     drwxr-xr-x 16 root  wheel 164576 Apr 23 00:37 ..\n";
        let (entries, summary, parsed_count) = compact_ls(input, false, false);
        assert_eq!(parsed_count, 0);
        assert_eq!(entries, "(empty)\n");
        assert!(summary.is_empty());
    }

    #[test]
    fn test_compact_summary() {
        let input = "total 48\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 src\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 main.rs\n\
                     -rw-r--r--  1 user  staff  5678 Jan  1 12:00 lib.rs\n\
                     -rw-r--r--  1 user  staff   100 Jan  1 12:00 Cargo.toml\n";
        let (_entries, summary, _) = compact_ls(input, false, false);
        assert!(summary.contains("Summary: 3 files, 1 dirs"));
        assert!(summary.contains(".rs"));
        assert!(summary.contains(".toml"));
    }

    #[test]
    fn test_human_size() {
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(500), "500B");
        assert_eq!(human_size(1024), "1.0K");
        assert_eq!(human_size(1234), "1.2K");
        assert_eq!(human_size(1_048_576), "1.0M");
        assert_eq!(human_size(2_500_000), "2.4M");
    }

    #[test]
    fn test_compact_handles_filenames_with_spaces() {
        let input = "total 8\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 my file.txt\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(entries.contains("my file.txt"));
    }

    #[test]
    fn test_compact_symlinks() {
        let input = "total 8\n\
                     lrwxr-xr-x  1 user  staff  10 Jan  1 12:00 link -> target\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(entries.contains("link -> target"));
    }

    #[test]
    fn test_entries_no_summary() {
        // Entries should never contain the summary line
        let input = "total 48\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 src\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 main.rs\n";
        let (entries, summary, _) = compact_ls(input, false, false);
        assert!(
            !entries.contains("Summary:"),
            "entries must not contain summary"
        );
        assert!(
            summary.contains("Summary:"),
            "summary must contain the icon"
        );
    }

    #[test]
    fn test_pipe_line_count() {
        // Simulates: ctxcrl ls | wc -l
        // Entries should have exactly 1 line per file/dir, no extra blank or summary
        let input = "total 48\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 src\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 main.rs\n\
                     -rw-r--r--  1 user  staff  5678 Jan  1 12:00 lib.rs\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        let line_count = entries.lines().count();
        assert_eq!(
            line_count, 3,
            "pipe should see exactly 3 lines (1 dir + 2 files), got {}",
            line_count
        );
    }

    // Regression test for #948: owner/group with spaces breaks fixed-column parsing
    #[test]
    fn test_compact_multiline_group() {
        let input = "total 8\n\
                     -rw-r--r--  1 fjeanne utilisa. du domaine    0 Mar 31 16:18 empty.txt\n\
                     -rw-r--r--  1 fjeanne utilisa. du domaine 1234 Mar 31 16:18 data.json\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(
            entries.contains("empty.txt"),
            "should contain 'empty.txt', got: {entries}"
        );
        assert!(
            entries.contains("data.json"),
            "should contain 'data.json', got: {entries}"
        );
        assert!(
            !entries.contains("16:18"),
            "time should not leak into filename, got: {entries}"
        );
        assert!(
            entries.contains("0B"),
            "empty.txt should show 0B, got: {entries}"
        );
        assert!(
            entries.contains("1.2K"),
            "data.json should show 1.2K (1234 bytes), got: {entries}"
        );
    }

    #[test]
    fn test_compact_year_format_date() {
        // Some systems show year instead of time for old files
        let input = "total 8\n\
                     -rw-r--r--  1 user staff  5678 Dec 25  2024 archive.tar\n";
        let (entries, _summary, _) = compact_ls(input, false, false);
        assert!(
            entries.contains("archive.tar"),
            "should contain filename, got: {entries}"
        );
        assert!(entries.contains("5.5K"), "should show 5.5K, got: {entries}");
    }

    #[test]
    fn test_parse_ls_line_basic() {
        let (ft, perms, size, name) =
            parse_ls_line("-rw-r--r--  1 user staff 1234 Jan  1 12:00 file.txt").unwrap();
        assert_eq!(ft, '-');
        assert_eq!(perms, "-rw-r--r--");
        assert_eq!(size, 1234);
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn test_parse_ls_line_multiline_group() {
        let (ft, perms, size, name) =
            parse_ls_line("-rw-r--r--  1 fjeanne utilisa. du domaine 0 Mar 31 16:18 empty.txt")
                .unwrap();
        assert_eq!(ft, '-');
        assert_eq!(perms, "-rw-r--r--");
        assert_eq!(size, 0);
        assert_eq!(name, "empty.txt");
    }

    #[test]
    fn test_parse_ls_line_dir_with_space_in_group() {
        let (ft, perms, size, name) =
            parse_ls_line("drwxr-xr-x  2 fjeanne utilisa. du domaine 64 Mar 31 16:18 my dir")
                .unwrap();
        assert_eq!(ft, 'd');
        assert_eq!(perms, "drwxr-xr-x");
        assert_eq!(size, 64);
        assert_eq!(name, "my dir");
    }

    #[test]
    fn test_parse_ls_line_symlink() {
        let (ft, perms, size, name) =
            parse_ls_line("lrwxr-xr-x  1 user staff 10 Jan  1 12:00 link -> target").unwrap();
        assert_eq!(ft, 'l');
        assert_eq!(perms, "lrwxr-xr-x");
        assert_eq!(size, 10);
        assert_eq!(name, "link -> target");
    }

    #[test]
    fn test_compact_device_files() {
        // Regression test for #844: `ctxcrl ls /dev/ttyACM*` returned "(empty)"
        // because character devices (type 'c') were not handled by compact_ls.
        let input = "crw-rw----  1 root  dialout  166, 0 Apr 22 09:46 /dev/ttyACM0\n";
        let (entries, _summary, _parsed) = compact_ls(input, false, false);
        assert!(
            entries.contains("/dev/ttyACM0"),
            "should contain device file, got: {entries}"
        );
        assert!(!entries.contains("(empty)"), "should not be empty");
    }

    #[test]
    fn test_compact_device_files_macos_hex_size() {
        // macOS shows device major/minor as hex (e.g. 0x2000000)
        let input = "crw-rw-rw-  1 root  wheel  0x2000000 Mar 31 19:25 /dev/tty\n";
        let (entries, _summary, _parsed) = compact_ls(input, false, false);
        assert!(
            entries.contains("/dev/tty"),
            "should contain device file, got: {entries}"
        );
    }

    #[test]
    fn test_compact_block_device() {
        let input = "brw-rw----  1 root  disk  8, 0 Apr 22 09:46 /dev/sda\n";
        let (entries, _summary, _parsed) = compact_ls(input, false, false);
        assert!(
            entries.contains("/dev/sda"),
            "should contain block device, got: {entries}"
        );
    }

    #[test]
    fn test_parse_ls_line_returns_none_for_total() {
        assert!(parse_ls_line("total 48").is_none());
    }

    #[test]
    fn test_parse_ls_line_year_format() {
        let (ft, perms, size, name) =
            parse_ls_line("-rw-r--r--  1 user staff 5678 Dec 25  2024 old.tar.gz").unwrap();
        assert_eq!(ft, '-');
        assert_eq!(perms, "-rw-r--r--");
        assert_eq!(size, 5678);
        assert_eq!(name, "old.tar.gz");
    }

    #[test]
    fn test_perms_to_octal_common() {
        assert_eq!(perms_to_octal("-rw-r--r--").as_deref(), Some("644"));
        assert_eq!(perms_to_octal("-rwxr-xr-x").as_deref(), Some("755"));
        assert_eq!(perms_to_octal("drwxr-xr-x").as_deref(), Some("755"));
        assert_eq!(perms_to_octal("-rw-------").as_deref(), Some("600"));
        assert_eq!(perms_to_octal("-rwxrwxrwx").as_deref(), Some("777"));
        assert_eq!(perms_to_octal("----------").as_deref(), Some("000"));
        assert_eq!(perms_to_octal("lrwxr-xr-x").as_deref(), Some("755"));
    }

    #[test]
    fn test_perms_to_octal_special_bits() {
        // setuid + 755 -> 4755
        assert_eq!(perms_to_octal("-rwsr-xr-x").as_deref(), Some("4755"));
        // setuid without execute -> 4644
        assert_eq!(perms_to_octal("-rwSr--r--").as_deref(), Some("4644"));
        // setgid + 755 -> 2755
        assert_eq!(perms_to_octal("-rwxr-sr-x").as_deref(), Some("2755"));
        // sticky bit on /tmp-style dir -> 1777
        assert_eq!(perms_to_octal("drwxrwxrwt").as_deref(), Some("1777"));
        // setuid + setgid + sticky
        assert_eq!(perms_to_octal("-rwsrwsrwt").as_deref(), Some("7777"));
    }

    #[test]
    fn test_perms_to_octal_garbage() {
        assert_eq!(perms_to_octal(""), None);
        assert_eq!(perms_to_octal("short"), None);
    }

    #[test]
    fn test_compact_long_format_includes_octal() {
        let input = "total 48\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 src\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 Cargo.toml\n\
                     -rwxr-xr-x  1 user  staff   500 Jan  1 12:00 build.sh\n";
        let (entries, _summary, _parsed) = compact_ls(input, false, true);
        assert!(
            entries.contains("755  src/"),
            "dir should be prefixed with octal perms, got: {entries}"
        );
        assert!(
            entries.contains("644  Cargo.toml  1.2K"),
            "file should be prefixed with octal perms, got: {entries}"
        );
        assert!(
            entries.contains("755  build.sh  500B"),
            "executable should show 755, got: {entries}"
        );
    }

    #[test]
    fn test_compact_short_format_omits_octal() {
        // Without -l, no octal prefix even though we still parse `ls -la`
        // under the hood.
        let input = "total 48\n\
                     -rw-r--r--  1 user  staff  1234 Jan  1 12:00 Cargo.toml\n";
        let (entries, _summary, _parsed) = compact_ls(input, false, false);
        assert!(
            !entries.contains("644"),
            "short format must not include octal perms, got: {entries}"
        );
        assert!(entries.contains("Cargo.toml"));
    }

    #[test]
    fn test_compact_long_format_preserves_symlink_and_dir_types() {
        // Type prefix is preserved separately from perms: a dir stays `name/`
        // and a symlink keeps its `link -> target` rendering.
        let input = "total 16\n\
                     drwxr-xr-x  2 user  staff    64 Jan  1 12:00 mydir\n\
                     lrwxr-xr-x  1 user  staff    10 Jan  1 12:00 link -> target\n";
        let (entries, _summary, _parsed) = compact_ls(input, false, true);
        assert!(
            entries.contains("755  mydir/"),
            "dir keeps trailing slash with octal prefix, got: {entries}"
        );
        assert!(
            entries.contains("755  link -> target"),
            "symlink target rendering preserved with octal prefix, got: {entries}"
        );
    }

    fn count_tokens(text: &str) -> usize {
        text.split_whitespace().count()
    }

    #[test]
    fn test_long_format_fixture_no_bloat() {
        // Real `ls -la` fixture: the long-format octal output must still be
        // smaller than the raw `ls -la` it replaces (positive savings).
        let input = include_str!("../../../tests/fixtures/ls_la_raw.txt");
        let (entries, _summary, parsed_count) = compact_ls(input, true, true);
        assert!(parsed_count > 0, "fixture should parse some entries");

        let input_tokens = count_tokens(input);
        let output_tokens = count_tokens(&entries);
        assert!(
            output_tokens < input_tokens,
            "long-format output should be smaller than raw ls -la: {output_tokens} >= {input_tokens}"
        );
        // Octal perms must actually be present in the long-format output.
        assert!(
            entries.contains("755") || entries.contains("644"),
            "long-format fixture output should carry octal perms, got: {entries}"
        );
    }

    #[test]
    fn test_compact_chinese_locale_fallback() {
        let input = "total 8\n\
                      drwxr-xr-x  2 user staff  64  1月  1 12:00 src\n\
                      -rw-r--r--  1 user staff 1234  1月  1 12:00 main.rs\n";
        let (entries, summary, parsed_count) = compact_ls(input, false, false);
        assert_eq!(parsed_count, 0);
        assert!(entries.is_empty());
        assert!(summary.is_empty());
    }

    #[test]
    fn test_parse_args_almost_all_shows_hidden() {
        // `-A` / `--almost-all` must reveal hidden noise dirs just like `-a`.
        let args: Vec<String> = ["-A"].iter().map(|s| s.to_string()).collect();
        let (_flags, paths, show_all, _long, _order) = parse_args(&args);
        assert!(show_all, "-A should enable show_all");
        assert!(paths.is_empty());

        let args: Vec<String> = ["--almost-all"].iter().map(|s| s.to_string()).collect();
        let (_flags, _paths, show_all, _long, _order) = parse_args(&args);
        assert!(show_all, "--almost-all should enable show_all");
    }

    #[test]
    fn test_almost_all_reveals_noise_dirs() {
        let input = "total 8\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 .git\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 .vscode\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 src\n";
        let (entries, _summary, _) = compact_ls_inner(input, true, false, false);
        assert!(entries.contains(".git/"), "got: {entries}");
        assert!(entries.contains(".vscode/"), "got: {entries}");
        assert!(entries.contains("src/"));

        // Without show_all they stay hidden.
        let (entries, _summary, _) = compact_ls_inner(input, false, false, false);
        assert!(!entries.contains(".git/"));
        assert!(!entries.contains(".vscode/"));
    }

    #[test]
    fn test_parse_args_dash_i_attached_is_not_a_path() {
        let args: Vec<String> = ["-Ihello"].iter().map(|s| s.to_string()).collect();
        let (flags, paths, _all, _long, _order) = parse_args(&args);
        assert!(
            paths.is_empty(),
            "pattern must not become a path: {paths:?}"
        );
        assert_eq!(flags, vec!["-Ihello".to_string()]);
    }

    #[test]
    fn test_parse_args_dash_i_separate_consumes_pattern() {
        let args: Vec<String> = ["-I", "target", "src"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (flags, paths, _all, _long, _order) = parse_args(&args);
        assert_eq!(flags, vec!["-I".to_string(), "target".to_string()]);
        assert_eq!(paths, vec!["src".to_string()]);
    }

    #[test]
    fn test_parse_args_dash_i_clustered_consumes_pattern() {
        let args: Vec<String> = ["-lIhello", "src"].iter().map(|s| s.to_string()).collect();
        let (flags, paths, _all, show_long, _order) = parse_args(&args);
        assert!(show_long);
        assert_eq!(flags, vec!["-Ihello".to_string()]);
        assert_eq!(paths, vec!["src".to_string()]);
    }

    #[test]
    fn test_parse_args_sort_time_sets_preserve_order() {
        let args: Vec<String> = ["-t"].iter().map(|s| s.to_string()).collect();
        let (flags, _paths, _all, _long, preserve_order) = parse_args(&args);
        assert!(preserve_order);
        assert_eq!(flags, vec!["-t".to_string()]);

        let args: Vec<String> = ["--sort=time"].iter().map(|s| s.to_string()).collect();
        let (_flags, _paths, _all, _long, preserve_order) = parse_args(&args);
        assert!(preserve_order);
    }

    #[test]
    fn test_parse_args_pattern_t_not_mistaken_for_time_sort() {
        // The `t` inside an -I pattern must not set preserve_order.
        let args: Vec<String> = ["-Itarget"].iter().map(|s| s.to_string()).collect();
        let (flags, _paths, _all, _long, preserve_order) = parse_args(&args);
        assert!(!preserve_order, "-Itarget must not imply -t");
        assert_eq!(flags, vec!["-Itarget".to_string()]);
    }

    #[test]
    fn test_preserve_order_interleaves_dirs_and_files() {
        // ls produced: dir, file, dir — with -t this exact order must survive.
        let input = "total 8\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 first\n\
                     -rw-r--r--  1 user  staff  10 Jan  1 12:00 b.txt\n\
                     drwxr-xr-x  2 user  staff  64 Jan  1 12:00 third\n";
        let (entries, _summary, _) = compact_ls_inner(input, false, false, true);
        let lines: Vec<&str> = entries.lines().collect();
        assert_eq!(lines, vec!["first/", "b.txt  10B", "third/"]);

        // Without the flag, directories are grouped first.
        let (entries, _summary, _) = compact_ls_inner(input, false, false, false);
        let lines: Vec<&str> = entries.lines().collect();
        assert_eq!(lines, vec!["first/", "third/", "b.txt  10B"]);
    }
}
