//! Curated public filter API for downstream embedders.
//!
//! These functions let a Rust program apply a named (or auto-detected)
//! ContextCrawler filter to text it has already captured — e.g. the stdout of a
//! command it ran itself — without spawning the `contextcrawler` CLI. They are
//! thin, panic-safe wrappers over the same machinery that powers
//! `contextcrawler pipe`.

use crate::cmds::system::pipe_cmd;

/// Canonical list of filter names accepted by [`filter_output`].
///
/// Kept in sync **by hand** with the `match` arms of
/// `crate::cmds::system::pipe_cmd::resolve_filter` (including aliases such as
/// `rg`/`fd`). If you add or rename a filter there, update this slice too.
const FILTER_NAMES: &[&str] = &[
    "cargo-test",
    "cargo",
    "pytest",
    "go-test",
    "go-build",
    "tsc",
    "vitest",
    "grep",
    "rg",
    "find",
    "fd",
    "git-log",
    "git-diff",
    "git-status",
    "mypy",
    "ruff-check",
    "ruff-format",
    "prettier",
];

/// Apply a named filter to captured command output.
///
/// `filter_name` is one of the names returned by [`available_filters`] (for
/// example `"grep"`, `"cargo-test"`, `"git-diff"`). `raw` is the text to
/// compact — typically the stdout you captured from running the corresponding
/// command yourself. Returns the filtered (token-reduced) text. If
/// `filter_name` is not recognised, `raw` is returned unchanged.
///
/// This mirrors `contextcrawler pipe -f <filter_name>` exactly and is
/// **exit-blind**: a piped filter only ever sees text, never the command's exit
/// code, so failure-aware behaviour (e.g. "show errors only on non-zero exit")
/// is not available here. The call is panic-safe: if the underlying filter
/// panics, the raw input is passed through unchanged.
pub fn filter_output(filter_name: &str, raw: &str) -> String {
    match pipe_cmd::resolve_filter(filter_name) {
        Some(filter_fn) => pipe_cmd::apply_filter(filter_fn, raw),
        None => raw.to_string(),
    }
}

/// Apply a filter chosen by sniffing the content of `raw`.
///
/// Inspects the first ~1 KiB of `raw` to detect the output shape (cargo test,
/// pytest, grep, go test JSON, mypy, vitest, find, …) and applies the matching
/// filter, returning the compacted text. If nothing matches, `raw` is returned
/// unchanged. Mirrors `contextcrawler pipe` with no `-f` flag and is likewise
/// exit-blind and panic-safe.
pub fn auto_filter_output(raw: &str) -> String {
    let filter_fn = pipe_cmd::auto_detect_filter(raw);
    pipe_cmd::apply_filter(filter_fn, raw)
}

/// The filter names accepted by [`filter_output`].
///
/// Returns every name (and alias) that [`filter_output`] will resolve, so an
/// embedder can present or validate the available filters. Names that are not in
/// this list cause [`filter_output`] to pass input through unchanged.
pub fn available_filters() -> Vec<&'static str> {
    FILTER_NAMES.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_output_known_filter_compacts() {
        // grep-shaped input: many matches across files should collapse.
        let mut input = String::new();
        for i in 1..=40 {
            input.push_str(&format!(
                "src/main.rs:{}:    let result = do_work(ctx, payload)?;\n",
                i
            ));
        }
        let out = filter_output("grep", &input);
        assert!(out.len() < input.len(), "expected compaction: out={}", out);
        assert!(out.contains("matches"), "expected grep summary: out={}", out);
    }

    #[test]
    fn filter_output_unknown_name_returns_raw() {
        let input = "arbitrary text the filter does not understand\n";
        let out = filter_output("definitely-not-a-filter", input);
        assert_eq!(out, input);
    }

    #[test]
    fn auto_filter_output_detects_grep_and_compacts() {
        let mut input = String::new();
        for i in 1..=40 {
            input.push_str(&format!(
                "src/lib.rs:{}:    handler.dispatch(request).await?;\n",
                i
            ));
        }
        let out = auto_filter_output(&input);
        assert!(out.len() < input.len(), "expected compaction: out={}", out);
        assert!(out.contains("matches"), "expected grep summary: out={}", out);
    }

    #[test]
    fn auto_filter_output_unknown_returns_raw() {
        let input = "just one unremarkable line\n";
        let out = auto_filter_output(input);
        assert_eq!(out, input);
    }

    #[test]
    fn available_filters_includes_core_names() {
        let names = available_filters();
        for expected in ["grep", "cargo-test", "git-diff", "prettier"] {
            assert!(names.contains(&expected), "missing {} in {:?}", expected, names);
        }
        // Every advertised name must actually resolve (keeps the hand-maintained
        // FILTER_NAMES list honest against resolve_filter).
        for name in &names {
            assert!(
                pipe_cmd::resolve_filter(name).is_some(),
                "advertised filter {} should resolve",
                name
            );
        }
    }
}
