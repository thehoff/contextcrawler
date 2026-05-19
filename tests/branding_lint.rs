//! Branding lint — prevents the downstream-rebrand regressions that
//! repeatedly bit us in this fork (issues #19, #20, #22, #23).
//!
//! Scans every `.rs` file under `src/` and asserts that none of the
//! forbidden upstream-branded literals appear in production source —
//! `[rtk]`, `[rtk:`, `RTK.md`, `@RTK.md`. Each occurrence either
//! - needs to be replaced with the equivalent CONTEXTCRAWLER form, or
//! - if it's an intentional legacy reference (regression-history
//!   comments, the `LEGACY_RTK_MD_FILES` registry, migration code
//!   that detects the old names, tests that verify legacy cleanup),
//!   needs the marker comment `// branding-lint: allow legacy` on the
//!   same line OR be in a function/test name whose role makes legacy
//!   reference obvious (matched via the allowed-callsite rules below).
//!
//! Future renames just update the `FORBIDDEN_TOKENS` table here — any
//! source line that drifts from the rebrand will fail this test with a
//! clear pointer back to this file.

use lazy_static::lazy_static;
use regex::Regex;
use std::fs;
use walkdir::WalkDir;

/// Tokens that should never appear in production source unless explicitly
/// allowlisted. Each entry: (needle, human-readable explanation shown on
/// failure).
const FORBIDDEN_TOKENS: &[(&str, &str)] = &[
    ("[rtk]", "warning/error prefix — use \"[contextcrawler]\" (issue #23)"),
    ("[rtk:", "diagnostic prefix variants — use \"[contextcrawler:\" (issue #23)"),
    ("RTK.md", "slim instructions filename — use CONTEXTCRAWLER.md or the RTK_MD constant (issue #19/#20)"),
    ("@RTK.md", "slim instructions @-reference — use @CONTEXTCRAWLER.md or RTK_MD_REF constant (issue #19/#20)"),
    // User-visible phrases that escaped the rebrand sweep and reached the
    // dashboard. Each entry below was found in the wild by a user report.
    ("rtk instructions", "init message — use \"contextcrawler instructions\" (post-v0.1.8 user report)"),
    ("\"rtk: ", "error prefix in unstructured stderr — use \"contextcrawler: \" (post-v0.1.8 user report)"),
    ("rtk telemetry", "CLI command in user-facing text — use \"contextcrawler telemetry\" (post-v0.1.8 user report)"),
    // Branding sweep round 3 (user-reported, 2026-05-18). Clap doc comments
    // (///) leak into `--help` output, which is high-visibility surface. The
    // specific phrases below were found in `--help` after the v0.1.8 deploy.
    ("RTK savings", "clap doc comment — use \"ContextCrawler savings\" (branding sweep round 3)"),
    ("RTK adoption", "clap doc comment — use \"ContextCrawler adoption\" (branding sweep round 3)"),
    ("RTK equivalent", "clap doc comment — use \"ContextCrawler equivalent\" (branding sweep round 3)"),
    ("RTK artifacts", "clap doc comment — use \"ContextCrawler artifacts\" (branding sweep round 3)"),
    ("RTK and native", "clap doc comment — use \"ContextCrawler and native\" (branding sweep round 3)"),
    ("(rtk)", "in-line attribution — use \"(contextcrawler)\" (branding sweep round 3)"),
    // The clap example `$(rtk rewrite ...)` in help text was rebranded
    // alongside the rewrite docstring; pin to prevent re-introduction.
    ("$(rtk ", "shell example in clap docs — use \"$(contextcrawler\" (branding sweep round 3)"),
    ("`rtk rewrite", "CLI example in clap docs — use \"`contextcrawler rewrite\" (branding sweep round 3)"),
    ("rtk find:", "find filter error prefix — use \"contextcrawler find:\" (branding sweep round 3)"),
    // NOTE: `format!("rtk ...")` literals inside `rewrite_command` are
    // INTENTIONAL — they're the rewritten-command strings the hook
    // executes, and the hook caller historically expects the `rtk` prefix.
    // Changing them is a correctness-tier scope (separate issue, not
    // branding). Tracking labels stored in the SQLite DB also stay `rtk `
    // prefixed to preserve historical analytics. Both categories are NOT
    // in FORBIDDEN_TOKENS to avoid false positives on legitimate output.
];

/// Per-line allowlist marker. A line ending with this comment is exempt.
const ALLOW_MARKER: &str = "// branding-lint: allow legacy";

/// Substrings that, if present on the line being scanned, exempt that line.
/// Use for short structural references (variable names, history comments)
/// that don't justify a per-line marker.
///
/// The history-comment exemptions below are restricted to **comment lines
/// only** (lines whose trimmed text starts with `//`) — a non-comment line
/// containing both `[rtk]` AND `issue #19` should still fail the lint
/// instead of slipping through (codex P3 catch on the introduction of the
/// config-file pin test).
const STRUCTURAL_ALLOW_NEEDLES_ANYWHERE: &[&str] = &[
    "LEGACY_RTK_MD_FILES", // the registry itself — appears in declarations, not comments
];

/// Same idea but only exempts the line if it's a comment. Catches the
/// regression-history references in `src/hooks/init.rs` without weakening
/// the lint for production code that incidentally mentions the issue
/// number.
const STRUCTURAL_ALLOW_NEEDLES_IN_COMMENTS_ONLY: &[&str] = &[
    "issue #19",
    "see issue #19",
    "see #19",
    "bcddd06", // the offending commit hash mentioned in history comments
];

/// Function-name prefixes whose entire body is exempt from the lint. Use
/// for tests/helpers that deliberately operate on the legacy filename and
/// would be tedious to mark line-by-line. The lint detects function
/// boundaries by tracking brace depth starting from the `fn` declaration.
const ALLOWED_FUNCTION_PREFIXES: &[&str] = &[
    "fn test_cleanup_legacy_codex_files_",
    "fn test_uninstall_codex_at_removes_legacy_rtk_md_file_and_ref",
    "fn test_patch_claude_md_migrates_legacy_at_ref_in_place",
    "fn test_strip_at_reference_line_collapses_surrounding_blanks",
    "fn test_rtk_md_constant_pinned_to_contextcrawler_filename",
];

/// Top-level entries (file path prefixes) that are skipped entirely. Keep
/// this list tiny — preferring per-line markers over bulk exemptions.
const SKIPPED_PATHS: &[&str] = &[
    // The branding-lint test itself reads forbidden tokens as data.
    "tests/branding_lint.rs",
];

#[test]
fn branding_lint_no_forbidden_upstream_literals_in_src() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = repo_root.join("src");

    let mut failures: Vec<String> = Vec::new();

    for entry in WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|s| s == "rs")
                .unwrap_or(false)
        })
    {
        let rel = entry
            .path()
            .strip_prefix(&repo_root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();

        if SKIPPED_PATHS.iter().any(|s| rel == *s) {
            continue;
        }

        let content = fs::read_to_string(entry.path())
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", rel, e));

        // Track which lines fall inside an allowed-function body. Simple
        // brace-depth tracking starting from the `fn` declaration: enter
        // when we see one of ALLOWED_FUNCTION_PREFIXES on the line; exit
        // when net brace count returns to 0.
        let mut in_allowed_fn = false;
        let mut allowed_fn_depth: i64 = 0;

        for (lineno, line) in content.lines().enumerate() {
            let lineno = lineno + 1;

            // Update brace-depth state BEFORE evaluating the line so that
            // the `fn` declaration line itself is treated as "inside".
            if !in_allowed_fn
                && ALLOWED_FUNCTION_PREFIXES.iter().any(|p| line.contains(p))
            {
                in_allowed_fn = true;
                allowed_fn_depth = 0;
            }
            if in_allowed_fn {
                let opens = line.chars().filter(|c| *c == '{').count() as i64;
                let closes = line.chars().filter(|c| *c == '}').count() as i64;
                allowed_fn_depth += opens - closes;
                // We exit on the line whose closes bring depth back to 0,
                // but the closing-brace line itself stays exempt.
                let exit_this_line = allowed_fn_depth <= 0 && (opens + closes) > 0;
                let was_in = in_allowed_fn;
                if exit_this_line {
                    in_allowed_fn = false;
                    allowed_fn_depth = 0;
                }
                if was_in {
                    continue;
                }
            }

            if line.contains(ALLOW_MARKER) {
                continue;
            }
            if STRUCTURAL_ALLOW_NEEDLES_ANYWHERE
                .iter()
                .any(|n| line.contains(n))
            {
                continue;
            }
            // Comment-only exemptions: only applied if the line is a
            // comment. Prevents bypass via "production code that happens
            // to mention issue #19".
            let is_comment_line = line.trim_start().starts_with("//");
            if is_comment_line
                && STRUCTURAL_ALLOW_NEEDLES_IN_COMMENTS_ONLY
                    .iter()
                    .any(|n| line.contains(n))
            {
                continue;
            }

            for (needle, why) in FORBIDDEN_TOKENS {
                if line.contains(needle) {
                    failures.push(format!(
                        "  {}:{}  found `{}`  ({})\n      {}",
                        rel,
                        lineno,
                        needle,
                        why,
                        line.trim()
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "\n\n--- branding-lint failures ---\n\
             {} forbidden upstream literal(s) found in production source:\n\n{}\n\n\
             FIX: replace each occurrence with the CONTEXTCRAWLER equivalent\n\
             (constants RTK_MD, RTK_MD_REF in src/hooks/init.rs), or — if the\n\
             reference is intentionally legacy (regression history, cleanup\n\
             code, migration tests) — add `{}` to the end of the line.\n\n\
             This test exists to prevent the rebrand-regression family\n\
             (issues #19, #20, #22, #23) from re-introducing itself silently\n\
             during future upstream rebases.\n",
            failures.len(),
            failures.join("\n\n"),
            ALLOW_MARKER,
        );
    }
}

#[test]
fn branding_lint_canonical_name_present_in_init() {
    // Sanity that the canonical name actually appears where it should, to
    // catch the inverse mistake: someone rips out all "CONTEXTCRAWLER.md"
    // references without re-adding them via the constant. This isn't a
    // perfect check but it costs nothing.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/hooks/init.rs");
    let content = fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("CONTEXTCRAWLER.md"),
        "src/hooks/init.rs no longer mentions CONTEXTCRAWLER.md anywhere — \
         did the rebrand get inverted again?"
    );
    assert!(
        content.contains("@CONTEXTCRAWLER.md"),
        "src/hooks/init.rs no longer mentions @CONTEXTCRAWLER.md — \
         same regression family as #19."
    );
}

#[test]
fn branding_lint_config_files_pin_canonical_package_name() {
    // Config files outside src/ — Cargo.toml's [package].name field and
    // release-please-config.json's "package-name" — also need to read
    // "contextcrawler", not "rtk". The upstream rebase silently set
    // release-please-config.json's package-name back to "rtk", which would
    // have produced rtk-vX.Y.Z tags + release-PR titles. The src/-scoped
    // lint above doesn't cover the build/release-engineering surface, so
    // this extra check pins those two fields explicitly.

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Cargo.toml [package].name — extract via simple line scan to avoid
    // pulling in a TOML parser dependency just for one assertion.
    let cargo = fs::read_to_string(repo_root.join("Cargo.toml"))
        .expect("Cargo.toml readable");
    let mut in_package = false;
    let mut found_name: Option<String> = None;
    for line in cargo.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package && t.starts_with("name") {
            if let Some(eq) = t.find('=') {
                let value = t[eq + 1..].trim().trim_matches('"').to_string();
                found_name = Some(value);
                break;
            }
        }
    }
    assert_eq!(
        found_name.as_deref(),
        Some("contextcrawler"),
        "Cargo.toml [package].name must be \"contextcrawler\" — \
         see issue #19 family."
    );

    // release-please-config.json package-name field. serde_json is already
    // a workspace dep so no new dependency cost.
    let rp = fs::read_to_string(repo_root.join("release-please-config.json"))
        .expect("release-please-config.json readable");
    let parsed: serde_json::Value =
        serde_json::from_str(&rp).expect("release-please-config.json is valid JSON");
    let pkg_name = parsed
        .pointer("/packages/./package-name")
        .and_then(|v| v.as_str());
    assert_eq!(
        pkg_name,
        Some("contextcrawler"),
        "release-please-config.json packages[\".\"].package-name must be \
         \"contextcrawler\" — caught silently set to \"rtk\" by the \
         upstream rebase. Same regression family as #19/#20/#22."
    );
}

// =====================================================================
// Allowlist-style branding scan — issue #67
// =====================================================================
//
// The `FORBIDDEN_TOKENS` test above is regression-style: each row is a known
// leak class. Across the v0.1.8 → v0.1.9 cycle that approach missed 3 leak
// classes (init message, error prefixes, clap help docs) that only surfaced
// via user reports, requiring 3 separate hotfix rounds.
//
// The test below is **allowlist-style**: it scans every `.rs` file under
// `src/` for ANY case-insensitive `\brtk\b` reference and FAILS unless the
// match is explained by an explicit allowlist rule. Future leaks fail at
// test time, not user-report time.
//
// Adding a new allowlist category is one entry in `ALLOWLIST_RULES`. Adding
// a real leak class to the regression-style backstop is one entry in
// `FORBIDDEN_TOKENS`. The two tests are complementary: this one stops new
// leak classes from slipping through silently; `FORBIDDEN_TOKENS` pins the
// specific phrasings of leaks we've already seen so a sloppy allowlist can't
// re-let-them-in.

/// A single allowlist rule. `name` shows up in failure messages so a future
/// editor can see exactly which rule a match was attributed to (and audit
/// whether the rule is too broad).
struct AllowlistRule {
    name: &'static str,
    /// Returns `true` if the (line, file path) is exempt under this rule.
    /// Receives the raw line and the repo-relative file path so per-file
    /// rules (e.g. test fixtures, registry tracking labels) can scope
    /// themselves narrowly.
    matches: fn(line: &str, rel_path: &str) -> bool,
}

lazy_static! {
    /// The bare `\brtk\b` finder. Case-insensitive. Used both to decide
    /// whether a line needs to be vetted at all, and to extract the
    /// offending substring for failure messages.
    static ref RTK_WORD_RE: Regex = Regex::new(r"(?i)\brtk\b").unwrap();

    /// Anchor for env-var-shape identifiers: `RTK_FOO`, `RTK_BAR_BAZ`. We
    /// allow ANY `RTK_*` identifier (uppercase + underscores + digits) on
    /// the principle that these are programmatic interfaces — renaming
    /// them breaks user configs / shell history / CI scripts.
    static ref RTK_ENVISH_RE: Regex = Regex::new(r"\bRTK_[A-Z0-9_]+\b").unwrap();

    /// Filesystem-path needles. Each one is an intentional cross-fork
    /// layout decision (config dirs, hook script names, DB file names).
    /// We accept these anywhere they appear because filenames are the
    /// only way users locate them on disk.
    static ref PATH_NEEDLES: Vec<&'static str> = vec![
        ".rtk/",                              // project-local filter dir
        "~/.rtk/",                            // home-config alt
        "/Library/Application Support/rtk/",  // macOS app-support dir
        "rtk/config.toml",                    // XDG config file
        "rtk/filters.toml",                   // XDG filters file
        "rtk/tracking.db",                    // tracking DB
        "rtk/history.db",                     // history DB
        "rtk/tee/",                           // tee output dir
        ".local/share/rtk",                   // Linux data dir
        "/tmp/rtk-tee",                       // tee default dir literal
        "rtk-tee",                            // tee dir basename
        "rtk-rewrite.sh",                     // installed hook script
        "rtk-rewrite.json",                   // claude / cursor hook entry
        "rtk-rewrite/",                       // hermes/opencode plugin dir
        "rtk-hook.sh",                        // gemini hook script
        "rtk-awareness.md",                   // bundled awareness doc
        "rtk-rules.md",                       // bundled rules doc
        "antigravity-rtk-rules.md",           // antigravity rules variant
        ".rtk-hook.sha256",                   // hook integrity sidecar
        "# rtk-hook-version:",                // hook script version marker
        "<!-- rtk-instructions",              // RTK_BLOCK_START sentinel
        "<!-- /rtk-instructions",             // RTK_BLOCK_END sentinel
        "rtk-instructions block",             // user-facing log of the same
        "rtk-instructions -->",               // RTK_BLOCK_END sentinel (alt)
        "/Cellar/rtk/",                       // homebrew install path
        "-rtk/bin/rtk",                       // nix-store install path
        ".cargo/bin/rtk",                     // cargo install path
        "Program Files\\rtk\\rtk.exe",        // windows install path
        "Program Files\\\\rtk\\\\rtk.exe",    // windows install path (source-escaped)
        "\\rtk\\rtk.exe",                     // windows install path (escaped)
        "\\\\rtk\\\\rtk.exe",                 // windows install path (source-escaped)
        "Files\\\\rtk",                       // windows path fragment (source-escaped)
        ".join(\"rtk\")",                     // PathBuf::join(\"rtk\") for install/data dirs
        ".join(\"rtk-",                       // PathBuf::join(\"rtk-something\")
        ".device_salt",                       // anchored alongside join("rtk")
        "rtk-rewrite",                        // hermes plugin name (manifest, settings)
    ];

    /// Upstream-attribution needles. We retain attribution to the upstream
    /// project (rtk-ai/rtk) per the downstream-fork honest-attribution
    /// guidelines.
    static ref ATTRIBUTION_NEEDLES: Vec<&'static str> = vec![
        "rtk-ai/rtk",
        "rtk-ai.app",
        "RTK AI Labs",
        "github.com/rtk-ai",
        "Sites/rtk",         // appears in a single ClaudeProvider unit-test path
    ];

    /// Tracking-label literals: `"rtk <cmd> ..."` strings passed into
    /// `tracker.track(...)`, `timer.track(...)`, or `format!("rtk ...")`
    /// builders. These are persisted to the SQLite `rtk_cmd` column in
    /// `history.db` — renaming them silently fragments historical
    /// analytics. The hook caller in `src/discover/registry.rs` ALSO
    /// emits rewritten command strings prefixed `rtk ` because the hook
    /// contract is that argv[0] stays `rtk` (see #62 for the open scope
    /// decision on whether to rename).
    ///
    /// Tracking-label / command-string literal patterns. The unifying
    /// invariant: the literal is a SHELL COMMAND STRING shaped like
    /// `"rtk <subcommand> ..."` and appears in a position where it's
    /// being passed as data to another function — never as the body of
    /// a `print!` / `eprintln!` / `panic!` etc. (those are caught by
    /// the leak self-test).
    ///
    /// Specific shapes we accept:
    ///   - `format!("rtk ...", ...)` — tracking-label builder
    ///   - `"rtk ...".into()` / `"rtk ...".to_string()` — registry
    ///     rewrite-expectation return shapes
    ///   - `rtk_cmd: "rtk ..."` / `rtk_equivalent: "rtk ..."` — struct
    ///     field initializers
    ///   - `("...", "rtk ...")` — second-arg tracking-label position
    ///   - `assert_eq!(..., "rtk ...")` and `assert_eq!(x, "rtk ...")` —
    ///     unit-test round-trip expectations on tracking labels
    ///   - `(..., "rtk ...", ...)` — function-arg position
    ///   - `== "rtk ..."` / `!= "rtk ..."` — comparisons against
    ///     tracking labels (matches `if rule.rtk_cmd == "rtk gh"`)
    ///   - `.starts_with("rtk ")` / `.strip_prefix("rtk ")` — adoption
    ///     detection of rtk-prefixed commands
    ///   - `&["rtk ", ...]` / `&[..., "rtk "]` — STARTS_WITH_PATTERNS
    ///     literal arrays for adoption detection
    ///
    /// Crucially this rule REJECTS plain `eprintln!("Run: rtk init -g")`
    /// — user-visible help/error text. Those have to either fix the leak
    /// or use the per-line allow marker. The self-test below verifies.
    static ref TRACKING_LABEL_RES: Vec<Regex> = vec![
        // `format!("rtk ...", ...)`. Also accepts `format!("rtk:toml ...")`
        // and similar tracking-label prefixes used as namespaces (rtk:toml,
        // rtk:DEGRADED, etc).
        Regex::new(r#"\bformat!\(\s*"rtk[ ":]"#).unwrap(),
        // `"rtk ...".into()` / `.to_string()` anywhere on the line
        Regex::new(r#""rtk[ ][^"]*"\s*\.(?:into|to_string|to_owned)\(\)"#).unwrap(),
        // `"rtk"` itself (no trailing space) `.into()` / `.to_string()`
        Regex::new(r#""rtk"\s*\.(?:into|to_string|to_owned)\(\)"#).unwrap(),
        // field initializer: `rtk_cmd: "rtk ..."`, `rtk_equivalent: "rtk ..."`
        Regex::new(r#"\brtk_(?:cmd|equivalent)\s*:\s*"rtk[ "]"#).unwrap(),
        // comparison: `== "rtk ..."` / `!= "rtk ..."`
        Regex::new(r#"[!=]=\s*"rtk[ "]"#).unwrap(),
        // method-call detection: `.starts_with("rtk")` / `.strip_prefix("rtk")` /
        // `.contains("rtk")` / `.ends_with("rtk")` — these all check the
        // command stream for rtk-prefixed commands.
        Regex::new(r#"\.(?:starts_with|strip_prefix|ends_with|contains|eq)\(\s*"rtk[ "]?"#).unwrap(),
        // function-arg position: `(..., "rtk ...", ...)` or `(..., "rtk ...")`.
        // Requires the preceding token to be `(` or `,` and the following to
        // be `,`, `)`, `]`, or whitespace.
        Regex::new(r#"[(,]\s*"rtk[ ][^"]*""#).unwrap(),
        // standalone `&["rtk "]` or `["rtk ", ...]` array element
        Regex::new(r#"[\[&]\s*"rtk\s?"\s*[,\]]"#).unwrap(),
        // line-leading `"rtk ..."` continuation (multi-line `format!` /
        // `track(...)` calls where each arg is on its own line)
        Regex::new(r#"^\s*&?"rtk[ "][^"]*"\s*,?\s*$"#).unwrap(),
        // line-leading `"rtk ..."` followed by `.into()` / `.to_string()`
        Regex::new(r#"^\s*&?"rtk[ "][^"]*"\s*\.(?:into|to_string|to_owned)"#).unwrap(),
        // multi-line CLI-parse continuation: `    "rtk", "pnpm", ...` —
        // first array elem on the line is the rtk argv[0] literal.
        Regex::new(r#"^\s*"rtk"\s*,"#).unwrap(),
        // command-string registry rewrite-expectations where the rtk
        // token appears mid-string and the literal ends with `.into()` /
        // `.to_string()`. Matches `"sudo rtk docker ps".into()`,
        // `"noglob rtk git status".into()`, etc.
        Regex::new(r#""[^"]*\brtk\b[^"]*"\s*\.(?:into|to_string|to_owned)\(\)"#).unwrap(),
        // command-string in function arg with internal rtk:
        // `classify_command("cargo install rtk")`,
        // `rewrite_command_no_prefixes("cargo install rtk", ...)`.
        // Restricted to single-quoted-string args of `classify_command`
        // / `rewrite_command_no_prefixes` / `rewrite_command` —
        // registry test entry points.
        Regex::new(r#"\b(?:classify_command|rewrite_command_no_prefixes|rewrite_command)\(\s*&?"[^"]*\brtk\b[^"]*""#).unwrap(),
        // `"command": "rtk ..."` — JSON literal value (hook protocol).
        Regex::new(r#""command"\s*:\s*"rtk[ "]"#).unwrap(),
        // Assertion-message strings inside `assert!(_, "RTK-... ...")` —
        // narrow to "RTK-" prefix to avoid catching arbitrary asserts.
        Regex::new(r#"\bassert!?\([^)]*,\s*"RTK[-_ ]"#).unwrap(),
    ];

    /// Hook-rewrite output strings: the registry's `rewrite_command_no_prefixes`
    /// and friends produce hook-output strings shaped like
    /// `"VAR=val rtk <cmd> ..."` (env-prefix preserved) or
    /// `"cd \"...\" && rtk <cmd>"` (chain-preserved). These are the
    /// hook-contract literals exchanged with the Claude Code hook caller
    /// — argv[0]=`rtk` is required by the existing contract (see #62).
    static ref HOOK_REWRITE_OUTPUT_RES: Vec<Regex> = vec![
        // env-prefix + rtk: `"FOO=bar rtk git status"`, `"FOO='val with spaces' rtk git ..."`
        Regex::new(r#""[A-Z_][A-Z0-9_]*=[^"]*\brtk\b[^"]*""#).unwrap(),
        // chain-preserving: `&& rtk`, `|| rtk`, `| rtk`, `; rtk`
        Regex::new(r#""[^"]*(?:&&|\|\||;)\s*rtk\b[^"]*""#).unwrap(),
        // command-name-then-rtk: `"command rtk git status"`,
        // `"shadowenv exec -- rtk cargo test"`
        Regex::new(r#""[^"]*\b(?:command|shadowenv\s+exec\s+--|exec)\s+rtk\b[^"]*""#).unwrap(),
        // `cd "/tmp" && rtk git ...` (escaped quotes inside)
        Regex::new(r#""cd \\?\"[^"]*\\?\"\s*&&\s*rtk\b"#).unwrap(),
        // Pipe-table audit log lines: `| rewrite | git status | rtk git status`
        Regex::new(r#"\|\s*rtk\s+[a-z]"#).unwrap(),
    ];

    /// Test-fixture argv[0] in CLI parsing tests: `vec!["rtk", ...]`,
    /// `&["rtk", ...]`, `Cli::try_parse_from(["rtk", ...])`, or a
    /// standalone `"rtk".into(),` / `"rtk",` line inside a multi-line
    /// vec literal. Clap ignores argv[0] so the literal is just
    /// convention; renaming the test fixture argv is churn for no
    /// behavior change.
    static ref CLI_ARGV_RE: Regex =
        Regex::new(r#"(?:[\[&]\s*"rtk"[,\s\]]|^\s*"rtk"(?:\.into\(\))?\s*,\s*$|^\s*"rtk"\s*\.into\(\)\s*,?\s*$)"#).unwrap();

    /// `let rtk = ...`, `rtk: String`, `rtk.push_str(...)`, etc — module-
    /// internal variable/field names. These are NOT user-visible.
    ///
    /// The patterns use `(?:^|[^"\w])` lookbehind-equivalent to make sure
    /// we don't match `rtk` that's the FIRST char of a string literal
    /// (which would let `"rtk: error message"` falsely pass as a binding).
    static ref IDENT_BINDING_RE: Regex =
        Regex::new(r#"\b(?:let|mut|ref|fn|struct|enum|trait|impl|use|mod|pub|const|static)\s+[^"]*\brtk\b|(?:^|[^"\w])rtk\s*[:.,)]|(?:^|[^"\w])rtk\s*\+?=|\.rtk\b|(?:^|[^"\w])rtk\.push_str|(?:^|[^"\w])rtk\.push\b|for\s+\w+\s+in\s+rtk\b|\((?:&\s*)?rtk\)|,\s*rtk\s*[,)]|=\s*rtk\b"#).unwrap();

    /// Identifiers / constants / type names that have `RTK` or `rtk` as a
    /// sub-token: `RTK_MD`, `LEGACY_RTK_MD_FILES`, `RtkBlockUpsert`,
    /// `rtk_cmd`, `rtk_equivalent`. These are program identifiers, not
    /// user-visible strings.
    ///
    /// Each pattern REQUIRES adjacent identifier glue (`_X`, `X_`, `xYz`)
    /// so a standalone `RTK` token (which would just be a user-visible
    /// word) is NOT matched and has to clear a different rule.
    static ref IDENT_TOKEN_RE: Regex =
        Regex::new(r"\b(?:[A-Z][A-Za-z0-9]*Rtk[A-Za-z0-9_]*|[A-Z][A-Z0-9_]*_RTK[A-Z0-9_]*|RTK_[A-Z0-9_]+|[a-z][a-z0-9_]*_rtk[a-z0-9_]*|rtk_[a-z0-9_]+)\b").unwrap();

    /// Hook-output JSON / hook-protocol literals. These are part of the
    /// over-the-wire contract with Claude Code and other agents.
    static ref HOOK_PROTOCOL_NEEDLES: Vec<&'static str> = vec![
        "Blocked by RTK permission rule",  // JSON "reason" field
        "RTK auto-rewrite",                // permissionDecisionReason
        "[RTK:PASSTHROUGH]",               // parser passthrough marker
        "[RTK:DEGRADED]",                  // parser degraded marker
        "RTK Learn",                       // learn-mode header
        "rtk learn",                       // learn-mode CLI name in self-ref docs
        "[rtk hook]",                      // hook stderr-log prefix
        "X-RTK-Token",                     // telemetry HTTP header name
        "RTK_TELEMETRY_TOKEN",             // env-var; also matches RTK_ENVISH_RE
    ];

    /// Known unbranded-text debt: user-visible strings that still mention
    /// `RTK` and need to be rebranded to `ContextCrawler` in a future
    /// sweep. Listed explicitly here so a NEW user-visible string class
    /// can't sneak in under the same rule — the existing surface is
    /// finite and enumerated; novel phrasings fail and have to be either
    /// fixed or added explicitly.
    ///
    /// This list is technical debt. See coordinator report for
    /// per-file leak-class breakdown.
    static ref KNOWN_UNBRANDED_TEXT_NEEDLES: Vec<&'static str> = vec![
        // src/discover/report.rs — `discover` report headlines (rebranded
        // 2026-05-19, #76); only the short column header remains in this list.
        "\"RTK Equivalent\"",     // table header in format! string (column width-constrained)
        // src/analytics/cc_economics.rs — short column header where width matters.
        "\"RTK Cmds\"",           // table column header (column width-constrained)
        // src/hooks/init.rs — uninstall flow messages.
        "RTK (Cursor):",
        "RTK (Gemini):",
        "RTK was not installed",
        "would uninstall RTK",
        "RTK from CLAUDE.md",
        "RTK from AGENTS.md",
        "RTK for Codex CLI",
        "RTK for Hermes CLI",
        "removed RTK plugin entry",
        "RTK end marker must be removed",
        "Rules file should reference the rewrite tool (RTK or ContextCrawler brand)",
        // src/core/telemetry_cmd.rs — telemetry interactive prompt.
        "RTK collects anonymous usage metrics",
        // src/cmds/git/git.rs — diff-truncation recovery hint (user-visible).
        "[full diff: rtk git diff --no-compact]",
        // src/cmds/cloud/container.rs — Usage hints.
        "Usage: rtk docker logs",
        "Usage: rtk kubectl logs",
        // src/main.rs — Usage / error hints.
        "Usage: rtk proxy",
        "Use: rtk init --agent kilocode",
        "Use: rtk init --agent antigravity",
        // src/hooks/integrity.rs — verify/restore advice.
        "To restore:  rtk init -g",
        "To inspect:  rtk verify",
        // src/core/tracking.rs — assert message comparing rtk_cmd values.
        "r.rtk_cmd == ",
        // src/hooks/init.rs — fixture content & search-strings on hook scripts.
        "command -v rtk",
        // Test-only fixture plugin content — `fs::write(_, "rtk")`.
        // (kept here because the IDENT scope of `"rtk"` is ambiguous —
        // is it argv[0]? is it fixture content? — and either reading is
        // intentional in init.rs tests.)
        "fs::write(&nested_plugin_file, \"rtk\")",
        // src/core/telemetry.rs — XDG path joined dynamically.
        "config_dir.join(\"rtk/filters\")",
        "config_dir.join(\"rtk\")",
        // src/cmds/system/read.rs — test diagnostics referencing the
        // binary by its rtk-compatible install name.
        "rtk_nonexistent_file",
        "failed to run rtk read",
        "failed to run rtk",
        "Failed to run rtk",
        // src/cmds/rust/cargo_cmd.rs — format_crate_info round-trip test
        // with rtk-as-package-name.
        "format_crate_info(\"rtk\"",
        // src/cmds/git/git.rs — branch-name fixture.
        "test-rtk-create-",
        // src/discover/provider.rs — project-filter fixture.
        "-Users-test-rtk",
        "Some(\"rtk\")",
        // src/hooks/constants.rs — bundled hook script filenames are
        // also covered by PATH_NEEDLES but listed here for the comment.
        "rtk-rewrite.sh",
        "rtk-hook-gemini.sh",
        "rtk hook claude",      // LEGACY_CLAUDE_HOOK_COMMAND
        "rtk hook cursor",      // LEGACY_CURSOR_HOOK_COMMAND
        "rtk.ts",               // OpenCode plugin filename
        // src/cmds/git/git.rs — RTK-default assert message.
        "\"RTK-default limit",
        // src/analytics/session_cmd.rs — column header.
        "\"RTK\", \"Adoption\"",
        // src/hooks/hook_cmd.rs — JSON fixture in json! macro.
        "\"command\": \"rtk git status\"",
    ];

    /// Raw-string tracking-label tests in registry.rs — these are single-
    /// line raw-string literals shaped like
    /// `Some(r#"GIT_SSH_COMMAND="ssh ..." rtk git push"#.into())`. Allow
    /// them when the raw-string ends with `.into()` / `.to_string()`.
    /// Pattern: `r#"...rtk...`"#`.into()|.to_string()`. The `.*?`
    /// (non-greedy any-char including internal `"`) is safe here because
    /// raw strings can contain internal quotes — Rust closes the raw
    /// string only on `"#`.
    static ref RAW_STRING_TRACKING_RE: Regex =
        Regex::new("r#\".*?\\brtk\\b.*?\"#\\s*\\.(?:into|to_string)").unwrap();

    /// Doc-comment-only references: cargo-doc `///` examples mentioning
    /// the legacy `rtk::` crate path or `rtk init`/`rtk gain` etc. We
    /// retain these because they document the upstream-compatible alias
    /// (the binary is still installable as `rtk` for fork compatibility).
    static ref DOC_EXAMPLE_NEEDLES: Vec<&'static str> = vec![
        "rtk::",                // crate path in `/// use rtk::xxx;` examples
    ];
}

/// Allowlist categories, in priority order. The first rule that matches
/// claims credit for the line. Adding a new category is one entry.
const ALLOWLIST_RULES: &[AllowlistRule] = &[
    AllowlistRule {
        name: "filesystem-path",
        matches: |line, _| PATH_NEEDLES.iter().any(|n| line.contains(n)),
    },
    AllowlistRule {
        name: "env-var-shape (RTK_*)",
        matches: |line, _| RTK_ENVISH_RE.is_match(line),
    },
    AllowlistRule {
        name: "upstream-attribution",
        matches: |line, _| ATTRIBUTION_NEEDLES.iter().any(|n| line.contains(n)),
    },
    AllowlistRule {
        name: "hook-protocol-literal",
        matches: |line, _| HOOK_PROTOCOL_NEEDLES.iter().any(|n| line.contains(n)),
    },
    AllowlistRule {
        name: "test-fixture-argv0",
        matches: |line, _| CLI_ARGV_RE.is_match(line),
    },
    AllowlistRule {
        name: "tracking-label-string (rtk_cmd DB column / registry expectation)",
        matches: |line, _| TRACKING_LABEL_RES.iter().any(|re| re.is_match(line)),
    },
    AllowlistRule {
        name: "hook-rewrite-output-literal (env-prefix / chain-preserve)",
        matches: |line, _| HOOK_REWRITE_OUTPUT_RES.iter().any(|re| re.is_match(line)),
    },
    AllowlistRule {
        name: "raw-string-tracking-literal (Some(r#\"... rtk ...\"#.into()))",
        matches: |line, _| RAW_STRING_TRACKING_RE.is_match(line),
    },
    AllowlistRule {
        // Explicit enumeration of known-incomplete-rebrand strings so
        // future NEW user-visible RTK leaks fail loudly. Adding a new
        // entry here is intentional rebrand-debt acknowledgement — the
        // reviewer should ask "why isn't this just fixed?".
        name: "known-unbranded-text-debt (cleanup-tracked; see #67 report)",
        matches: |line, _| {
            KNOWN_UNBRANDED_TEXT_NEEDLES.iter().any(|n| line.contains(n))
        },
    },
    AllowlistRule {
        name: "doc-comment-example (/// use rtk::...)",
        matches: |line, _| {
            let trimmed = line.trim_start();
            (trimmed.starts_with("///") || trimmed.starts_with("//!"))
                && DOC_EXAMPLE_NEEDLES.iter().any(|n| line.contains(n))
        },
    },
    AllowlistRule {
        name: "module-internal-identifier",
        matches: |line, _| {
            // Lines whose ONLY rtk references are identifier-shaped tokens
            // (let rtk=, rtk_cmd:, RtkBlockUpsert, etc) are exempt. We
            // verify by stripping identifier-shaped matches and trailing
            // line comments, then re-checking for bare `\brtk\b`.
            //
            // We deliberately do NOT strip the contents of string
            // literals here — those have to clear a separate, narrower
            // string-shaped rule (TRACKING_LABEL_RES, HOOK_REWRITE_OUTPUT_RES,
            // PATH_NEEDLES, CLI_ARGV_RE, HOOK_PROTOCOL_NEEDLES). If we
            // stripped strings here, `eprintln!("Run: rtk init -g")` would
            // pass this rule and the leak would slip through silently.
            let no_trailing_comment = strip_trailing_line_comment(line);
            let stripped = IDENT_TOKEN_RE.replace_all(&no_trailing_comment, "");
            let stripped = IDENT_BINDING_RE.replace_all(&stripped, "");
            !RTK_WORD_RE.is_match(&stripped)
        },
    },
    AllowlistRule {
        name: "per-line allow marker (// branding-lint: allow legacy)",
        matches: |line, _| line.contains(ALLOW_MARKER),
    },
    AllowlistRule {
        name: "structural-needle (LEGACY_RTK_MD_FILES, etc)",
        matches: |line, _| {
            STRUCTURAL_ALLOW_NEEDLES_ANYWHERE.iter().any(|n| line.contains(n))
        },
    },
    AllowlistRule {
        name: "history-comment (issue-# / commit-hash references)",
        matches: |line, _| {
            let trimmed = line.trim_start();
            (trimmed.starts_with("//") || trimmed.starts_with("///")
                || trimmed.starts_with("//!"))
                && STRUCTURAL_ALLOW_NEEDLES_IN_COMMENTS_ONLY
                    .iter()
                    .any(|n| line.contains(n))
        },
    },
    AllowlistRule {
        name: "internal-comment mention (// or //!)",
        matches: |line, _| {
            // Free-form mentions in INTERNAL comments (// implementation
            // notes, //! module-level docs) are allowed — the
            // FORBIDDEN_TOKENS regression list above pins specific
            // user-visible phrasings that ever leaked, so comments can't
            // reintroduce those without also tripping that test.
            let trimmed = line.trim_start();
            (trimmed.starts_with("//") || trimmed.starts_with("//!"))
                && !trimmed.starts_with("///")
        },
    },
    AllowlistRule {
        // Cargo-doc / rustdoc comments. CAUTION: `///` immediately above
        // a clap `#[derive(Parser)]` field leaks into `--help` output —
        // that's user-visible. The FORBIDDEN_TOKENS regression list
        // above pins the SPECIFIC phrasings of help-leak strings we've
        // already seen (`RTK savings`, `RTK adoption`, etc.) so that
        // those literal phrases can't be re-introduced silently. But
        // novel `///` doc-comment phrasings on clap fields WILL slip
        // through this allowlist — the trade-off is that we accept
        // 100+ legitimate rustdoc mentions of the project name in
        // exchange for not requiring per-line markers on every one.
        // If a clap-help leak DOES recur, add the specific phrasing
        // to FORBIDDEN_TOKENS above.
        name: "rustdoc-comment mention (///) [clap-help leak risk — see FORBIDDEN_TOKENS]",
        matches: |line, _| line.trim_start().starts_with("///"),
    },
    AllowlistRule {
        name: "test-only fixture text",
        matches: |line, rel_path| {
            // Test fixtures embedded as raw string literals (e.g. cargo
            // test output containing `Compiling rtk v0.5.0`, README
            // markdown containing `rtk-ai/rtk` badges) and test-only
            // assertions on those fixtures. Only allowed in files that
            // contain test code AND inside a likely fixture context
            // (raw-string r#"..."#, multi-line string with rtk-as-crate-
            // name pattern, or an assert/format check). Scoped narrowly
            // by file path to limit collateral.
            let is_test_file = rel_path.contains("/tests/")
                || rel_path.ends_with("_test.rs")
                || rel_path.ends_with("_cmd.rs")
                || rel_path.ends_with("/git.rs")
                || rel_path.ends_with("/ls.rs")
                || rel_path.ends_with("/read.rs")
                || rel_path.ends_with("/registry.rs")
                || rel_path.ends_with("/provider.rs")
                || rel_path.ends_with("/init.rs")
                || rel_path.ends_with("/integrity.rs")
                || rel_path.ends_with("/hook_cmd.rs")
                || rel_path.ends_with("/hook_audit_cmd.rs")
                || rel_path.ends_with("/rewrite_cmd.rs")
                || rel_path.ends_with("/parser/mod.rs")
                || rel_path.ends_with("/tracking.rs")
                || rel_path.ends_with("/telemetry.rs")
                || rel_path.ends_with("/runner.rs")
                || rel_path.ends_with("/session_cmd.rs")
                || rel_path.ends_with("/cc_economics.rs")
                || rel_path.ends_with("/gain.rs")
                || rel_path.ends_with("/main.rs");
            if !is_test_file {
                return false;
            }
            // Heuristics for fixture-flavoured lines:
            //   - `Compiling rtk v...`, `Installing rtk v...`, `Checking rtk v...`
            //   - `rtk v0.x.y` standalone version mentions
            //   - `.contains("rtk")` / `.contains("rtk ...")` assertions
            //   - `assert_eq!(... "rtk ...")` test expectations
            //   - `.starts_with("rtk ")` / `.strip_prefix("rtk ")`
            //   - shell-snippet lines mixing `rtk` with `&&` / `||` / `|`
            //     (the registry rewrite-expectation strings)
            //   - `==> name <==` / `Doc-tests rtk` / `bin/rtk` cargo banners
            line.contains("Compiling rtk v")
                || line.contains("Installing rtk v")
                || line.contains("Checking rtk v")
                || line.contains("Replaced package `rtk")
                || line.contains("`rtk` (bin)")
                || line.contains("bin/rtk")
                || line.contains("Doc-tests rtk")
                || line.contains("/tmp/rtk-")
                || line.contains("/tmp/rtk/")
                || line.contains("rtk_dotnet_")
                || line.contains(".contains(\"rtk")
                || line.contains(".starts_with(\"rtk")
                || line.contains(".strip_prefix(\"rtk")
                || line.contains(".ends_with(\"rtk")
                || line.contains("is_some_and(|c| c.contains(\"rtk\")")
                || line.contains("hook_content.contains(\"rtk")
                || line.contains("existing.contains(\"RTK\") || existing.contains(\"rtk\")")
                || line.contains("content.contains(\"RTK\")")
                || line.contains("removed.iter().any(|r| r.contains(\"rtk")
                || line.contains("Removed legacy rtk-rewrite.sh")
                || line.contains("RTK from AGENTS.md")
                || line.contains("RTK from Gemini settings.json")
                || line.contains("RTK content")
                || line.contains("RTK block")
                || line.contains("RTK entry")
                || line.contains("RTK hook")
                || line.contains("RTK permission")
                || line.contains("RTK will not execute")
                || line.contains("RTK installs a")
                || line.contains("RTK uses native")
                || line.contains("# CLI Corrections (auto-generated by rtk learn")
                || line.contains("Run `rtk learn")
                || line.contains("# rtk-hook-version:")
                || line.contains("\"rtk-rewrite\"")
                || line.contains("- rtk-rewrite")
                || line.contains("rtk-rewrite\\n")
                || line.contains("rtk-rewrite\")")
                || line.contains("contains(\"@RTK.md\")")
                || line.contains("contains(\"RTK.md\")")
                || line.contains("path.join(\"RTK.md\")")
                || line.contains("RTK.md\")")
                || line.contains("RTK STUFF")
                || line.contains("RTK CONTENT")
                || line.contains("opencode/plugins/rtk.ts")
                || line.contains("plugins/rtk.ts")
                || line.contains("@RTK.md")
                || line.contains("# header\n\n@RTK.md")
                || line.contains("rtk-instructions block")
                || line.contains("Already using RTK:")
                || line.contains("RTK already handles")
                || line.contains("Already RTK")
                || line.contains("already-RTK")
                || line.contains("RTK-covered")
                || line.contains("`rtk ")
                || line.contains("RTK-style")
                || line.contains("RTK default")
                || line.contains("RTK syntax")
                || line.contains("MISSED SAVINGS")
                || line.contains("missed RTK")
                // assert_eq!/assert! diagnostic message ending in rtk-
                // related text. Narrow: only the message-string arg, and
                // only inside test files.
                || line.trim_start().starts_with("assert_eq!(")
                || line.trim_start().starts_with("assert!(")
                || line.trim_start().starts_with("assert_ne!(")
        },
    },
];

/// Apply allowlist rules to a line. Returns the first rule that matches,
/// or `None` if the line is NOT exempt.
fn match_allowlist(line: &str, rel_path: &str) -> Option<&'static AllowlistRule> {
    ALLOWLIST_RULES
        .iter()
        .find(|r| (r.matches)(line, rel_path))
}

/// Strip a trailing `// ...` line comment. Naive — does not understand
/// `//` inside string literals (good enough here; only used by the
/// module-internal-identifier rule which already cares only about bare-
/// word residuals after identifier-shaped tokens are removed).
///
/// We DON'T strip when the line is itself a comment line (`//`, `///`,
/// `//!`) — those are handled by their own rules.
fn strip_trailing_line_comment(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return line.to_string();
    }
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Don't mangle URLs like `https://...`.
            if i == 0 || bytes[i - 1] != b':' {
                return line[..i].to_string();
            }
        }
        i += 1;
    }
    line.to_string()
}


/// Track whether the current line is inside a multi-line raw string
/// literal (`r#"..."#`). These are commonly used in tests/fixtures and
/// contain real command output that legitimately mentions `rtk` (e.g.
/// `   Compiling rtk v0.5.0`, audit log lines, registry expectations).
///
/// Implementation: greedy-balance counting of `r#"` opens vs matching
/// `"#` closes. Doesn't handle arbitrary `r##" ... "##` depth — we
/// haven't needed to. If we ever do, extend.
#[derive(Default)]
struct RawStringTracker {
    inside: bool,
}

impl RawStringTracker {
    /// Update state for the current line. Returns whether the line was
    /// (at any point) inside a multi-line raw string literal — i.e. it's
    /// either entirely inside, or the closing-delimiter line.
    fn step(&mut self, line: &str) -> bool {
        let was_inside = self.inside;
        let mut i = 0;
        let bytes = line.as_bytes();
        while i < bytes.len() {
            if self.inside {
                // Look for closing `"#`.
                if i + 1 < bytes.len() && bytes[i] == b'"' && bytes[i + 1] == b'#' {
                    self.inside = false;
                    i += 2;
                    continue;
                }
                i += 1;
            } else {
                // Look for opening `r#"` (or `r"`).
                if i + 2 < bytes.len()
                    && bytes[i] == b'r'
                    && bytes[i + 1] == b'#'
                    && bytes[i + 2] == b'"'
                {
                    self.inside = true;
                    i += 3;
                    continue;
                }
                // Skip past regular `"..."` strings so we don't pick
                // up `"r#""` inside one.
                if bytes[i] == b'"' {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                    continue;
                }
                i += 1;
            }
        }
        was_inside || self.inside
    }
}

/// Track whether a line is inside an `ALLOWED_FUNCTION_PREFIXES` body.
/// Uses simple brace-depth tracking.
struct AllowedFnTracker {
    in_fn: bool,
    depth: i64,
}

impl AllowedFnTracker {
    fn new() -> Self {
        Self { in_fn: false, depth: 0 }
    }

    /// Update state for the current line and return whether this line is
    /// considered part of an allowed function body.
    fn step(&mut self, line: &str) -> bool {
        if !self.in_fn
            && ALLOWED_FUNCTION_PREFIXES.iter().any(|p| line.contains(p))
        {
            self.in_fn = true;
            self.depth = 0;
        }
        if self.in_fn {
            let opens = line.chars().filter(|c| *c == '{').count() as i64;
            let closes = line.chars().filter(|c| *c == '}').count() as i64;
            self.depth += opens - closes;
            let exit_this_line = self.depth <= 0 && (opens + closes) > 0;
            let was_in = self.in_fn;
            if exit_this_line {
                self.in_fn = false;
                self.depth = 0;
            }
            return was_in;
        }
        false
    }
}

#[test]
fn branding_lint_no_unrecognised_rtk_references_in_src() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = repo_root.join("src");

    let mut failures: Vec<String> = Vec::new();

    for entry in WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|s| s == "rs")
                .unwrap_or(false)
        })
    {
        let rel = entry
            .path()
            .strip_prefix(&repo_root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();

        if SKIPPED_PATHS.iter().any(|s| rel == *s) {
            continue;
        }

        let content = fs::read_to_string(entry.path())
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", rel, e));

        let mut allowed_fn = AllowedFnTracker::new();
        let mut raw_string = RawStringTracker::default();

        for (lineno, line) in content.lines().enumerate() {
            let lineno = lineno + 1;

            // Update raw-string state first so the in_raw flag below is
            // accurate for THIS line (the opening-delimiter line counts
            // as "inside" because the rtk text often appears on it).
            let in_raw = raw_string.step(line);

            // Skip lines inside allowed function bodies.
            if allowed_fn.step(line) {
                continue;
            }

            // Cheap fast path: most lines don't mention `rtk` at all.
            if !RTK_WORD_RE.is_match(line) {
                continue;
            }

            // Lines inside a multi-line raw string literal (`r#"..."#`)
            // are treated as fixture text — these are real captured
            // command outputs (cargo, audit logs, etc) used to drive
            // filter tests. The FORBIDDEN_TOKENS regression test still
            // applies for specific user-visible leaks.
            if in_raw {
                continue;
            }

            if match_allowlist(line, &rel).is_some() {
                continue;
            }

            // Unrecognised reference. Extract the offending substring for
            // the failure message — show up to 3 distinct matches on the
            // line so a multi-`rtk` line surfaces them all.
            let mut snippets: Vec<String> = RTK_WORD_RE
                .find_iter(line)
                .map(|m| m.as_str().to_string())
                .collect();
            snippets.sort();
            snippets.dedup();
            let snippets = snippets.join(", ");

            failures.push(format!(
                "  {}:{}  unrecognised `{}`  (no allowlist rule matched)\n      {}",
                rel,
                lineno,
                snippets,
                line.trim()
            ));
        }
    }

    // Sanity self-test: simulate the v0.1.8 leak classes that triggered
    // this issue and make sure the allowlist correctly REJECTS them. If
    // any of these escapes flagging, the allowlist has drifted too broad
    // and needs to be re-tightened.
    //
    // NOTE: clap `///` doc-comment leaks (`/// RTK savings`) are
    // explicitly covered by the FORBIDDEN_TOKENS regression list above
    // rather than by this allowlist scan — see the
    // `rustdoc-comment mention (///)` rule for the trade-off rationale.
    let leak_simulations: &[(&str, &str)] = &[
        // The init-message leak (post-v0.1.8 user report).
        ("src/hooks/init.rs", "    eprintln!(\"Run: rtk init -g\");"),
        // The error-prefix leak (post-v0.1.8 user report).
        ("src/cmds/git/git.rs", "    eprintln!(\"rtk: filter failed\");"),
        // A novel `eprintln!` leak that has NEVER been seen — proves the
        // allowlist would catch a new user-facing string-leak class.
        ("src/main.rs", "    eprintln!(\"warning: rtk dashboard unavailable\");"),
        // A novel `panic!` leak.
        ("src/core/utils.rs", "    panic!(\"unexpected rtk state\");"),
    ];
    for (rel, line) in leak_simulations {
        // These lines must NOT match any allowlist rule. If they do, the
        // allowlist would let real leaks slip through silently.
        assert!(
            match_allowlist(line, rel).is_none(),
            "Allowlist self-test FAILED: leak simulation `{}` in `{}` was \
             incorrectly accepted by rule `{}`. The allowlist has drifted \
             too broad — tighten the rule before this protection regresses.",
            line.trim(),
            rel,
            match_allowlist(line, rel).map(|r| r.name).unwrap_or(""),
        );
    }

    if !failures.is_empty() {
        let rule_names: Vec<&str> =
            ALLOWLIST_RULES.iter().map(|r| r.name).collect();
        panic!(
            "\n\n--- branding-lint (allowlist) failures ---\n\
             {} unrecognised `rtk` reference(s) in production source:\n\n{}\n\n\
             This test is allowlist-style: every `\\brtk\\b` reference must \
             match a named rule. Available rules:\n  - {}\n\n\
             FIX OPTIONS:\n\
             1. Replace the leak with the CONTEXTCRAWLER equivalent (preferred \
                if the reference is user-visible: error prefix, help text, \
                init message, etc).\n\
             2. Add `{}` to the end of the line if the reference is \
                intentionally legacy (regression-history comments, cleanup code).\n\
             3. If this is a NEW intentional category (e.g. a new env var \
                surface, a new tracking column), add a NAMED entry to \
                `ALLOWLIST_RULES` in `tests/branding_lint.rs` so the rule is \
                auditable.\n\n\
             This test exists to prevent the v0.1.8→v0.1.9 whack-a-mole \
             (3 hotfix rounds for missed leak classes) from recurring. See #67.\n",
            failures.len(),
            failures.join("\n\n"),
            rule_names.join("\n  - "),
            ALLOW_MARKER,
        );
    }
}
