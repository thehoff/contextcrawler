//! Sets up ContextCrawler hooks so AI coding agents automatically route commands through ContextCrawler.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::hooks::constants::{
    CONFIG_DIR, CURSOR_DIR, GEMINI_DIR, OPENCODE_PLUGIN_FILE, OPENCODE_SUBDIR, PLUGIN_SUBDIR,
};

use super::constants::{
    BEFORE_TOOL_KEY, CLAUDE_DIR, CLAUDE_HOOK_COMMAND, CODEX_DIR, CURSOR_HOOK_COMMAND,
    LEGACY_CURSOR_HOOK_COMMAND,
    GEMINI_HOOK_FILE, HERMES_DIR, HERMES_PLUGINS_SUBDIR, HERMES_PLUGIN_INIT_FILE,
    HERMES_PLUGIN_MANIFEST_FILE, HERMES_PLUGIN_NAME, HOOKS_JSON, HOOKS_SUBDIR,
    PI_AGENT_SUBDIR, PI_DIR, PI_EXTENSIONS_SUBDIR, PI_EXTENSION_FILE,
    PRE_TOOL_USE_KEY, REWRITE_HOOK_FILE, SETTINGS_JSON,
};
use super::integrity;

// Embedded OpenCode plugin (auto-rewrite)
const OPENCODE_PLUGIN: &str = include_str!("../../hooks/opencode/rtk.ts");

// Embedded Pi extension (auto-rewrite via createBashTool spawnHook)
const PI_EXTENSION: &str = include_str!("../../hooks/pi/rtk-extension.ts"); // branding-lint: allow legacy

// ─── Unified guidance ──────────────────────────────────────────────────────
//
// CANONICAL agent guidance rendered from a single source file.
// `agent_guidance(key)` prepends a per-harness title + "How commands are
// rewritten" section to the shared body and strips the maintainer comment.
// Do NOT add per-harness copies — edit `hooks/shared/guidance.md` instead.

const GUIDANCE_CORE: &str = include_str!("../../hooks/shared/guidance.md");

/// Supported harness identifiers for `agent_guidance`.
///
/// Keys that do not map to `AgentTarget` (Gemini, OpenCode, Codex, Copilot)
/// are handled by name so callers outside AgentTarget can still use this function.
const AGENT_CLAUDE: &str = "claude";
const AGENT_CODEX: &str = "codex";
const AGENT_CURSOR: &str = "cursor";
const AGENT_WINDSURF: &str = "windsurf";
const AGENT_CLINE: &str = "cline";
const AGENT_KILOCODE: &str = "kilocode";
const AGENT_ANTIGRAVITY: &str = "antigravity";
const AGENT_HERMES: &str = "hermes";
const AGENT_GEMINI: &str = "gemini";
const AGENT_COPILOT: &str = "copilot";
const AGENT_OPENCODE: &str = "opencode";
const AGENT_PIDEV: &str = "pidev";

/// Return the per-harness ContextCrawler guidance document.
///
/// Output format:
///   `# ContextCrawler ({title})\n\n{mechanism}\n\n{guidance_core_body}`
///
/// The HTML maintainer comment at the top of `GUIDANCE_CORE` is stripped so
/// agents do not see it. The rendered output starts at the
/// `**Token-optimised CLI proxy.**` line.
///
/// Valid `agent` keys: "claude", "codex", "cursor", "windsurf", "cline",
/// "kilocode", "antigravity", "hermes", "gemini", "copilot", "opencode".
///
/// # Errors
/// Returns an error on an unrecognised key — callers must use one of the
/// eleven `AGENT_*` constants above; passing a typo is a programming error
/// surfaced as a `Result` rather than a panic (CTXCRL no-panic-in-production rule).
fn agent_guidance(agent: &str) -> Result<String> {
    let title = match agent {
        AGENT_CLAUDE     => "Claude Code",
        AGENT_CODEX      => "Codex CLI",
        AGENT_CURSOR     => "Cursor",
        AGENT_WINDSURF   => "Windsurf",
        AGENT_CLINE      => "Cline",
        AGENT_KILOCODE   => "Kilo Code",
        AGENT_ANTIGRAVITY => "Google Antigravity",
        AGENT_HERMES     => "Hermes",
        AGENT_GEMINI     => "Gemini CLI",
        AGENT_COPILOT    => "GitHub Copilot",
        AGENT_OPENCODE   => "OpenCode",
        AGENT_PIDEV      => "Pi",
        other => anyhow::bail!("agent_guidance: unknown agent key '{other}'"),
    };

    // Mechanism section differs by integration type.
    let mechanism = match agent {
        // CODEX: no hook, must self-prefix. Carry the imperative content from
        // the former hooks/codex/rtk-awareness.md (issue #53 regression guard).
        AGENT_CODEX => concat!(
            "## How commands are rewritten\n",
            "\n",
            "Codex has no automatic hook — **you must prefix every shell command** ",
            "with `contextcrawler `. This is mandatory, not advisory.\n",
            "\n",
            "| WRONG | RIGHT |\n",
            "|-------|-------|\n",
            "| `git status` | `contextcrawler git status` |\n",
            "| `git log -3 --oneline` | `contextcrawler git log -3 --oneline` |\n",
            "| `git -C /path/to/repo status` | `contextcrawler git -C /path/to/repo status` |\n",
            "| `grep -r foo src/` | `contextcrawler grep -r foo src/` |\n",
            "| `rg -n foo src/` | `contextcrawler rg -n foo src/` |\n",
            "| `cat README.md` | `contextcrawler read README.md` |\n",
            "| `nl -ba src/main.rs` | `contextcrawler read -n src/main.rs` |\n",
            "| `ls -la` | `contextcrawler ls -la` |\n",
            "| `find . -name '*.ts'` | `contextcrawler find . -name '*.ts'` |\n",
            "\n",
            "The `git -C <dir>`, `rg -n`, and `nl … | sed -n` patterns are common gaps — ",
            "they look \"different enough\" that you might not register them as wrappable. ",
            "They are. All three accept the `contextcrawler ` prefix.\n",
            "\n",
            "Applies to: git, gh, glab, grep, find, ls, tree, cat (use `contextcrawler read`), ",
            "head, tail, cargo, npm, pnpm, pytest, jest, vitest, tsc, docker, kubectl, aws, ",
            "psql, dotnet, wget, wc, diff, log — every shell command.\n",
            "\n",
            "Escape hatch only when contextcrawler genuinely cannot handle the command: ",
            "`contextcrawler proxy <raw-command>`. Do not fall back to bare commands.\n",
            "\n",
            "Before issuing any shell call, check: does it start with `contextcrawler `? ",
            "If no, rewrite it.",
        ),

        // PLUGIN agents: OpenCode, Hermes, and Pi use a plugin/extension, not a shell hook.
        AGENT_OPENCODE | AGENT_HERMES | AGENT_PIDEV => concat!(
            "## How commands are rewritten\n",
            "\n",
            "A ContextCrawler plugin rewrites shell commands automatically — ",
            "`git status` becomes `contextcrawler git status` transparently. ",
            "Use the meta commands below directly; everything else is wrapped for you.",
        ),

        // HOOKED agents: all others have a PreToolUse / BeforeTool hook.
        _ => {
            let agent_name = match agent {
                AGENT_CLAUDE     => "Claude Code",
                AGENT_CURSOR     => "Cursor",
                AGENT_WINDSURF   => "Windsurf",
                AGENT_CLINE      => "Cline",
                AGENT_KILOCODE   => "Kilo Code",
                AGENT_ANTIGRAVITY => "Google Antigravity",
                AGENT_GEMINI     => "Gemini CLI",
                AGENT_COPILOT    => "GitHub Copilot",
                _                => title,
            };
            // Build owned string for hooked agents — returned from match arm.
            return Ok(format!(
                "# ContextCrawler ({title})\n\n\
                 ## How commands are rewritten\n\n\
                 The {agent_name} hook rewrites shell commands automatically — \
                 `git status` becomes `contextcrawler git status` transparently, \
                 with zero token overhead. Use the meta commands below directly; \
                 everything else is wrapped for you.\n\n\
                 {body}",
                body = guidance_core_body(),
            ));
        }
    };

    Ok(format!(
        "# ContextCrawler ({title})\n\n{mechanism}\n\n{body}",
        body = guidance_core_body(),
    ))
}

/// Wrap `agent_guidance(agent)` output in a ContextCrawler marker block so it can be
/// upserted into a shared instructions file (AGENTS.md) via
/// [`write_ctxcrl_block`] / [`upsert_ctxcrl_block`] without clobbering user content.
///
/// The markers (`CTXCRL_BLOCK_START` … `CTXCRL_BLOCK_END`) are the same ones the
/// Claude CLAUDE.md and Copilot copilot-instructions.md flows use.
fn agent_guidance_block(agent: &str) -> Result<String> {
    Ok(format!(
        "<!-- ctxcrl-instructions v3 -->\n{}\n<!-- /ctxcrl-instructions -->\n",
        agent_guidance(agent)?
    ))
}

/// Return the body of `GUIDANCE_CORE` with the maintainer HTML comment stripped.
///
/// The comment block runs from the first `<!--` to the first `-->` (inclusive)
/// and is followed by a newline. Everything after is the renderable content.
fn guidance_core_body() -> &'static str {
    // The comment ends with "-->\n". Find the position just after that.
    if let Some(end) = GUIDANCE_CORE.find("-->") {
        let after = &GUIDANCE_CORE[end + "-->".len()..];
        after.trim_start_matches('\n')
    } else {
        // No comment found — return whole file (future-proof).
        GUIDANCE_CORE
    }
}

/// Template written by `contextcrawler init` when no filters.toml exists yet.
const FILTERS_TEMPLATE: &str = r#"# Project-local ContextCrawler filters — commit this file with your repo.
# Filters here override user-global and built-in filters.
# Trust gate: run `contextcrawler trust` after editing.
# Docs: https://github.com/thehoff/contextcrawler#custom-filters
schema_version = 1

# Example: suppress build noise from a custom tool
# [filters.my-tool]
# description = "Compact my-tool output"
# match_command = "^my-tool\\s+build"
# strip_ansi = true
# strip_lines_matching = ["^\\s*$", "^Downloading", "^Installing"]
# max_lines = 30
# on_empty = "my-tool: ok"
"#;

/// Template for user-global filters (~/.config/ctxcrl/filters.toml).
const FILTERS_GLOBAL_TEMPLATE: &str = r#"# User-global ContextCrawler filters — apply to all your projects.
# Project-local .ctxcrl/filters.toml takes precedence over these.
# Trust gate: run `contextcrawler trust --global` after editing.
# Docs: https://github.com/thehoff/contextcrawler#custom-filters
schema_version = 1

# Example: suppress noise from a tool you use everywhere
# [filters.my-global-tool]
# description = "Compact my-global-tool output"
# match_command = "^my-global-tool\\b"
# strip_ansi = true
# strip_lines_matching = ["^\\s*$"]
# max_lines = 40
"#;

// The slim instructions file is named CONTEXTCRAWLER.md (not RTK.md) so it // branding-lint: allow legacy
// matches the downstream tool name on disk. Commit bcddd06 silently reverted
// this to "RTK.md" during the upstream rebase; see issue #19 and the
// `test_ctxcrl_md_constant_pinned_to_contextcrawler_filename` regression test.
const CTXCRL_MD: &str = "CONTEXTCRAWLER.md";
const CLAUDE_MD: &str = "CLAUDE.md";
const AGENTS_MD: &str = "AGENTS.md";
const CTXCRL_MD_REF: &str = "@CONTEXTCRAWLER.md";
const GEMINI_MD: &str = "GEMINI.md";

/// Legacy file names that should be cleaned up if found, both on disk and as
/// `@<name>` references in AGENTS.md / CLAUDE.md. Add to this list whenever
/// a rename happens so users running `init` after the change don't end up
/// with duplicate orphan files.
const LEGACY_CTXCRL_MD_FILES: &[&str] = &["RTK.md"]; // branding-lint: allow legacy

const CTXCRL_BLOCK_START: &str = "<!-- ctxcrl-instructions";
const CTXCRL_BLOCK_END: &str = "<!-- /ctxcrl-instructions -->";

/// Pre-0.3.0 installs wrote the managed block with `rtk-instructions` markers.
/// We RECOGNISE these legacy markers for FINDING/REMOVING an existing block (so
/// upgrade replaces it in place rather than appending a duplicate, and uninstall
/// strips it), but always WRITE the canonical `ctxcrl-instructions` markers.
/// Mirrors the "recognise legacy, write new" pattern used for
/// `LEGACY_CTXCRL_MD_FILES`.
const LEGACY_BLOCK_START: &str = "<!-- rtk-instructions"; // branding-lint: allow legacy
const LEGACY_BLOCK_END: &str = "<!-- /rtk-instructions -->"; // branding-lint: allow legacy

/// True if `content` holds a managed block under either the canonical or the
/// legacy markers.
fn contains_ctxcrl_block(content: &str) -> bool {
    content.contains(CTXCRL_BLOCK_START) || content.contains(LEGACY_BLOCK_START)
}

/// Return the `(start, end)` marker pair for the managed block present in
/// `content`, trying the canonical markers first and falling back to the legacy
/// `rtk-instructions` markers. `None` if no opening marker is present.
fn block_markers_in(content: &str) -> Option<(&'static str, &'static str)> {
    if content.contains(CTXCRL_BLOCK_START) {
        Some((CTXCRL_BLOCK_START, CTXCRL_BLOCK_END))
    } else if content.contains(LEGACY_BLOCK_START) {
        Some((LEGACY_BLOCK_START, LEGACY_BLOCK_END))
    } else {
        None
    }
}

/// Control flow for settings.json patching
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchMode {
    Ask,  // Default: prompt user [y/N]
    Auto, // --auto-patch: no prompt
    Skip, // --no-patch: manual instructions
}

/// Result of settings.json patching operation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchResult {
    Patched,        // Hook was added successfully
    AlreadyPresent, // Hook was already in settings.json
    Declined,       // User declined when prompted
    Skipped,        // --no-patch flag used
    WouldPatch,     // Dry-run: hook would have been added
}

/// Shared context threaded through every init/uninstall function.
///
/// Replaces ad-hoc `verbose: u8, dry_run: bool` parameter pairs to keep
/// signatures compact as more flags are added (mirrors `RunOptions` in
/// `src/core/runner.rs`).
#[derive(Clone, Copy, Default)]
pub struct InitContext {
    pub verbose: u8,
    pub dry_run: bool,
}

/// Shared dry-run footer printed at the end of every init sub-mode.
fn print_dry_run_footer() {
    println!("\n[dry-run] Nothing written.");
}

// Legacy full instructions for backward compatibility (--claude-md mode)
const CTXCRL_INSTRUCTIONS: &str = r##"<!-- ctxcrl-instructions v3 -->
# ContextCrawler — Token-Optimized Commands

## Golden Rule

**Always prefix commands with `contextcrawler`**. If ContextCrawler has a dedicated filter, it uses it. If not, it passes through unchanged. This means ContextCrawler is always safe to use.

**Important**: Even in command chains with `&&`, use `contextcrawler`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
contextcrawler git add . && contextcrawler git commit -m "msg" && contextcrawler git push
```

## ContextCrawler Commands by Workflow

### Build & Compile (80-90% savings)
```bash
contextcrawler cargo build         # Cargo build output
contextcrawler cargo check         # Cargo check output
contextcrawler cargo clippy        # Clippy warnings grouped by file (80%)
contextcrawler tsc                 # TypeScript errors grouped by file/code (83%)
contextcrawler lint                # ESLint/Biome violations grouped (84%)
contextcrawler prettier --check    # Files needing format only (70%)
contextcrawler next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
contextcrawler cargo test          # Cargo test failures only (90%)
contextcrawler go test             # Go test failures only (90%)
contextcrawler jest                # Jest failures only (99.5%)
contextcrawler vitest              # Vitest failures only (99.5%)
contextcrawler playwright test     # Playwright failures only (94%)
contextcrawler pytest              # Python test failures only (90%)
contextcrawler rake test           # Ruby test failures only (90%)
contextcrawler rspec               # RSpec test failures only (60%)
contextcrawler test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
contextcrawler git status          # Compact status
contextcrawler git log             # Compact log (works with all git flags)
contextcrawler git diff            # Compact diff (80%)
contextcrawler git show            # Compact show (80%)
contextcrawler git add             # Ultra-compact confirmations (59%)
contextcrawler git commit          # Ultra-compact confirmations (59%)
contextcrawler git push            # Ultra-compact confirmations
contextcrawler git pull            # Ultra-compact confirmations
contextcrawler git branch          # Compact branch list
contextcrawler git fetch           # Compact fetch
contextcrawler git stash           # Compact stash
contextcrawler git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
contextcrawler gh pr view <num>    # Compact PR view (87%)
contextcrawler gh pr checks        # Compact PR checks (79%)
contextcrawler gh run list         # Compact workflow runs (82%)
contextcrawler gh issue list       # Compact issue list (80%)
contextcrawler gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
contextcrawler pnpm list           # Compact dependency tree (70%)
contextcrawler pnpm outdated       # Compact outdated packages (80%)
contextcrawler pnpm install        # Compact install output (90%)
contextcrawler npm run <script>    # Compact npm script output
contextcrawler npx <cmd>           # Compact npx command output
contextcrawler prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
contextcrawler ls <path>           # Tree format, compact (65%)
contextcrawler read <file>         # Full file content; --level minimal/aggressive to filter (opt-in)
contextcrawler grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
contextcrawler find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
contextcrawler err <cmd>           # Filter errors only from any command
contextcrawler log <file>          # Deduplicated logs with counts
contextcrawler json <file>         # JSON structure without values
contextcrawler deps                # Dependency overview
contextcrawler env                 # Environment variables compact
contextcrawler summary <cmd>       # Smart summary of command output
contextcrawler diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
contextcrawler docker ps           # Compact container list
contextcrawler docker images       # Compact image list
contextcrawler docker logs <c>     # Deduplicated logs
contextcrawler kubectl get         # Compact resource list
contextcrawler kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
contextcrawler curl <url>          # Compact HTTP responses (70%)
contextcrawler wget <url>          # Compact download output (65%)
contextcrawler web <url>           # Defuddle-extracted readable HTML
```

### Meta Commands
```bash
contextcrawler gain                # View token savings statistics
contextcrawler gain --history      # View command history with savings
contextcrawler gain --weak-filters # Rank tools by leaked tokens (where filters underperform)
contextcrawler discover            # Analyze Claude Code sessions for missed opportunities
contextcrawler proxy <cmd>         # Run command without filtering (for debugging)
contextcrawler init                # Add ContextCrawler instructions to CLAUDE.md
contextcrawler init --global       # Add ContextCrawler to ~/.claude/CLAUDE.md
contextcrawler trust               # Trust project-local TOML filters
contextcrawler trust --global      # Trust user-global TOML filters
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget, web | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /ctxcrl-instructions -->
"##;

/// Main entry point for `contextcrawler init`
#[allow(clippy::too_many_arguments)]
pub fn run(
    global: bool,
    install_claude: bool,
    install_opencode: bool,
    install_cursor: bool,
    install_windsurf: bool,
    install_cline: bool,
    claude_md: bool,
    hook_only: bool,
    codex: bool,
    patch_mode: PatchMode,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    // Validation: Codex mode conflicts
    if codex {
        if install_opencode {
            anyhow::bail!("--codex cannot be combined with --opencode");
        }
        if claude_md {
            anyhow::bail!("--codex cannot be combined with --claude-md");
        }
        if hook_only {
            anyhow::bail!("--codex cannot be combined with --hook-only");
        }
        if matches!(patch_mode, PatchMode::Auto) {
            anyhow::bail!("--codex cannot be combined with --auto-patch");
        }
        if matches!(patch_mode, PatchMode::Skip) {
            anyhow::bail!("--codex cannot be combined with --no-patch");
        }
        run_codex_mode(global, ctx)?;
    } else {
        // Validation: Global-only features
        if install_opencode && !global {
            anyhow::bail!("OpenCode plugin is global-only. Use: contextcrawler init -g --opencode");
        }

        if install_cursor && !global {
            anyhow::bail!("Cursor hooks are global-only. Use: contextcrawler init -g --agent cursor");
        }

        if install_windsurf && !global {
            anyhow::bail!("Windsurf support is global-only. Use: contextcrawler init -g --agent windsurf");
        }

        if install_windsurf {
            run_windsurf_mode(ctx)?;
        } else if install_cline {
            run_cline_mode(ctx)?;
        } else {
            // Mode selection (Claude Code / OpenCode)
            match (install_claude, install_opencode, claude_md, hook_only) {
                (false, true, _, _) => run_opencode_only_mode(ctx)?,
                (true, opencode, true, _) => run_claude_md_mode(global, opencode, ctx)?,
                (true, opencode, false, true) => {
                    run_hook_only_mode(global, patch_mode, opencode, ctx)?
                }
                (true, opencode, false, false) => {
                    run_default_mode(global, patch_mode, opencode, ctx)?
                }
                (false, false, _, _) => {
                    if !install_cursor {
                        anyhow::bail!(
                            "at least one of install_claude or install_opencode must be true"
                        )
                    }
                }
            }

            // Cursor hooks (additive, installed alongside Claude Code)
            if install_cursor {
                install_cursor_hooks(ctx)?;
            }
        }
    }

    if !dry_run {
        prompt_telemetry_consent()?;
    }

    if dry_run {
        print_dry_run_footer();
    } else {
        println!();
    }

    Ok(())
}

/// Idempotent file write: create or update if content differs.
/// When `dry_run` is true, prints the intended action and does not touch the filesystem.
fn write_if_changed(path: &Path, content: &str, name: &str, ctx: InitContext) -> Result<bool> {
    let InitContext { verbose, dry_run } = ctx;
    if path.exists() {
        let existing = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}: {}", name, path.display()))?;

        if existing == content {
            if verbose > 0 {
                eprintln!("{} already up to date: {}", name, path.display());
            }
            Ok(false)
        } else {
            if dry_run {
                println!("[dry-run] would update {}: {}", name, path.display());
                if verbose > 0 {
                    println!("[dry-run] content:\n{}", content);
                }
            } else {
                atomic_write(path, content)
                    .with_context(|| format!("Failed to write {}: {}", name, path.display()))?;
                if verbose > 0 {
                    eprintln!("Updated {}: {}", name, path.display());
                }
            }
            Ok(true)
        }
    } else {
        if dry_run {
            println!("[dry-run] would create {}: {}", name, path.display());
            if verbose > 0 {
                println!("[dry-run] content:\n{}", content);
            }
        } else {
            atomic_write(path, content)
                .with_context(|| format!("Failed to write {}: {}", name, path.display()))?;
            if verbose > 0 {
                eprintln!("Created {}: {}", name, path.display());
            }
        }
        Ok(true)
    }
}

/// Resolve the final write target: if `path` is a symlink, follow it so the
/// atomic rename lands on the real file and the link itself is preserved.
///
/// `fs::canonicalize` resolves symlink chains (and any relative components) to
/// the underlying file. It fails when the path does not yet exist (e.g. a
/// first-time write), in which case we fall back to the original path — exactly
/// the behaviour we want for creating a brand-new regular file.
fn resolve_atomic_target(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Atomic write using tempfile + rename
/// Prevents corruption on crash/interrupt
/// Follows symlinks so the link itself is preserved.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let target = resolve_atomic_target(path);
    let parent = target.parent().with_context(|| {
        format!(
            "Cannot write to {}: path has no parent directory",
            target.display()
        )
    })?;

    // Create the parent before creating the same-directory temp file. Global
    // first-run init may target ~/.claude/CONTEXTCRAWLER.md before ~/.claude
    // exists; NamedTempFile::new_in(parent) cannot create that directory for
    // us (#2519). Dry-run callers never reach atomic_write(), so dry-run stays
    // side-effect free.
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory {}", parent.display()))?;

    // Create temp file in same directory (ensures same filesystem for atomic rename)
    let mut temp_file = NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;

    // Write content
    temp_file
        .write_all(content.as_bytes())
        .with_context(|| format!("Failed to write {} bytes to temp file", content.len()))?;

    // Atomic rename onto the resolved target (the real file behind any symlink),
    // so an existing symlink is written through rather than clobbered.
    temp_file.persist(&target).with_context(|| {
        format!(
            "Failed to atomically replace {} (disk full?)",
            target.display()
        )
    })?;

    Ok(())
}

/// Prompt user for consent to patch settings.json
/// Prints to stderr (stdout may be piped), reads from stdin
/// Default is No (capital N)
fn prompt_user_consent(settings_path: &Path) -> Result<bool> {
    use std::io::{self, BufRead, IsTerminal};

    eprintln!("\nPatch existing {}? [y/N] ", settings_path.display());

    // If stdin is not a terminal (piped), default to No
    if !io::stdin().is_terminal() {
        eprintln!("(non-interactive mode, defaulting to N)");
        return Ok(false);
    }

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("Failed to read user input")?;

    let response = line.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

pub fn save_telemetry_consent(accepted: bool) -> Result<()> {
    let mut config = crate::core::config::Config::load().unwrap_or_default();
    config.telemetry.consent_given = Some(accepted);
    config.telemetry.enabled = accepted;
    config.telemetry.consent_date = Some(chrono::Utc::now().to_rfc3339());
    config
        .save()
        .context("Failed to save telemetry consent to config.toml")
}

fn prompt_telemetry_consent() -> Result<()> {
    use std::io::{self, BufRead, IsTerminal};

    let config = crate::core::config::Config::load().unwrap_or_default();
    match config.telemetry.consent_given {
        Some(true) => return Ok(()),
        Some(false) => return Ok(()),
        None => {}
    }

    if !io::stdin().is_terminal() {
        return Ok(());
    }

    eprintln!();
    eprintln!("--- Telemetry ---");
    eprintln!("ContextCrawler collects anonymous usage metrics once per day to improve filters.");
    eprintln!();
    eprintln!("  What:    command names (not arguments), token savings, OS, version");
    eprintln!("  Why:     prioritize filter development for the most-used commands");
    eprintln!("  Who:     RTK AI Labs, contact@rtk-ai.app");
    eprintln!("  Rights:  disable anytime with `contextcrawler telemetry disable`,");
    eprintln!("           request erasure with `contextcrawler telemetry forget`");
    eprintln!("  Details: https://github.com/rtk-ai/rtk/blob/master/docs/TELEMETRY.md");
    eprintln!();
    eprint!("Enable anonymous telemetry? [y/N] ");

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("Failed to read user input")?;

    let accepted = {
        let response = line.trim().to_lowercase();
        response == "y" || response == "yes"
    };

    save_telemetry_consent(accepted)?;

    if accepted {
        eprintln!("  Telemetry enabled. Disable anytime: contextcrawler telemetry disable");
    } else {
        eprintln!("  Telemetry disabled.");
    }

    Ok(())
}

fn print_manual_instructions(hook_command: &str, include_opencode: bool) {
    println!("\n  MANUAL STEP: Add this to ~/.claude/settings.json:");
    println!("  {{");
    println!("    \"hooks\": {{ \"PreToolUse\": [{{");
    println!("      \"matcher\": \"Bash\",");
    println!("      \"hooks\": [{{ \"type\": \"command\",");
    println!("        \"command\": \"{}\"", hook_command);
    println!("      }}]");
    println!("    }}]}}");
    println!("  }}");
    if include_opencode {
        println!("\n  Then restart Claude Code and OpenCode. Test with: git status\n");
    } else {
        println!("\n  Then restart Claude Code. Test with: git status\n");
    }
}

/// `true` if `command` is the legacy ContextCrawler rewrite *script*
/// hook entry.
///
/// SECURITY (#100 G2 IMPORTANT 6): the legacy hook command is a filesystem
/// path ending in `rtk-rewrite.sh`. A bare `contains(REWRITE_HOOK_FILE)`
/// substring match would also delete an unrelated user hook whose command
/// merely *mentions* that filename (e.g. `echo see rtk-rewrite.sh`). Match
/// the final path component exactly instead — precise, and needs no
/// install-time marker migration so existing installs stay removable.
fn command_is_legacy_rewrite_hook(command: &str) -> bool {
    // The legacy entry is a path the installer wrote (`~/.claude/hooks/
    // rtk-rewrite.sh`), possibly bare or quoted. Take the last whitespace
    // token, then its final path component.
    command
        .split_whitespace()
        .next_back()
        .map(|tok| tok.trim_matches(['"', '\'']))
        .and_then(|tok| {
            std::path::Path::new(tok)
                .file_name()
                .and_then(|n| n.to_str())
        })
        .is_some_and(|base| base == REWRITE_HOOK_FILE)
}

fn remove_hook_from_json(root: &mut serde_json::Value) -> bool {
    let hooks = match root
        .get_mut("hooks")
        .and_then(|h| h.get_mut(PRE_TOOL_USE_KEY))
    {
        Some(pre_tool_use) => pre_tool_use,
        None => return false,
    };

    let pre_tool_use_array = match hooks.as_array_mut() {
        Some(arr) => arr,
        None => return false,
    };

    let original_len = pre_tool_use_array.len();
    pre_tool_use_array.retain(|entry| {
        if let Some(hooks_array) = entry.get("hooks").and_then(|h| h.as_array()) {
            for hook in hooks_array {
                if let Some(command) = hook.get("command").and_then(|c| c.as_str()) {
                    // Match both legacy script path and new binary command
                    if command_is_legacy_rewrite_hook(command)
                        || command == CLAUDE_HOOK_COMMAND
                    {
                        return false;
                    }
                }
            }
        }
        true
    });

    pre_tool_use_array.len() < original_len
}

/// Remove ContextCrawler hook from settings.json file
/// Backs up before modification, returns true if hook was found and removed
fn remove_hook_from_settings(ctx: InitContext) -> Result<bool> {
    let InitContext { verbose, dry_run } = ctx;
    let claude_dir = resolve_claude_dir()?;
    let settings_path = claude_dir.join(SETTINGS_JSON);

    if !settings_path.exists() {
        if verbose > 0 {
            eprintln!("settings.json not found, nothing to remove");
        }
        return Ok(false);
    }

    let content = fs::read_to_string(&settings_path)
        .with_context(|| format!("Failed to read {}", settings_path.display()))?;

    if content.trim().is_empty() {
        return Ok(false);
    }

    let mut root: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {} as JSON", settings_path.display()))?;

    let removed = remove_hook_from_json(&mut root);

    if removed {
        if dry_run {
            println!(
                "[dry-run] would remove ContextCrawler hook entry from {}",
                settings_path.display()
            );
            if verbose > 0 {
                let serialized = serde_json::to_string_pretty(&root)
                    .context("Failed to serialize settings.json")?;
                println!("[dry-run] content:\n{}", serialized);
            }
            return Ok(true);
        }

        // Backup original
        let backup_path = settings_path.with_extension("json.bak");
        fs::copy(&settings_path, &backup_path)
            .with_context(|| format!("Failed to backup to {}", backup_path.display()))?;

        // Atomic write
        let serialized =
            serde_json::to_string_pretty(&root).context("Failed to serialize settings.json")?;
        atomic_write(&settings_path, &serialized)?;

        if verbose > 0 {
            eprintln!("Removed ContextCrawler hook from settings.json");
        }
    }

    Ok(removed)
}

/// Full uninstall for Claude, Gemini, Codex, or Cursor artifacts.
pub fn uninstall(
    global: bool,
    gemini: bool,
    codex: bool,
    cursor: bool,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    if codex {
        uninstall_codex(global, ctx)?;
        if dry_run {
            print_dry_run_footer();
        }
        return Ok(());
    }

    if cursor {
        if !global {
            anyhow::bail!("Cursor uninstall only works with --global flag");
        }
        let cursor_removed = remove_cursor_hooks(ctx).context("Failed to remove Cursor hooks")?;
        if !cursor_removed.is_empty() {
            let header = if dry_run {
                "[dry-run] would uninstall ContextCrawler (Cursor):"
            } else {
                "ContextCrawler uninstalled (Cursor):"
            };
            println!("{}", header);
            for item in &cursor_removed {
                println!("  - {}", item);
            }
            if !dry_run {
                println!("\nRestart Cursor to apply changes.");
            }
        } else {
            println!("ContextCrawler Cursor support was not installed (nothing to remove)");
        }
        if dry_run {
            print_dry_run_footer();
        }
        return Ok(());
    }

    if !global {
        anyhow::bail!("Uninstall only works with --global flag. For local projects, manually remove ContextCrawler from CLAUDE.md");
    }

    let claude_dir = resolve_claude_dir()?;
    let mut removed = Vec::new();

    // Also uninstall Gemini artifacts if --gemini or always (clean everything)
    if gemini {
        let gemini_removed = uninstall_gemini(ctx)?;
        removed.extend(gemini_removed);
        if !removed.is_empty() {
            let header = if dry_run {
                "[dry-run] would uninstall ContextCrawler (Gemini):"
            } else {
                "ContextCrawler uninstalled (Gemini):"
            };
            println!("{}", header);
            for item in &removed {
                println!("  - {}", item);
            }
            if !dry_run {
                println!("\nRestart Gemini CLI to apply changes.");
            }
        } else {
            println!("ContextCrawler Gemini support was not installed (nothing to remove)");
        }
        if dry_run {
            print_dry_run_footer();
        }
        return Ok(());
    }

    // 1. Remove legacy hook file (if exists from old installation)
    let hook_path = claude_dir.join(HOOKS_SUBDIR).join(REWRITE_HOOK_FILE);
    if hook_path.exists() {
        if dry_run {
            println!(
                "[dry-run] would remove hook script: {}",
                hook_path.display()
            );
        } else {
            fs::remove_file(&hook_path)
                .with_context(|| format!("Failed to remove hook: {}", hook_path.display()))?;
        }
        removed.push(format!("Hook script: {}", hook_path.display()));
    }

    // 1b. Remove integrity hash file
    if dry_run {
        // integrity::remove_hash would delete the sidecar file; just report intent.
        if integrity::hash_path_for(&hook_path).exists() {
            println!("[dry-run] would remove integrity hash sidecar");
            removed.push("Integrity hash: removed".to_string());
        }
    } else if integrity::remove_hash(&hook_path)? {
        removed.push("Integrity hash: removed".to_string());
    }

    // 2. Remove CONTEXTCRAWLER.md
    let ctxcrl_md_path = claude_dir.join(CTXCRL_MD);
    if ctxcrl_md_path.exists() {
        if dry_run {
            println!("[dry-run] would remove CONTEXTCRAWLER.md: {}", ctxcrl_md_path.display());
        } else {
            fs::remove_file(&ctxcrl_md_path)
                .with_context(|| format!("Failed to remove CONTEXTCRAWLER.md: {}", ctxcrl_md_path.display()))?;
        }
        removed.push(format!("CONTEXTCRAWLER.md: {}", ctxcrl_md_path.display()));
    }

    // 3. Remove @CONTEXTCRAWLER.md reference from CLAUDE.md
    let claude_md_path = claude_dir.join(CLAUDE_MD);
    if claude_md_path.exists() {
        let content = fs::read_to_string(&claude_md_path)
            .with_context(|| format!("Failed to read CLAUDE.md: {}", claude_md_path.display()))?;

        let mut claude_md_changed = false;
        let mut working_content = content.clone();

        if working_content.contains(CTXCRL_MD_REF) {
            let new_content = working_content
                .lines()
                .filter(|line| !line.trim().starts_with(CTXCRL_MD_REF))
                .collect::<Vec<_>>()
                .join("\n");

            working_content = clean_double_blanks(&new_content);
            claude_md_changed = true;
            removed.push("CLAUDE.md: removed @CONTEXTCRAWLER.md reference".to_string());
        }

        if contains_ctxcrl_block(&working_content) {
            let (cleaned, did_remove) = remove_ctxcrl_block(&working_content);
            if did_remove {
                working_content = cleaned;
                claude_md_changed = true;
                removed.push("CLAUDE.md: removed ctxcrl-instructions block".to_string());
            }
        }

        if claude_md_changed {
            let trimmed = working_content.trim();
            if trimmed.is_empty() {
                if dry_run {
                    println!(
                        "[dry-run] would remove CLAUDE.md (empty after cleanup): {}",
                        claude_md_path.display()
                    );
                } else {
                    // nosemgrep: filesystem-deletion
                    fs::remove_file(&claude_md_path).with_context(|| {
                        format!(
                            "Failed to remove empty CLAUDE.md: {}",
                            claude_md_path.display()
                        )
                    })?;
                }
                removed.retain(|r| !r.starts_with("CLAUDE.md:"));
                removed.push("CLAUDE.md: removed (was empty after cleanup)".to_string());
            } else if dry_run {
                println!(
                    "[dry-run] would update CLAUDE.md: {}",
                    claude_md_path.display()
                );
                if verbose > 0 {
                    println!("[dry-run] content:\n{}", working_content);
                }
            } else {
                fs::write(&claude_md_path, &working_content).with_context(|| {
                    format!("Failed to write CLAUDE.md: {}", claude_md_path.display())
                })?;
            }
        }
    }

    // 4. Remove hook entry from settings.json
    if remove_hook_from_settings(ctx)? {
        removed.push("settings.json: removed ContextCrawler hook entry".to_string());
    }

    // 5. Remove OpenCode plugin
    let opencode_removed = remove_opencode_plugin(ctx)?;
    for path in opencode_removed {
        removed.push(format!("OpenCode plugin: {}", path.display()));
    }

    // 6. Remove Cursor hooks
    let cursor_removed = remove_cursor_hooks(ctx)?;
    removed.extend(cursor_removed);

    // Report results
    if removed.is_empty() {
        println!("ContextCrawler was not installed (nothing to remove)");
        println!("  Checked: {}", hook_path.display());
        println!("  Checked: {}", claude_dir.join(CTXCRL_MD).display());
        println!("  Checked: {}", claude_md_path.display());
        println!("  Checked: {}", claude_dir.join(SETTINGS_JSON).display());
    } else {
        let header = if dry_run {
            "[dry-run] would uninstall ContextCrawler:"
        } else {
            "ContextCrawler uninstalled:"
        };
        println!("{}", header);
        for item in removed {
            println!("  - {}", item);
        }
        if !dry_run {
            println!("\nRestart Claude Code, OpenCode, and Cursor (if used) to apply changes.");
        }
    }

    if dry_run {
        print_dry_run_footer();
    }

    Ok(())
}

fn uninstall_codex(global: bool, ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    if !global {
        anyhow::bail!(
            "Uninstall only works with --global flag. For local projects, manually remove ContextCrawler from AGENTS.md"
        );
    }

    let codex_dir = resolve_codex_dir()?;
    let removed = uninstall_codex_at(&codex_dir, ctx)?;

    if removed.is_empty() {
        println!("ContextCrawler was not installed for Codex CLI (nothing to remove)");
    } else {
        let header = if dry_run {
            "[dry-run] would uninstall ContextCrawler for Codex CLI:"
        } else {
            "ContextCrawler uninstalled for Codex CLI:"
        };
        println!("{}", header);
        for item in removed {
            println!("  - {}", item);
        }
    }

    Ok(())
}

fn uninstall_codex_at(codex_dir: &Path, ctx: InitContext) -> Result<Vec<String>> {
    let InitContext { verbose, dry_run } = ctx;
    let mut removed = Vec::new();
    let absolute_ctxcrl_md_ref = codex_ctxcrl_md_ref(codex_dir);

    // ORDER MATTERS (issue #26): patch AGENTS.md FIRST, delete files SECOND.
    //
    // The previous order (delete → patch) left users with an inconsistent
    // install if the patch failed: files gone but AGENTS.md still importing
    // them. Codex then logged warnings on every load AND uninstall couldn't
    // be re-run cleanly because the helper tried to delete files that were
    // already gone. The new order has only two failure shapes:
    //   - patch fails    → nothing removed, safe to rerun
    //   - patch succeeds → both phases complete (AGENTS.md update is the
    //                       expensive/contended step; file deletes after
    //                       are nearly always trivial)
    //
    // Both AGENTS.md mutations (block removal + @-reference strip) are
    // collapsed into ONE read + ONE atomic_write to avoid a half-mutated
    // intermediate state between the two operations.

    let agents_md_path = codex_dir.join(AGENTS_MD);
    let mut refs_to_strip: Vec<String> = vec![
        CTXCRL_MD_REF.to_string(),
        absolute_ctxcrl_md_ref.clone(),
    ];
    for legacy in LEGACY_CTXCRL_MD_FILES {
        refs_to_strip.push(format!("@{}", legacy));
        refs_to_strip.push(format!("@{}", codex_dir.join(legacy).display()));
    }
    let refs_borrowed: Vec<&str> = refs_to_strip.iter().map(|s| s.as_str()).collect();

    if agents_md_path.exists() {
        let content = fs::read_to_string(&agents_md_path)
            .with_context(|| format!("Failed to read AGENTS.md: {}", agents_md_path.display()))?;

        // Apply BOTH mutations in-memory before any disk write.
        let mut working_content = content.clone();
        let mut block_removed = false;
        let mut ref_removed = false;

        if contains_ctxcrl_block(&working_content) {
            let (cleaned, did_remove) = remove_ctxcrl_block(&working_content);
            if did_remove {
                working_content = cleaned;
                block_removed = true;
            }
        }

        if has_rtk_reference(&working_content, &refs_borrowed) {
            let new_content = working_content
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !refs_borrowed.contains(&trimmed)
                })
                .collect::<Vec<_>>()
                .join("\n");
            working_content = clean_double_blanks(&new_content);
            ref_removed = true;
        }

        let changed = block_removed || ref_removed;
        if changed && working_content != content {
            if dry_run {
                println!(
                    "[dry-run] would update AGENTS.md: {}",
                    agents_md_path.display()
                );
                if verbose > 0 {
                    println!("[dry-run] new content:\n{}", working_content);
                }
            } else {
                atomic_write(&agents_md_path, &working_content).with_context(|| {
                    format!("Failed to write AGENTS.md: {}", agents_md_path.display())
                })?;
            }
            if block_removed {
                removed.push("AGENTS.md: removed ctxcrl-instructions block".to_string());
            }
            if ref_removed {
                removed.push("AGENTS.md: removed @CONTEXTCRAWLER.md reference".to_string());
            }
        }
    }

    // AGENTS.md patch succeeded (or was unnecessary). Now safe to delete
    // the canonical file AND any legacy variants. If a delete fails
    // mid-loop, the earlier removes still count as removed — but AGENTS.md
    // is already in its final state so the user can re-run `uninstall`
    // safely; the remaining files will be retried.
    let candidate_files: Vec<&str> = std::iter::once(CTXCRL_MD)
        .chain(LEGACY_CTXCRL_MD_FILES.iter().copied())
        .collect();
    for filename in candidate_files {
        let file_path = codex_dir.join(filename);
        if file_path.exists() {
            if dry_run {
                println!("[dry-run] would remove {}: {}", filename, file_path.display());
            } else {
                fs::remove_file(&file_path).with_context(|| {
                    format!("Failed to remove {}: {}", filename, file_path.display())
                })?;
                if verbose > 0 {
                    eprintln!("Removed {}: {}", filename, file_path.display());
                }
            }
            removed.push(format!("{}: {}", filename, file_path.display()));
        }
    }

    Ok(removed)
}

/// Orchestrator: patch settings.json with ContextCrawler hook (binary command variant)
/// Handles reading, checking, prompting, merging, backing up, and atomic writing
fn patch_settings_json_command(
    hook_command: &str,
    mode: PatchMode,
    include_opencode: bool,
    ctx: InitContext,
) -> Result<PatchResult> {
    let InitContext { verbose, dry_run } = ctx;
    let claude_dir = resolve_claude_dir()?;
    let settings_path = claude_dir.join(SETTINGS_JSON);

    // Read or create settings.json
    let mut root = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)
            .with_context(|| format!("Failed to read {}", settings_path.display()))?;

        if content.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {} as JSON", settings_path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    // Check idempotency
    if hook_already_present(&root, hook_command) {
        if verbose > 0 {
            eprintln!("settings.json: hook already present");
        }
        return Ok(PatchResult::AlreadyPresent);
    }

    // Handle mode
    match mode {
        PatchMode::Skip => {
            print_manual_instructions(hook_command, include_opencode);
            return Ok(PatchResult::Skipped);
        }
        PatchMode::Ask => {
            // Skip the interactive prompt in dry-run: we must not mutate state or block on stdin.
            if dry_run {
                println!(
                    "[dry-run] would prompt before patching {}",
                    settings_path.display()
                );
            } else if !prompt_user_consent(&settings_path)? {
                print_manual_instructions(hook_command, include_opencode);
                return Ok(PatchResult::Declined);
            }
        }
        PatchMode::Auto => {
            // Proceed without prompting
        }
    }

    insert_hook_entry(&mut root, hook_command)?;

    let serialized =
        serde_json::to_string_pretty(&root).context("Failed to serialize settings.json")?;

    if dry_run {
        println!(
            "[dry-run] would patch settings.json: {}",
            settings_path.display()
        );
        if verbose > 0 {
            println!("[dry-run] content:\n{}", serialized);
        }
        return Ok(PatchResult::WouldPatch);
    }

    // Backup original
    if settings_path.exists() {
        let backup_path = settings_path.with_extension("json.bak");
        fs::copy(&settings_path, &backup_path)
            .with_context(|| format!("Failed to backup to {}", backup_path.display()))?;
        if verbose > 0 {
            eprintln!("Backup: {}", backup_path.display());
        }
    }

    // Atomic write
    atomic_write(&settings_path, &serialized)?;

    println!("\n  settings.json: hook added");
    if settings_path.with_extension("json.bak").exists() {
        println!(
            "  Backup: {}",
            settings_path.with_extension("json.bak").display()
        );
    }
    if include_opencode {
        println!("  Restart Claude Code and OpenCode. Test with: git status");
    } else {
        println!("  Restart Claude Code. Test with: git status");
    }

    Ok(PatchResult::Patched)
}

/// Clean up consecutive blank lines (collapse 3+ to 2)
/// Used when removing @CONTEXTCRAWLER.md line from CLAUDE.md
fn clean_double_blanks(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        if line.trim().is_empty() {
            // Count consecutive blank lines
            let mut blank_count = 0;
            while i < lines.len() && lines[i].trim().is_empty() {
                blank_count += 1;
                i += 1;
            }

            // Keep at most 2 blank lines
            let keep = blank_count.min(2);
            result.extend(std::iter::repeat_n("", keep));
        } else {
            result.push(line);
            i += 1;
        }
    }

    result.join("\n")
}

/// Deep-merge ContextCrawler hook entry into settings.json
/// Creates hooks.PreToolUse structure if missing, preserves existing hooks
fn insert_hook_entry(root: &mut serde_json::Value, hook_command: &str) -> Result<()> {
    let root_obj = match root.as_object_mut() {
        Some(obj) => obj,
        None => {
            *root = serde_json::json!({});
            root.as_object_mut().expect("just-created json object")
        }
    };

    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context("hooks value is not an object")?;

    let pre_tool_use = hooks
        .entry(PRE_TOOL_USE_KEY)
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .context("PreToolUse value is not an array")?;

    pre_tool_use.push(serde_json::json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": hook_command
        }]
    }));
    Ok(())
}

/// Check if ContextCrawler hook is already present in settings.json
/// Matches on legacy rtk-rewrite.sh path OR new `contextcrawler hook claude` command
fn hook_already_present(root: &serde_json::Value, hook_command: &str) -> bool {
    let pre_tool_use_array = match root
        .get("hooks")
        .and_then(|h| h.get(PRE_TOOL_USE_KEY))
        .and_then(|p| p.as_array())
    {
        Some(arr) => arr,
        None => return false,
    };

    pre_tool_use_array
        .iter()
        .filter_map(|entry| entry.get("hooks")?.as_array())
        .flatten()
        .filter_map(|hook| hook.get("command")?.as_str())
        .any(|cmd| {
            cmd == hook_command
                || cmd == CLAUDE_HOOK_COMMAND
                || command_is_legacy_rewrite_hook(cmd)
        })
}

/// Default mode: hook + slim CONTEXTCRAWLER.md + @CONTEXTCRAWLER.md reference
fn run_default_mode(
    global: bool,
    patch_mode: PatchMode,
    install_opencode: bool,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    if !global {
        // Local init: inject CLAUDE.md + generate project-local filters template
        run_claude_md_mode(false, install_opencode, ctx)?;
        generate_project_filters_template(ctx)?;
        return Ok(());
    }

    let claude_dir = resolve_claude_dir()?;
    let ctxcrl_md_path = claude_dir.join(CTXCRL_MD);
    let claude_md_path = claude_dir.join(CLAUDE_MD);

    // 1. Migrate old hook script if present
    migrate_old_hook_script(ctx);

    // 2. Write CONTEXTCRAWLER.md
    write_if_changed(&ctxcrl_md_path, &agent_guidance(AGENT_CLAUDE)?, CTXCRL_MD, ctx)?;

    let opencode_plugin_path = if install_opencode {
        let path = prepare_opencode_plugin_path()?;
        ensure_opencode_plugin_installed(&path, ctx)?;
        Some(path)
    } else {
        None
    };

    // 3. Patch CLAUDE.md (add @CONTEXTCRAWLER.md, migrate if needed)
    let migrated = patch_claude_md(&claude_md_path, ctx)?;

    // 4. Print success message (skip in dry-run)
    if !dry_run {
        println!("\nContextCrawler hook registered (global).\n");
        println!("  Command:   {}", CLAUDE_HOOK_COMMAND);
        println!("  CONTEXTCRAWLER.md:    {} (10 lines)", ctxcrl_md_path.display());
        if let Some(path) = &opencode_plugin_path {
            println!("  OpenCode:  {}", path.display());
        }
        println!("  CLAUDE.md: @CONTEXTCRAWLER.md reference added");

        if migrated {
            println!("\n  [ok] Migrated: removed 137-line ContextCrawler block from CLAUDE.md");
            println!("              replaced with @CONTEXTCRAWLER.md (10 lines)");
        }
    }

    // 5. Patch settings.json with binary command
    let patch_result =
        patch_settings_json_command(CLAUDE_HOOK_COMMAND, patch_mode, install_opencode, ctx)?;

    // Report result
    if !dry_run {
        match patch_result {
            PatchResult::Patched => {
                // Already printed by patch_settings_json_command
            }
            PatchResult::AlreadyPresent => {
                println!("\n  settings.json: hook already present");
                if install_opencode {
                    println!("  Restart Claude Code and OpenCode. Test with: git status");
                } else {
                    println!("  Restart Claude Code. Test with: git status");
                }
            }
            PatchResult::Declined | PatchResult::Skipped => {
                // Manual instructions already printed
            }
            PatchResult::WouldPatch => {
                // Cannot happen outside dry_run
            }
        }
    }

    // 6. Generate user-global filters template (~/.config/ctxcrl/filters.toml)
    generate_global_filters_template(ctx)?;

    if !dry_run {
        println!(); // Final newline
    }

    Ok(())
}

/// Migrate old hook script to new binary command.
/// Deletes `~/.claude/hooks/rtk-rewrite.sh` and `.ctxcrl-hook.sha256` if present,
/// and removes the stale settings.json entry so the new `contextcrawler hook claude` entry
/// can be registered.
fn migrate_old_hook_script(ctx: InitContext) {
    let InitContext { verbose, dry_run } = ctx;
    if let Some(home) = dirs::home_dir() {
        let old_hook = home
            .join(CLAUDE_DIR)
            .join(HOOKS_SUBDIR)
            .join(REWRITE_HOOK_FILE);
        if old_hook.exists() {
            if dry_run {
                println!(
                    "[dry-run] would migrate legacy hook script: {}",
                    old_hook.display()
                );
            // nosemgrep: filesystem-deletion
            } else if let Err(e) = std::fs::remove_file(&old_hook) {
                if verbose > 0 {
                    eprintln!("  [warn] Failed to remove old hook script: {e}");
                }
            } else {
                if verbose > 0 {
                    eprintln!("  [ok] Removed old hook script: {}", old_hook.display());
                }
                // Clean up the stale settings.json entry that pointed to the deleted script
                if let Err(e) = remove_legacy_settings_entries(ctx) {
                    if verbose > 0 {
                        eprintln!("  [warn] Failed to clean legacy settings.json entry: {e}");
                    }
                }
            }
        }
        // Remove legacy hash file
        let hash_file = home
            .join(CLAUDE_DIR)
            .join(HOOKS_SUBDIR)
            .join(".ctxcrl-hook.sha256");
        if hash_file.exists() {
            if dry_run {
                println!(
                    "[dry-run] would remove legacy hash file: {}",
                    hash_file.display()
                );
            } else {
                let _ = std::fs::remove_file(&hash_file);
            }
        }
        // Remove Cursor legacy hook
        let cursor_hook = home.join(CURSOR_DIR).join("hooks").join(REWRITE_HOOK_FILE);
        if cursor_hook.exists() {
            if dry_run {
                println!(
                    "[dry-run] would remove legacy Cursor hook: {}",
                    cursor_hook.display()
                );
            } else {
                let _ = std::fs::remove_file(&cursor_hook);
            }
        }
    }
}

/// Remove only legacy `rtk-rewrite.sh` entries from settings.json.
/// Preserves any existing `contextcrawler hook claude` entries (new format).
fn remove_legacy_settings_entries(ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    let claude_dir = resolve_claude_dir()?;
    let settings_path = claude_dir.join(SETTINGS_JSON);

    if !settings_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&settings_path)
        .with_context(|| format!("Failed to read {}", settings_path.display()))?;
    if content.trim().is_empty() {
        return Ok(());
    }

    let mut root: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", settings_path.display()))?;

    if !remove_legacy_hook_entries_from_json(&mut root) {
        return Ok(());
    }

    if dry_run {
        println!(
            "[dry-run] would remove legacy rtk-rewrite.sh entry from {}",
            settings_path.display()
        );
        return Ok(());
    }

    // Backup before modifying
    let backup_path = settings_path.with_extension("json.bak");
    fs::copy(&settings_path, &backup_path)
        .with_context(|| format!("Failed to backup to {}", backup_path.display()))?;

    let serialized =
        serde_json::to_string_pretty(&root).context("Failed to serialize settings.json")?;
    atomic_write(&settings_path, &serialized)?;

    if verbose > 0 {
        eprintln!("  [ok] Removed legacy rtk-rewrite.sh entry from settings.json");
    }
    Ok(())
}

/// Remove only legacy `rtk-rewrite.sh` hook entries from a parsed settings.json.
/// Returns true if any entries were removed.
/// Does NOT remove `contextcrawler hook claude` entries — those are the new format.
fn remove_legacy_hook_entries_from_json(root: &mut serde_json::Value) -> bool {
    let pre_tool_use_array = match root
        .get_mut("hooks")
        .and_then(|h| h.get_mut(PRE_TOOL_USE_KEY))
        .and_then(|p| p.as_array_mut())
    {
        Some(arr) => arr,
        None => return false,
    };

    let original_len = pre_tool_use_array.len();
    pre_tool_use_array.retain(|entry| {
        let dominated_by_legacy = entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|hooks| {
                hooks.iter().all(|hook| {
                    hook.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(command_is_legacy_rewrite_hook)
                })
            })
            .unwrap_or(false);
        !dominated_by_legacy
    });

    pre_tool_use_array.len() < original_len
}

/// Generate .ctxcrl/filters.toml template in the current directory if not present.
fn generate_project_filters_template(ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    let ctxcrl_dir = std::path::Path::new(".ctxcrl");
    let path = ctxcrl_dir.join("filters.toml");

    if path.exists() {
        if verbose > 0 {
            eprintln!(".ctxcrl/filters.toml already exists, skipping template");
        }
        return Ok(());
    }

    if dry_run {
        println!(
            "[dry-run] would create .ctxcrl/filters.toml template: {}",
            path.display()
        );
        return Ok(());
    }

    fs::create_dir_all(ctxcrl_dir)
        .with_context(|| format!("Failed to create directory: {}", ctxcrl_dir.display()))?;
    fs::write(&path, FILTERS_TEMPLATE)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!(
        "  filters:   {} (template, edit to add project filters)",
        path.display()
    );
    Ok(())
}

/// Generate ~/.config/ctxcrl/filters.toml template if not present.
fn generate_global_filters_template(ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    let config_dir = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from(".config"));
    let ctxcrl_dir = config_dir.join(crate::core::constants::RTK_DATA_DIR);
    let path = ctxcrl_dir.join("filters.toml");

    if path.exists() {
        if verbose > 0 {
            eprintln!("{} already exists, skipping template", path.display());
        }
        return Ok(());
    }

    if dry_run {
        println!(
            "[dry-run] would create global filters template: {}",
            path.display()
        );
        return Ok(());
    }

    fs::create_dir_all(&ctxcrl_dir)
        .with_context(|| format!("Failed to create directory: {}", ctxcrl_dir.display()))?;
    fs::write(&path, FILTERS_GLOBAL_TEMPLATE)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!(
        "  filters:   {} (template, edit to add user-global filters)",
        path.display()
    );
    Ok(())
}

/// Hook-only mode: just the hook, no CONTEXTCRAWLER.md
fn run_hook_only_mode(
    global: bool,
    patch_mode: PatchMode,
    install_opencode: bool,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    if !global {
        eprintln!("[warn] Warning: --hook-only only makes sense with --global");
        eprintln!("    For local projects, use default mode or --claude-md");
        return Ok(());
    }

    // Migrate old hook script if present
    migrate_old_hook_script(ctx);

    let opencode_plugin_path = if install_opencode {
        let path = prepare_opencode_plugin_path()?;
        ensure_opencode_plugin_installed(&path, ctx)?;
        Some(path)
    } else {
        None
    };

    if !dry_run {
        println!("\nContextCrawler hook registered (hook-only mode).\n");
        println!("  Command: {}", CLAUDE_HOOK_COMMAND);
        if let Some(path) = &opencode_plugin_path {
            println!("  OpenCode: {}", path.display());
        }
        println!(
            "  Note: No CONTEXTCRAWLER.md created. Claude won't know about meta commands (gain, discover, proxy)."
        );
    }

    // Patch settings.json with binary command
    let patch_result =
        patch_settings_json_command(CLAUDE_HOOK_COMMAND, patch_mode, install_opencode, ctx)?;

    // Report result
    if !dry_run {
        match patch_result {
            PatchResult::Patched => {
                // Already printed by patch_settings_json_command
            }
            PatchResult::AlreadyPresent => {
                println!("\n  settings.json: hook already present");
                if install_opencode {
                    println!("  Restart Claude Code and OpenCode. Test with: git status");
                } else {
                    println!("  Restart Claude Code. Test with: git status");
                }
            }
            PatchResult::Declined | PatchResult::Skipped => {
                // Manual instructions already printed
            }
            PatchResult::WouldPatch => {
                // Cannot happen outside dry_run
            }
        }
    }

    if !dry_run {
        println!(); // Final newline
    }

    Ok(())
}

/// Legacy mode: full 137-line injection into CLAUDE.md
fn run_claude_md_mode(global: bool, install_opencode: bool, ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    let path = if global {
        resolve_claude_dir()?.join(CLAUDE_MD)
    } else {
        PathBuf::from(CLAUDE_MD)
    };

    if global && !dry_run {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }

    if verbose > 0 {
        eprintln!("Writing contextcrawler instructions to: {}", path.display());
    }

    let recovery_cmd = if global {
        "contextcrawler init -g --claude-md"
    } else {
        "contextcrawler init --claude-md"
    };

    // write_ctxcrl_block handles all 4 cases: add, update, unchanged, malformed.
    // A malformed CLAUDE.md bails with a diagnostic instead of silently
    // exiting 0 and skipping the OpenCode plugin step below.
    let action = write_ctxcrl_block(
        &path,
        CTXCRL_INSTRUCTIONS,
        "contextcrawler instructions",
        recovery_cmd,
        ctx,
    )?;

    if matches!(action, CtxcrlBlockUpsert::Unchanged) {
        return Ok(());
    }

    if global {
        if install_opencode {
            let opencode_plugin_path = prepare_opencode_plugin_path()?;
            ensure_opencode_plugin_installed(&opencode_plugin_path, ctx)?;
            if !dry_run {
                println!(
                    "[ok] OpenCode plugin installed: {}",
                    opencode_plugin_path.display()
                );
            }
        }
        if !dry_run {
            println!("   Claude Code will now use contextcrawler in all sessions");
        }
    } else if !dry_run {
        println!("   Claude Code will use contextcrawler in this project");
    }

    Ok(())
}

// ─── Windsurf support ─────────────────────────────────────────

// ─── Cline / Roo Code support ─────────────────────────────────

fn run_cline_mode(ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    // Cline reads .clinerules from the project root (workspace-scoped)
    let rules_path = PathBuf::from(".clinerules");

    let existing = fs::read_to_string(&rules_path).unwrap_or_default();
    if existing.contains("RTK") || existing.contains("rtk") {
        if !dry_run {
            println!("\nContextCrawler already configured for Cline in this project.\n");
            println!("  Rules: .clinerules (already present)");
        }
    } else {
        let cline_guidance = agent_guidance(AGENT_CLINE)?;
        let new_content = if existing.trim().is_empty() {
            cline_guidance
        } else {
            format!("{}\n\n{}", existing.trim(), cline_guidance)
        };
        if dry_run {
            println!(
                "[dry-run] would write .clinerules: {}",
                rules_path.display()
            );
            if verbose > 0 {
                println!("[dry-run] content:\n{}", new_content);
            }
        } else {
            fs::write(&rules_path, &new_content).context("Failed to write .clinerules")?;

            if verbose > 0 {
                eprintln!("Wrote .clinerules");
            }

            println!("\nContextCrawler configured for Cline.\n");
            println!("  Rules: .clinerules (installed)");
        }
    }
    if !dry_run {
        println!("  Cline will now use contextcrawler commands for token savings.");
        println!("  Test with: git status\n");
    }

    Ok(())
}

fn run_windsurf_mode(ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    // Windsurf reads .windsurfrules from the project root (workspace-scoped).
    // Global rules (~/.codeium/windsurf/memories/global_rules.md) are unreliable.
    let rules_path = PathBuf::from(".windsurfrules");

    let existing = fs::read_to_string(&rules_path).unwrap_or_default();
    if existing.contains("RTK") || existing.contains("rtk") {
        if !dry_run {
            println!("\nContextCrawler already configured for Windsurf in this project.\n");
            println!("  Rules: .windsurfrules (already present)");
        }
    } else {
        let windsurf_guidance = agent_guidance(AGENT_WINDSURF)?;
        let new_content = if existing.trim().is_empty() {
            windsurf_guidance
        } else {
            format!("{}\n\n{}", existing.trim(), windsurf_guidance)
        };
        if dry_run {
            println!(
                "[dry-run] would write .windsurfrules: {}",
                rules_path.display()
            );
            if verbose > 0 {
                println!("[dry-run] content:\n{}", new_content);
            }
        } else {
            fs::write(&rules_path, &new_content).context("Failed to write .windsurfrules")?;

            if verbose > 0 {
                eprintln!("Wrote .windsurfrules");
            }

            println!("\nContextCrawler configured for Windsurf Cascade.\n");
            println!("  Rules: .windsurfrules (installed)");
        }
    }
    if !dry_run {
        println!("  Cascade will now use contextcrawler commands for token savings.");
        println!("  Restart Windsurf. Test with: git status\n");
    }

    Ok(())
}

// ─── Kilo Code support ────────────────────────────────────────

pub fn run_kilocode_mode(ctx: InitContext) -> Result<()> {
    run_kilocode_mode_at(&std::env::current_dir()?, ctx)
}

fn run_kilocode_mode_at(base_dir: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    // Kilo Code reads .kilocode/rules/ from the project root (workspace-scoped)
    let target_dir = base_dir.join(".kilocode/rules");
    let rules_path = target_dir.join("rtk-rules.md");

    let existing = fs::read_to_string(&rules_path).unwrap_or_default();
    if existing.contains("RTK") || existing.contains("rtk") {
        if !dry_run {
            println!("\nContextCrawler already configured for Kilo Code in this project.\n");
            println!("  Rules: .kilocode/rules/rtk-rules.md (already present)");
        }
    } else {
        let kilocode_guidance = agent_guidance(AGENT_KILOCODE)?;
        let new_content = if existing.trim().is_empty() {
            kilocode_guidance
        } else {
            format!("{}\n\n{}", existing.trim(), kilocode_guidance)
        };
        if dry_run {
            println!(
                "[dry-run] would write {}: (and create parent dir if missing)",
                rules_path.display()
            );
            if verbose > 0 {
                println!("[dry-run] content:\n{}", new_content);
            }
        } else {
            fs::create_dir_all(&target_dir)
                .context("Failed to create .kilocode/rules directory")?;
            fs::write(&rules_path, &new_content)
                .context("Failed to write .kilocode/rules/rtk-rules.md")?;

            if verbose > 0 {
                eprintln!("Wrote .kilocode/rules/rtk-rules.md");
            }

            println!("\nContextCrawler configured for Kilo Code.\n");
            println!("  Rules: .kilocode/rules/rtk-rules.md (installed)");
        }
    }
    if dry_run {
        print_dry_run_footer();
    } else {
        println!("  Kilo Code will now use contextcrawler commands for token savings.");
        println!("  Test with: git status\n");
    }

    Ok(())
}

// ─── Google Antigravity support ───────────────────────────────

pub fn run_antigravity_mode(ctx: InitContext) -> Result<()> {
    run_antigravity_mode_at(&std::env::current_dir()?, ctx)
}

fn run_antigravity_mode_at(base_dir: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    // Antigravity reads .agents/rules/ from the project root (workspace-scoped)
    let target_dir = base_dir.join(".agents/rules");
    let rules_path = target_dir.join("antigravity-rtk-rules.md");

    let existing = fs::read_to_string(&rules_path).unwrap_or_default();
    if existing.contains("RTK") || existing.contains("rtk") {
        if !dry_run {
            println!("\nContextCrawler already configured for Antigravity in this project.\n");
            println!("  Rules: .agents/rules/antigravity-rtk-rules.md (already present)");
        }
    } else {
        let antigravity_guidance = agent_guidance(AGENT_ANTIGRAVITY)?;
        let new_content = if existing.trim().is_empty() {
            antigravity_guidance
        } else {
            format!("{}\n\n{}", existing.trim(), antigravity_guidance)
        };
        if dry_run {
            println!(
                "[dry-run] would write {}: (and create parent dir if missing)",
                rules_path.display()
            );
            if verbose > 0 {
                println!("[dry-run] content:\n{}", new_content);
            }
        } else {
            fs::create_dir_all(&target_dir).context("Failed to create .agents/rules directory")?;
            fs::write(&rules_path, &new_content)
                .context("Failed to write .agents/rules/antigravity-rtk-rules.md")?;

            if verbose > 0 {
                eprintln!("Wrote .agents/rules/antigravity-rtk-rules.md");
            }

            println!("\nContextCrawler configured for Google Antigravity.\n");
            println!("  Rules: .agents/rules/antigravity-rtk-rules.md (installed)");
        }
    }
    if dry_run {
        print_dry_run_footer();
    } else {
        println!("  Antigravity will now use contextcrawler commands for token savings.");
        println!("  Test with: git status\n");
    }

    Ok(())
}

// ─── Hermes support ────────────────────────────────────────────

const HERMES_PLUGIN_INIT: &str = include_str!("../../hooks/hermes/ctxcrl-rewrite/__init__.py");
const HERMES_PLUGIN_YAML: &str = include_str!("../../hooks/hermes/ctxcrl-rewrite/plugin.yaml");

pub fn run_hermes_mode(ctx: InitContext) -> Result<()> {
    let hermes_home = resolve_hermes_home()?;
    run_hermes_mode_at(&hermes_home, ctx)
}

fn hermes_plugin_dir(hermes_home: &Path) -> PathBuf {
    hermes_home
        .join(HERMES_PLUGINS_SUBDIR)
        .join(HERMES_PLUGIN_NAME)
}

fn run_hermes_mode_at(hermes_home: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    let plugin_dir = hermes_plugin_dir(hermes_home);
    if !dry_run {
        fs::create_dir_all(&plugin_dir).with_context(|| {
            format!(
                "Failed to create Hermes plugin directory: {}",
                plugin_dir.display()
            )
        })?;
    }

    let init_path = plugin_dir.join(HERMES_PLUGIN_INIT_FILE);
    let manifest_path = plugin_dir.join(HERMES_PLUGIN_MANIFEST_FILE);
    write_if_changed(&init_path, HERMES_PLUGIN_INIT, "Hermes plugin", ctx)?;
    write_if_changed(
        &manifest_path,
        HERMES_PLUGIN_YAML,
        "Hermes plugin manifest",
        ctx,
    )?;

    let config_path = hermes_home.join("config.yaml");
    let existing_config = if config_path.exists() {
        fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read Hermes config: {}", config_path.display()))?
    } else {
        String::new()
    };
    let patched_config = patch_hermes_config(&existing_config);
    write_if_changed(&config_path, &patched_config, "Hermes config", ctx)?;

    // Upsert guidance as a marked block into ~/.hermes/AGENTS.md.
    // Hermes auto-loads AGENTS.md at session start; it does not read a
    // standalone CONTEXTCRAWLER.md. Only the marked block is touched —
    // user content in AGENTS.md is preserved.
    let agents_md_path = hermes_home.join(AGENTS_MD);
    write_ctxcrl_block(
        &agents_md_path,
        &agent_guidance_block(AGENT_HERMES)?,
        "Hermes guidance",
        "contextcrawler init --agent hermes",
        ctx,
    )?;

    if dry_run {
        print_dry_run_footer();
    } else {
        println!("\nContextCrawler configured for Hermes.\n");
        println!("  Plugin:   {}", plugin_dir.display());
        println!("  Config:   {}", config_path.display());
        println!("  Guidance: {}", agents_md_path.display());
        println!("  Hermes will now rewrite terminal commands through contextcrawler.");
        println!("  Restart Hermes. Test with: git status\n");
    }

    Ok(())
}

pub fn uninstall_hermes(ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    let hermes_home = resolve_hermes_home()?;
    let removed = uninstall_hermes_at(&hermes_home, ctx)?;

    if removed.is_empty() {
        println!("ContextCrawler Hermes support was not installed (nothing to remove)");
    } else {
        let header = if dry_run {
            "[dry-run] would uninstall ContextCrawler for Hermes CLI:"
        } else {
            "ContextCrawler uninstalled for Hermes CLI:"
        };
        println!("{}", header);
        for item in removed {
            println!("  - {}", item);
        }
    }

    if dry_run {
        print_dry_run_footer();
    }

    Ok(())
}

fn uninstall_hermes_at(hermes_home: &Path, ctx: InitContext) -> Result<Vec<String>> {
    let InitContext { verbose, dry_run } = ctx;
    let mut removed = Vec::new();

    let plugin_dir = hermes_plugin_dir(hermes_home);
    if plugin_dir.exists() {
        if dry_run {
            println!(
                "[dry-run] would remove Hermes plugin directory: {}",
                plugin_dir.display()
            );
        } else {
            // nosemgrep: filesystem-deletion -- uninstall intentionally removes only ContextCrawler's Hermes plugin directory.
            fs::remove_dir_all(&plugin_dir).with_context(|| {
                format!(
                    "Failed to remove Hermes plugin directory: {}",
                    plugin_dir.display()
                )
            })?;
            if verbose > 0 {
                eprintln!("Removed Hermes plugin directory: {}", plugin_dir.display());
            }
        }
        removed.push(format!("Hermes plugin: {}", plugin_dir.display()));
    }

    let config_path = hermes_home.join("config.yaml");
    if config_path.exists() {
        let existing_config = fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read Hermes config: {}", config_path.display()))?;
        let patched_config = unpatch_hermes_config(&existing_config);

        if patched_config != existing_config {
            if dry_run {
                println!(
                    "[dry-run] would update Hermes config: {}",
                    config_path.display()
                );
                if verbose > 0 {
                    println!("[dry-run] content:\n{}", patched_config);
                }
            } else {
                atomic_write(&config_path, &patched_config).with_context(|| {
                    format!("Failed to write Hermes config: {}", config_path.display())
                })?;
                if verbose > 0 {
                    eprintln!("Updated Hermes config: {}", config_path.display());
                }
            }
            removed.push("Hermes config: removed ContextCrawler plugin entry".to_string());
        }
    }

    // Strip the ContextCrawler guidance block from ~/.hermes/AGENTS.md.
    // Only the marked block is removed — user content in AGENTS.md is kept.
    let agents_md_path = hermes_home.join(AGENTS_MD);
    if let Some(desc) = strip_ctxcrl_block_from_file(&agents_md_path, "Hermes guidance", ctx)? {
        removed.push(desc);
    }

    Ok(removed)
}

fn patch_hermes_config(existing: &str) -> String {
    rewrite_hermes_config(existing, true)
}

fn unpatch_hermes_config(existing: &str) -> String {
    rewrite_hermes_config(existing, false)
}

fn rewrite_hermes_config(existing: &str, add_plugin: bool) -> String {
    if existing.trim().is_empty() {
        return if add_plugin {
            hermes_plugins_block()
        } else {
            String::new()
        };
    }

    let mut lines = split_yaml_lines(existing);
    let Some(plugins_idx) = find_yaml_key_line(&lines, "plugins", 0, None) else {
        return if add_plugin {
            append_hermes_plugins_block(existing)
        } else {
            existing.to_string()
        };
    };

    let plugins_indent = yaml_indent(&lines[plugins_idx]);
    let plugins_end = yaml_block_end(&lines, plugins_idx, plugins_indent);
    let Some(enabled_idx) = find_yaml_key_line(
        &lines,
        "enabled",
        plugins_idx + 1,
        Some((plugins_end, plugins_indent)),
    ) else {
        if add_plugin {
            let (enabled_indent, item_indent) =
                hermes_missing_enabled_indents(&lines, plugins_idx, plugins_end, plugins_indent);
            let enabled_block = format!(
                "{}enabled:\n{}- {}\n",
                " ".repeat(enabled_indent),
                " ".repeat(item_indent),
                HERMES_PLUGIN_NAME
            );
            ensure_previous_yaml_line_ends_with_newline(&mut lines, plugins_end);
            lines.insert(plugins_end, enabled_block);
        }
        return lines.concat();
    };

    if yaml_line_without_ending(&lines[enabled_idx]).contains('[') {
        rewrite_inline_hermes_enabled(&mut lines, enabled_idx, add_plugin);
        return lines.concat();
    }

    rewrite_block_hermes_enabled(&mut lines, enabled_idx, add_plugin);
    lines.concat()
}

fn split_yaml_lines(input: &str) -> Vec<String> {
    if input.is_empty() {
        Vec::new()
    } else {
        input.split_inclusive('\n').map(str::to_string).collect()
    }
}

fn ensure_previous_yaml_line_ends_with_newline(lines: &mut [String], insert_idx: usize) {
    if insert_idx == 0 {
        return;
    }

    if let Some(previous) = lines.get_mut(insert_idx - 1) {
        if !previous.ends_with('\n') {
            previous.push('\n');
        }
    }
}

fn hermes_plugins_block() -> String {
    format!("plugins:\n  enabled:\n    - {}\n", HERMES_PLUGIN_NAME)
}

fn append_hermes_plugins_block(existing: &str) -> String {
    let mut patched = existing.to_string();
    if !patched.ends_with('\n') {
        patched.push('\n');
    }
    patched.push_str(&hermes_plugins_block());
    patched
}

fn find_yaml_key_line(
    lines: &[String],
    key: &str,
    start: usize,
    block: Option<(usize, usize)>,
) -> Option<usize> {
    let end = block.map_or(lines.len(), |(end, _)| end);
    let min_indent = block.map(|(_, indent)| indent);

    lines[start..end]
        .iter()
        .enumerate()
        .find_map(|(offset, line)| {
            let raw = yaml_line_without_ending(line);
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }

            if min_indent.is_some_and(|indent| yaml_indent(line) <= indent) {
                return None;
            }

            let is_key = trimmed == format!("{key}:") || trimmed.starts_with(&format!("{key}:"));
            is_key.then_some(start + offset)
        })
}

fn yaml_block_end(lines: &[String], start: usize, parent_indent: usize) -> usize {
    lines[start + 1..]
        .iter()
        .enumerate()
        .find_map(|(offset, line)| {
            let raw = yaml_line_without_ending(line);
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }

            (yaml_indent(line) <= parent_indent).then_some(start + 1 + offset)
        })
        .unwrap_or(lines.len())
}

fn rewrite_inline_hermes_enabled(lines: &mut [String], enabled_idx: usize, add_plugin: bool) {
    let line_ending = yaml_line_ending(&lines[enabled_idx]);
    let raw = yaml_line_without_ending(&lines[enabled_idx]);
    let Some((prefix, rest)) = raw.split_once('[') else {
        return;
    };
    let Some((items_raw, suffix)) = rest.rsplit_once(']') else {
        return;
    };

    let mut items = Vec::new();
    let mut saw_plugin = false;
    for item in items_raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        if is_hermes_plugin_name(trimmed) {
            if add_plugin && !saw_plugin {
                items.push(trimmed.to_string());
                saw_plugin = true;
            }
        } else {
            items.push(trimmed.to_string());
        }
    }

    if add_plugin && !saw_plugin {
        items.push(HERMES_PLUGIN_NAME.to_string());
    }

    let replacement = if items.is_empty() {
        format!("{}[]{}{}", prefix, suffix, line_ending)
    } else {
        format!("{}[{}]{}{}", prefix, items.join(", "), suffix, line_ending)
    };
    lines[enabled_idx] = replacement;
}

fn rewrite_block_hermes_enabled(lines: &mut Vec<String>, enabled_idx: usize, add_plugin: bool) {
    let enabled_end = hermes_enabled_list_end(lines, enabled_idx);
    let item_indent = hermes_enabled_list_item_indent(lines, enabled_idx, enabled_end);
    let mut kept = Vec::with_capacity(lines.len() + 1);
    let mut saw_plugin = false;

    for line in &lines[enabled_idx + 1..enabled_end] {
        if is_yaml_list_item_named(line, HERMES_PLUGIN_NAME) {
            if add_plugin && !saw_plugin {
                kept.push(line.clone());
                saw_plugin = true;
            }
            continue;
        }

        kept.push(line.clone());
    }

    if add_plugin && !saw_plugin {
        let insert_idx = kept.len();
        ensure_previous_yaml_line_ends_with_newline(&mut kept, insert_idx);
        kept.push(format!(
            "{}- {}\n",
            " ".repeat(item_indent),
            HERMES_PLUGIN_NAME
        ));
    }

    let mut enabled_line = if add_plugin || kept.iter().any(|line| is_yaml_list_item_line(line)) {
        lines[enabled_idx].clone()
    } else {
        collapse_yaml_list_key_to_empty(&lines[enabled_idx])
    };

    if add_plugin
        && kept
            .iter()
            .any(|line| is_yaml_list_item_named(line, HERMES_PLUGIN_NAME))
        && !enabled_line.ends_with('\n')
    {
        enabled_line.push('\n');
    }

    let mut patched = Vec::with_capacity(lines.len() + 1);
    patched.extend_from_slice(&lines[..enabled_idx]);
    patched.push(enabled_line);
    patched.extend(kept);
    patched.extend_from_slice(&lines[enabled_end..]);
    *lines = patched;
}

fn hermes_enabled_list_end(lines: &[String], enabled_idx: usize) -> usize {
    let enabled_indent = yaml_indent(&lines[enabled_idx]);

    lines[enabled_idx + 1..]
        .iter()
        .enumerate()
        .find_map(|(offset, line)| {
            let raw = yaml_line_without_ending(line);
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }

            let indent = yaml_indent(line);
            if indent < enabled_indent
                || (indent == enabled_indent && !is_yaml_list_item_line(line))
            {
                return Some(enabled_idx + 1 + offset);
            }

            None
        })
        .unwrap_or(lines.len())
}

fn hermes_enabled_list_item_indent(
    lines: &[String],
    enabled_idx: usize,
    enabled_end: usize,
) -> usize {
    lines[enabled_idx + 1..enabled_end]
        .iter()
        .find(|line| is_yaml_list_item_line(line))
        .map(|line| yaml_indent(line))
        .unwrap_or_else(|| yaml_indent(&lines[enabled_idx]) + 2)
}

fn hermes_missing_enabled_indents(
    lines: &[String],
    plugins_idx: usize,
    plugins_end: usize,
    plugins_indent: usize,
) -> (usize, usize) {
    let child_indent = lines[plugins_idx + 1..plugins_end]
        .iter()
        .filter_map(|line| {
            let raw = yaml_line_without_ending(line);
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }

            let indent = yaml_indent(line);
            (indent > plugins_indent).then_some(indent)
        })
        .min()
        .unwrap_or(plugins_indent + 2);

    let uses_indentationless_sequences = lines[plugins_idx + 1..plugins_end]
        .iter()
        .any(|line| is_yaml_list_item_line(line) && yaml_indent(line) == child_indent);

    let item_indent = if uses_indentationless_sequences {
        child_indent
    } else {
        child_indent + 2
    };

    (child_indent, item_indent)
}

fn yaml_line_without_ending(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn yaml_line_ending(line: &str) -> &str {
    if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else {
        ""
    }
}

fn yaml_indent(line: &str) -> usize {
    yaml_line_without_ending(line)
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .count()
}

fn is_yaml_list_item_named(line: &str, expected: &str) -> bool {
    let trimmed = yaml_line_without_ending(line).trim();
    let Some(item) = trimmed.strip_prefix("- ") else {
        return false;
    };

    normalized_yaml_scalar(item).is_some_and(|item| item == expected)
}

fn is_yaml_list_item_line(line: &str) -> bool {
    yaml_line_without_ending(line).trim().starts_with("- ")
}

fn is_hermes_plugin_name(value: &str) -> bool {
    normalized_yaml_scalar(value).is_some_and(|item| item == HERMES_PLUGIN_NAME)
}

fn collapse_yaml_list_key_to_empty(line: &str) -> String {
    let raw = yaml_line_without_ending(line);
    let indent = yaml_indent(line);
    let Some((key, suffix)) = raw.split_once(':') else {
        return format!("{}enabled: []\n", " ".repeat(indent));
    };

    let comment = suffix
        .find('#')
        .map(|idx| format!(" {}", suffix[idx..].trim_start()))
        .unwrap_or_default();

    format!("{}: []{}\n", key, comment)
}

fn normalized_yaml_scalar(value: &str) -> Option<String> {
    let without_comment = value.split_once('#').map_or(value, |(item, _)| item);
    let trimmed = without_comment.trim().trim_matches(['\'', '"']);
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn run_codex_mode(global: bool, ctx: InitContext) -> Result<()> {
    let (agents_md_path, ctxcrl_md_path) = if global {
        let codex_dir = resolve_codex_dir()?;
        (codex_dir.join(AGENTS_MD), codex_dir.join(CTXCRL_MD))
    } else {
        (PathBuf::from(AGENTS_MD), PathBuf::from(CTXCRL_MD))
    };

    run_codex_mode_with_paths(agents_md_path, ctxcrl_md_path, global, ctx)
}

fn run_codex_mode_with_paths(
    agents_md_path: PathBuf,
    ctxcrl_md_path: PathBuf,
    global: bool,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    if global && !dry_run {
        if let Some(parent) = agents_md_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create Codex config directory: {}",
                    parent.display()
                )
            })?;
        }
    }

    // ISSUE #892: In global mode, use absolute path so @CONTEXTCRAWLER.md resolves
    // from any CWD (worktrees, nested projects). Codex resolves @ references
    // relative to CWD, not the AGENTS.md file location.
    let ctxcrl_md_ref = if global {
        codex_ctxcrl_md_ref(
            ctxcrl_md_path
                .parent()
                .context("CONTEXTCRAWLER.md path missing parent directory")?,
        )
    } else {
        CTXCRL_MD_REF.to_string()
    };

    write_if_changed(&ctxcrl_md_path, &agent_guidance(AGENT_CODEX)?, CTXCRL_MD, ctx)?;
    let added_ref = patch_agents_md(&agents_md_path, &ctxcrl_md_ref, ctx)?;

    // Clean up legacy filenames (e.g. RTK.md left behind by the regressed // branding-lint: allow legacy
    // bcddd06 commit) so users upgrading don't end up with two duplicate
    // imports in AGENTS.md and a stale orphan file on disk. See issue #19.
    let cleaned_legacy = cleanup_legacy_codex_files(
        &agents_md_path,
        ctxcrl_md_path
            .parent()
            .context("CONTEXTCRAWLER.md path missing parent directory")?,
        ctx,
    )?;

    if !dry_run {
        for note in &cleaned_legacy {
            println!("  cleaned legacy artifact: {}", note);
        }
        println!("\nContextCrawler configured for Codex CLI.\n");
        println!("  CONTEXTCRAWLER.md:    {}", ctxcrl_md_path.display());
        if added_ref {
            println!("  AGENTS.md: {} reference added", ctxcrl_md_ref);
        } else {
            println!("  AGENTS.md: {} reference already present", ctxcrl_md_ref);
        }
        if global {
            println!(
                "\n  Codex global instructions path: {}",
                agents_md_path.display()
            );
        } else {
            println!(
                "\n  Codex project instructions path: {}",
                agents_md_path.display()
            );
        }
    }

    Ok(())
}

// --- upsert_ctxcrl_block: idempotent ContextCrawler block management ---

#[derive(Debug, Clone, Copy, PartialEq)]
enum CtxcrlBlockUpsert {
    /// No existing block found — appended new block
    Added,
    /// Existing block found with different content — replaced
    Updated,
    /// Existing block found with identical content — no-op
    Unchanged,
    /// Opening marker found without closing marker — not safe to rewrite
    Malformed,
}

/// Insert or replace the ContextCrawler instructions block in `content`.
///
/// Returns `(new_content, action)` describing what happened.
/// The caller decides whether to write `new_content` based on `action`.
fn upsert_ctxcrl_block(content: &str, block: &str) -> (String, CtxcrlBlockUpsert) {
    // Recognise an existing block under either the canonical or the legacy
    // markers; we always WRITE the canonical block (`block` carries the new
    // markers), so a legacy block is replaced in place on upgrade.
    let (start_marker, end_marker) = block_markers_in(content)
        .unwrap_or((CTXCRL_BLOCK_START, CTXCRL_BLOCK_END));

    if let Some(start) = content.find(start_marker) {
        if let Some(relative_end) = content[start..].find(end_marker) {
            let end = start + relative_end;
            let end_pos = end + end_marker.len();
            let current_block = content[start..end_pos].trim();
            let desired_block = block.trim();

            if current_block == desired_block {
                return (content.to_string(), CtxcrlBlockUpsert::Unchanged);
            }

            // Replace stale block with desired block
            let before = content[..start].trim_end();
            let after = content[end_pos..].trim_start();

            let result = match (before.is_empty(), after.is_empty()) {
                (true, true) => desired_block.to_string(),
                (true, false) => format!("{desired_block}\n\n{after}"),
                (false, true) => format!("{before}\n\n{desired_block}"),
                (false, false) => format!("{before}\n\n{desired_block}\n\n{after}"),
            };

            return (result, CtxcrlBlockUpsert::Updated);
        }

        // Opening marker without closing marker — malformed
        return (content.to_string(), CtxcrlBlockUpsert::Malformed);
    }

    // No existing block — append
    let trimmed = content.trim();
    if trimmed.is_empty() {
        (block.to_string(), CtxcrlBlockUpsert::Added)
    } else {
        (
            format!("{trimmed}\n\n{}", block.trim()),
            CtxcrlBlockUpsert::Added,
        )
    }
}

/// Idempotently write a ContextCrawler-owned marker block into `path`,
/// preserving user content.
///
/// Reads the file (if any), passes it through [`upsert_ctxcrl_block`], and writes
/// the result back via [`atomic_write`]. Refuses to modify files containing an
/// opening marker without a matching closing marker (bails with a diagnostic
/// and the exact `recovery_cmd` to re-run after manual cleanup).
///
/// Returns the [`CtxcrlBlockUpsert`] action so callers can branch on whether
/// anything was actually changed.
///
/// `label` is shown in user-facing messages (e.g. `"Copilot instructions"`).
fn write_ctxcrl_block(
    path: &Path,
    block: &str,
    label: &str,
    recovery_cmd: &str,
    ctx: InitContext,
) -> Result<CtxcrlBlockUpsert> {
    let InitContext { dry_run, .. } = ctx;

    let existing = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?
    } else {
        String::new()
    };

    let (new_content, action) = upsert_ctxcrl_block(&existing, block);

    match action {
        CtxcrlBlockUpsert::Added => {
            if dry_run {
                println!("[dry-run] would add {} to {}", label, path.display());
            } else {
                atomic_write(path, &new_content)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                println!("[ok] Added {} to {}", label, path.display());
            }
        }
        CtxcrlBlockUpsert::Updated => {
            if dry_run {
                println!("[dry-run] would update {} in {}", label, path.display());
            } else {
                atomic_write(path, &new_content)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                println!("[ok] Updated {} in {}", label, path.display());
            }
        }
        CtxcrlBlockUpsert::Unchanged => {
            if !dry_run {
                println!("[ok] {} already up to date in {}", label, path.display());
            }
        }
        CtxcrlBlockUpsert::Malformed => {
            eprintln!(
                "[warn] Found '{}' without closing marker in {}",
                CTXCRL_BLOCK_START,
                path.display()
            );
            if let Some((line_num, _)) = existing
                .lines()
                .enumerate()
                .find(|(_, line)| line.contains(CTXCRL_BLOCK_START))
            {
                eprintln!("    Location: line {}", line_num + 1);
            }
            eprintln!("    Action: Manually remove the incomplete block, then re-run:");
            eprintln!("            {recovery_cmd}");
            anyhow::bail!("Refusing to modify malformed {} at {}", label, path.display());
        }
    }

    Ok(action)
}

/// Patch CLAUDE.md: add @CONTEXTCRAWLER.md, migrate if old block exists
fn patch_claude_md(path: &Path, ctx: InitContext) -> Result<bool> {
    let InitContext { verbose, dry_run } = ctx;
    let mut content = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };

    let mut migrated = false;

    // Check for old block and migrate
    if contains_ctxcrl_block(&content) {
        let (new_content, did_migrate) = remove_ctxcrl_block(&content);
        if did_migrate {
            content = new_content;
            migrated = true;
            if verbose > 0 {
                eprintln!("Migrated: removed old ContextCrawler block from CLAUDE.md");
            }
        }
    }

    // Migrate legacy `@CONTEXTCRAWLER.md` line(s) to the canonical `CTXCRL_MD_REF`. On an
    // upgraded install CLAUDE.md may still reference the old filename — left
    // alone, the contains-check below misses it and the appender adds a
    // second line, leaving both references in place. See codex review on #19.
    for legacy in LEGACY_CTXCRL_MD_FILES {
        let legacy_ref = format!("@{}", legacy);
        if content.contains(&legacy_ref) {
            // Replace whole-line occurrences only — substring replace could
            // mangle prose that incidentally mentions the legacy name.
            let migrated_content = content
                .lines()
                .map(|line| {
                    if line.trim() == legacy_ref.as_str() {
                        CTXCRL_MD_REF
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let mut migrated_content = migrated_content;
            if content.ends_with('\n') && !migrated_content.ends_with('\n') {
                migrated_content.push('\n');
            }
            if migrated_content != content {
                content = migrated_content;
                migrated = true;
                if verbose > 0 {
                    eprintln!(
                        "Migrated: {} -> {} in CLAUDE.md",
                        legacy_ref, CTXCRL_MD_REF
                    );
                }
            }
        }
    }

    // Check if @CONTEXTCRAWLER.md already present
    if content.contains(CTXCRL_MD_REF) {
        if verbose > 0 {
            eprintln!("@CONTEXTCRAWLER.md reference already present in CLAUDE.md");
        }
        if migrated {
            if dry_run {
                println!(
                    "[dry-run] would migrate old ContextCrawler block in CLAUDE.md: {}",
                    path.display()
                );
            } else {
                fs::write(path, content)?;
            }
        }
        return Ok(migrated);
    }

    // Add the @-reference. Must use CTXCRL_MD_REF (not a hardcoded literal) so
    // this stays in lock-step with the constant — see #19.
    let new_content = if content.is_empty() {
        format!("{}\n", CTXCRL_MD_REF)
    } else {
        format!("{}\n\n{}\n", content.trim(), CTXCRL_MD_REF)
    };

    if dry_run {
        println!(
            "[dry-run] would add @CONTEXTCRAWLER.md reference to CLAUDE.md: {}",
            path.display()
        );
        if verbose > 0 {
            println!("[dry-run] content:\n{}", new_content);
        }
    } else {
        fs::write(path, new_content)?;

        if verbose > 0 {
            eprintln!("Added @CONTEXTCRAWLER.md reference to CLAUDE.md");
        }
    }

    Ok(migrated)
}

/// Patch AGENTS.md: add @CONTEXTCRAWLER.md (or absolute path), migrate old inline block if present
fn patch_agents_md(path: &Path, ctxcrl_md_ref: &str, ctx: InitContext) -> Result<bool> {
    let InitContext { verbose, dry_run } = ctx;
    let mut content = if path.exists() {
        fs::read_to_string(path)
            .with_context(|| format!("Failed to read AGENTS.md: {}", path.display()))?
    } else {
        String::new()
    };

    let mut migrated = false;
    if contains_ctxcrl_block(&content) {
        let (new_content, did_migrate) = remove_ctxcrl_block(&content);
        if did_migrate {
            content = new_content;
            migrated = true;
            if verbose > 0 {
                eprintln!("Migrated: removed old ContextCrawler block from AGENTS.md");
            }
        }
    }

    // ISSUE #892: Check for both relative and absolute @CONTEXTCRAWLER.md references
    if content.contains(CTXCRL_MD_REF) || content.contains(ctxcrl_md_ref) {
        if verbose > 0 {
            eprintln!("{} reference already present in AGENTS.md", ctxcrl_md_ref);
        }
        // ISSUE #892: Migrate old relative @CONTEXTCRAWLER.md to absolute path if needed
        if ctxcrl_md_ref != CTXCRL_MD_REF && content.contains(CTXCRL_MD_REF) && !content.contains(ctxcrl_md_ref)
        {
            content = content.replace(CTXCRL_MD_REF, ctxcrl_md_ref);
            if dry_run {
                println!(
                    "[dry-run] would migrate {} to {} in {}",
                    CTXCRL_MD_REF,
                    ctxcrl_md_ref,
                    path.display()
                );
            } else {
                atomic_write(path, &content)
                    .with_context(|| format!("Failed to write AGENTS.md: {}", path.display()))?;
                if verbose > 0 {
                    eprintln!("Migrated {} to {}", CTXCRL_MD_REF, ctxcrl_md_ref);
                }
            }
            return Ok(true);
        }
        if migrated {
            if dry_run {
                println!(
                    "[dry-run] would write migrated AGENTS.md: {}",
                    path.display()
                );
            } else {
                atomic_write(path, &content)
                    .with_context(|| format!("Failed to write AGENTS.md: {}", path.display()))?;
            }
        }
        return Ok(false);
    }

    let new_content = if content.is_empty() {
        format!("{}\n", ctxcrl_md_ref)
    } else {
        format!("{}\n\n{}\n", content.trim(), ctxcrl_md_ref)
    };

    if dry_run {
        println!(
            "[dry-run] would add {} reference to AGENTS.md: {}",
            ctxcrl_md_ref,
            path.display()
        );
        if verbose > 0 {
            println!("[dry-run] content:\n{}", new_content);
        }
    } else {
        atomic_write(path, &new_content)
            .with_context(|| format!("Failed to write AGENTS.md: {}", path.display()))?;
        if verbose > 0 {
            eprintln!("Added {} reference to AGENTS.md", ctxcrl_md_ref);
        }
    }

    Ok(true)
}

fn has_rtk_reference(content: &str, refs: &[&str]) -> bool {
    content
        .lines()
        .map(str::trim)
        .any(|line| refs.contains(&line))
}

// `remove_rtk_reference_from_agents` was inlined into `uninstall_codex_at`
// for issue #26 (transactional safety — combine block + ref removal into
// one atomic write before any file deletion). The standalone helper has no
// other callers and was removed; the body lives at the bottom of
// `uninstall_codex_at` and is exercised by the same tests.

/// Remove old ContextCrawler block from CLAUDE.md (migration helper)
fn remove_ctxcrl_block(content: &str) -> (String, bool) {
    // Recognise both canonical and legacy markers so an upgraded/legacy block is
    // removed in place. `None` => no block at all.
    let Some((start_marker, end_marker)) = block_markers_in(content) else {
        return (content.to_string(), false);
    };
    if let (Some(start), Some(end)) = (content.find(start_marker), content.find(end_marker)) {
        let end_pos = end + end_marker.len();
        let before = content[..start].trim_end();
        let after = content[end_pos..].trim_start();

        let result = if after.is_empty() {
            format!("{}\n", before)
        } else {
            format!("{}\n\n{}", before, after)
        };

        (result, true) // migrated
    } else {
        // Opening marker present without its closing marker — malformed.
        eprintln!(
            "[warn] Warning: Found '{}' without closing marker.",
            start_marker
        );
        eprintln!("    This can happen if CLAUDE.md was manually edited.");

        if let Some((line_num, _)) = content
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains(start_marker))
        {
            eprintln!("    Location: line {}", line_num + 1);
        }

        eprintln!("    Action: Manually remove the incomplete block, then re-run:");
        eprintln!("            contextcrawler init -g");
        (content.to_string(), false)
    }
}

/// Strip the ContextCrawler guidance marker block from a shared instructions file
/// (e.g. AGENTS.md), preserving any surrounding user content. If removing the
/// block empties the file, the file itself is deleted. No-op if the file is
/// missing or contains no block.
///
/// Returns `Some(description)` when something was removed (for uninstall
/// reporting), `None` otherwise.
fn strip_ctxcrl_block_from_file(
    path: &Path,
    label: &str,
    ctx: InitContext,
) -> Result<Option<String>> {
    let InitContext { verbose, dry_run } = ctx;

    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}: {}", label, path.display()))?;

    if !contains_ctxcrl_block(&content) {
        return Ok(None);
    }

    let (stripped, removed) = remove_ctxcrl_block(&content);
    if !removed {
        // Malformed block (opening marker, no closing marker) — remove_ctxcrl_block
        // already warned. Leave the file untouched.
        return Ok(None);
    }

    if dry_run {
        if stripped.trim().is_empty() {
            println!(
                "[dry-run] would remove {} (now empty): {}",
                label,
                path.display()
            );
        } else {
            println!(
                "[dry-run] would remove ContextCrawler guidance block from {}: {}",
                label,
                path.display()
            );
        }
        return Ok(Some(format!("{}: {}", label, path.display())));
    }

    if stripped.trim().is_empty() {
        // nosemgrep: filesystem-deletion -- only deletes a file we created and
        // that now holds nothing but our removed block.
        fs::remove_file(path)
            .with_context(|| format!("Failed to remove {}: {}", label, path.display()))?;
        if verbose > 0 {
            eprintln!("Removed {} (now empty): {}", label, path.display());
        }
    } else {
        atomic_write(path, &stripped)
            .with_context(|| format!("Failed to write {}: {}", label, path.display()))?;
        if verbose > 0 {
            eprintln!("Removed ContextCrawler guidance block from {}: {}", label, path.display());
        }
    }

    Ok(Some(format!("{}: {}", label, path.display())))
}

fn resolve_home_subdir(subdir: &str) -> Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(subdir))
        .context(if cfg!(windows) {
            "Cannot determine home directory. Is %USERPROFILE% set?"
        } else {
            "Cannot determine home directory. Is $HOME set?"
        })
}

/// Opt-in escape hatch for an env-var config root that resolves outside
/// `$HOME`. Off by default — production must never silently follow a
/// poisoned `RTK_CLAUDE_DIR` / `CODEX_HOME` / `HERMES_HOME` (e.g. from a
/// project `.env`) to a write/delete root outside the user's home.
const ALLOW_NONHOME_ROOT_ENV: &str = "CONTEXTCRAWLER_ALLOW_NONHOME_ROOT";

/// Cache for the opt-in flag. The env var is read EXACTLY ONCE, on first use
/// (#100 G2 Codex 2nd pass — PARTIAL 4): reading it per-call left a
/// theoretical TOCTOU window where a mid-run env change could flip the
/// escape-hatch decision between two `validate_env_root` calls.
static NONHOME_ROOT_ALLOWED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn nonhome_root_allowed() -> bool {
    *NONHOME_ROOT_ALLOWED.get_or_init(|| {
        std::env::var_os(ALLOW_NONHOME_ROOT_ENV).is_some_and(|v| !v.is_empty())
    })
}

/// `true` if `root`, after best-effort canonicalisation, does not start with
/// `home`. Best-effort: a path that doesn't exist yet falls back to a
/// lexical comparison of the raw path, which still catches the obvious
/// accidents (`=/etc`, `=/tmp/x`, a `..` escape).
fn root_escapes_home(root: &Path, home: &Path) -> bool {
    let canon_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let canon_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    !canon_root.starts_with(&canon_home)
}

/// Validate an env-var-derived config root (#100 G2 IMPORTANT 5).
///
/// A poisoned env var must not redirect file writes/deletes outside the
/// user's home. If the resolved root escapes `$HOME` we bail — unless the
/// caller has explicitly opted in via `CONTEXTCRAWLER_ALLOW_NONHOME_ROOT`.
fn validate_env_root(root: PathBuf, env_name: &str) -> Result<PathBuf> {
    if nonhome_root_allowed() {
        return Ok(root);
    }
    if let Some(home) = dirs::home_dir() {
        if root_escapes_home(&root, &home) {
            anyhow::bail!(
                "${} resolves outside $HOME: {}\n\
                 Refusing to use a config root outside your home directory. \
                 If this is intentional, set {}=1.",
                env_name,
                root.display(),
                ALLOW_NONHOME_ROOT_ENV
            );
        }
    }
    Ok(root)
}

fn resolve_claude_dir() -> Result<PathBuf> {
    if let Some(dir) = crate::core::env_compat::env_var("CTXCRL_CLAUDE_DIR") {
        return validate_env_root(PathBuf::from(dir), "CTXCRL_CLAUDE_DIR");
    }
    resolve_home_subdir(CLAUDE_DIR)
}

fn resolve_codex_dir() -> Result<PathBuf> {
    resolve_codex_dir_from(
        std::env::var_os("CODEX_HOME").map(PathBuf::from),
        dirs::home_dir(),
        nonhome_root_allowed(),
    )
}

fn resolve_codex_dir_from(
    codex_home: Option<PathBuf>,
    home_dir: Option<PathBuf>,
    allow_nonhome: bool,
) -> Result<PathBuf> {
    if let Some(path) = codex_home.filter(|path| !path.as_os_str().is_empty()) {
        // SECURITY (#100 G2 IMPORTANT 5): if `$CODEX_HOME` resolves outside
        // `$HOME`, bail. A poisoned `CODEX_HOME` (e.g. from a project
        // `.env`) would otherwise redirect init's config writes / uninstall
        // deletes outside the user's home. The explicit opt-in
        // `CONTEXTCRAWLER_ALLOW_NONHOME_ROOT=1` is the escape hatch for
        // genuine non-home setups (upstream Codex CLI accepts them).
        if !allow_nonhome {
            if let Some(home) = home_dir.as_deref() {
                if root_escapes_home(&path, home) {
                    anyhow::bail!(
                        "$CODEX_HOME resolves outside $HOME: {}\n\
                         Refusing to use a config root outside your home directory. \
                         If this is intentional, set {}=1.",
                        path.display(),
                        ALLOW_NONHOME_ROOT_ENV
                    );
                }
            }
        }
        return Ok(path);
    }

    home_dir
        .map(|home| home.join(CODEX_DIR))
        .context("Cannot determine Codex config directory. Set $CODEX_HOME or $HOME.")
}

fn resolve_hermes_home() -> Result<PathBuf> {
    resolve_hermes_home_from_env(
        dirs::home_dir(),
        std::env::var_os("HERMES_HOME"),
        nonhome_root_allowed(),
    )
}

fn resolve_hermes_home_from_env(
    home_dir: Option<PathBuf>,
    hermes_home: Option<OsString>,
    allow_nonhome: bool,
) -> Result<PathBuf> {
    if let Some(path) = hermes_home.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        // SECURITY (#100 G2 IMPORTANT 5): reject a `$HERMES_HOME` that
        // escapes `$HOME` unless explicitly opted in. See `validate_env_root`.
        if !allow_nonhome {
            if let Some(home) = home_dir.as_deref() {
                if root_escapes_home(&path, home) {
                    anyhow::bail!(
                        "$HERMES_HOME resolves outside $HOME: {}\n\
                         Refusing to use a config root outside your home directory. \
                         If this is intentional, set {}=1.",
                        path.display(),
                        ALLOW_NONHOME_ROOT_ENV
                    );
                }
            }
        }
        return Ok(path);
    }

    home_dir
        .map(|home| home.join(HERMES_DIR))
        .context("Cannot determine Hermes home directory. Set $HERMES_HOME or $HOME.")
}

fn codex_ctxcrl_md_ref(codex_dir: &Path) -> String {
    format!("@{}", codex_dir.join(CTXCRL_MD).display())
}

/// Remove orphan files and stale @-references left behind by a previous
/// rename of the slim instructions file (see issue #19). Returns a list of
/// human-readable notes describing what was cleaned, for printing by the
/// caller. Idempotent — safe to run when nothing legacy exists.
fn cleanup_legacy_codex_files(
    agents_md_path: &Path,
    codex_dir: &Path,
    ctx: InitContext,
) -> Result<Vec<String>> {
    let InitContext { dry_run, .. } = ctx;
    let mut notes = Vec::new();

    let canonical = codex_dir.join(CTXCRL_MD);
    for legacy in LEGACY_CTXCRL_MD_FILES {
        let legacy_path = codex_dir.join(legacy);
        // Don't remove the canonical file even if it happens to share a name.
        if legacy_path == canonical {
            continue;
        }
        if legacy_path.exists() {
            if !dry_run {
                fs::remove_file(&legacy_path).with_context(|| {
                    format!("Failed to remove legacy file: {}", legacy_path.display())
                })?;
            }
            notes.push(format!("removed orphan {}", legacy_path.display()));
        }
    }

    // Strip stale `@<legacy>` reference lines from AGENTS.md so the agent
    // doesn't keep loading both the old and new files.
    if agents_md_path.exists() {
        let content = fs::read_to_string(agents_md_path).with_context(|| {
            format!("Failed to read AGENTS.md: {}", agents_md_path.display())
        })?;
        let mut new_content = content.clone();
        for legacy in LEGACY_CTXCRL_MD_FILES {
            // Match both relative `@CONTEXTCRAWLER.md` and absolute `@/path/to/CONTEXTCRAWLER.md`.
            let relative_ref = format!("@{}", legacy);
            let absolute_ref = format!("@{}", codex_dir.join(legacy).display());
            for needle in [relative_ref.as_str(), absolute_ref.as_str()] {
                let stripped = strip_at_reference_line(&new_content, needle);
                if stripped != new_content {
                    new_content = stripped;
                    notes.push(format!("removed `{}` reference from AGENTS.md", needle));
                }
            }
        }
        if new_content != content && !dry_run {
            fs::write(agents_md_path, new_content).with_context(|| {
                format!("Failed to write AGENTS.md: {}", agents_md_path.display())
            })?;
        }
    }

    Ok(notes)
}

/// Remove any line whose trimmed content equals `needle`. Preserves the
/// surrounding blank-line structure (collapses one of the bordering blank
/// lines if both sides are blank) so the file doesn't accumulate extra
/// vertical space across repeated cleanups.
fn strip_at_reference_line(content: &str, needle: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == needle {
            // Skip this line. If the previous and next lines are both blank,
            // also skip one of them to avoid leaving a double blank.
            let prev_blank = out.last().is_some_and(|l| l.trim().is_empty());
            let next_blank = lines.get(i + 1).is_some_and(|l| l.trim().is_empty());
            if prev_blank && next_blank {
                i += 1; // skip the redundant trailing blank line too
            }
            i += 1;
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    let mut result = out.join("\n");
    if content.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

fn resolve_opencode_dir() -> Result<PathBuf> {
    resolve_home_subdir(CONFIG_DIR).map(|p| p.join(OPENCODE_SUBDIR))
}

/// Return OpenCode plugin path: ~/.config/opencode/plugins/rtk.ts
fn opencode_plugin_path(opencode_dir: &Path) -> PathBuf {
    opencode_dir.join(PLUGIN_SUBDIR).join(OPENCODE_PLUGIN_FILE)
}

/// Prepare OpenCode plugin directory and return install path
fn prepare_opencode_plugin_path() -> Result<PathBuf> {
    let opencode_dir = resolve_opencode_dir()?;
    let path = opencode_plugin_path(&opencode_dir);
    // Directory creation is deferred to install time (caller guards on dry_run).
    Ok(path)
}

/// Write OpenCode plugin file if missing or outdated
fn ensure_opencode_plugin_installed(path: &Path, ctx: InitContext) -> Result<bool> {
    let InitContext { dry_run, .. } = ctx;
    // Ensure parent dir exists (skip in dry-run)
    if !dry_run {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create OpenCode plugin directory: {}",
                    parent.display()
                )
            })?;
        }
    }
    write_if_changed(path, OPENCODE_PLUGIN, "OpenCode plugin", ctx)
}

/// Remove OpenCode plugin file and strip the guidance block from AGENTS.md
fn remove_opencode_plugin(ctx: InitContext) -> Result<Vec<PathBuf>> {
    let InitContext { verbose, dry_run } = ctx;
    let opencode_dir = resolve_opencode_dir()?;
    let path = opencode_plugin_path(&opencode_dir);
    let mut removed = Vec::new();

    if path.exists() {
        if dry_run {
            println!("[dry-run] would remove OpenCode plugin: {}", path.display());
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove OpenCode plugin: {}", path.display()))?;
            if verbose > 0 {
                eprintln!("Removed OpenCode plugin: {}", path.display());
            }
        }
        removed.push(path);
    }

    // Strip the ContextCrawler guidance block from ~/.config/opencode/AGENTS.md.
    // Only the marked block is removed — user content in AGENTS.md is kept.
    let agents_md_path = opencode_agents_md_path(&opencode_dir);
    if strip_ctxcrl_block_from_file(&agents_md_path, "OpenCode guidance", ctx)?.is_some() {
        removed.push(agents_md_path);
    }

    Ok(removed)
}

// ─── Pi (pi.dev) support ──────────────────────────────────────────────

/// Resolve `~/.pi/agent/` — Pi's per-user agent directory. Pi auto-loads
/// `AGENTS.md` from here, parent dirs, and the cwd; extensions are TypeScript
/// modules auto-discovered from `~/.pi/agent/extensions/`.
fn resolve_pidev_agent_dir() -> Result<PathBuf> {
    Ok(resolve_home_subdir(PI_DIR)?.join(PI_AGENT_SUBDIR))
}

fn pidev_extension_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(PI_EXTENSIONS_SUBDIR).join(PI_EXTENSION_FILE)
}

fn pidev_agents_md_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(AGENTS_MD)
}

pub fn run_pidev_mode(ctx: InitContext) -> Result<()> {
    let agent_dir = resolve_pidev_agent_dir()?;
    run_pidev_mode_at(&agent_dir, ctx)
}

fn run_pidev_mode_at(agent_dir: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;

    let extensions_dir = agent_dir.join(PI_EXTENSIONS_SUBDIR);
    if !dry_run {
        fs::create_dir_all(&extensions_dir).with_context(|| {
            format!(
                "Failed to create Pi extensions directory: {}",
                extensions_dir.display()
            )
        })?;
    }

    let extension_path = pidev_extension_path(agent_dir);
    write_if_changed(&extension_path, PI_EXTENSION, "Pi extension", ctx)?;

    // Upsert guidance as a marked block into ~/.pi/agent/AGENTS.md.
    // Pi auto-loads AGENTS.md at session start from this directory; only the
    // marked block is touched, user content in AGENTS.md is preserved.
    let agents_md_path = pidev_agents_md_path(agent_dir);
    write_ctxcrl_block(
        &agents_md_path,
        &agent_guidance_block(AGENT_PIDEV)?,
        "Pi guidance",
        "contextcrawler init --agent pidev",
        ctx,
    )?;

    if dry_run {
        print_dry_run_footer();
    } else {
        println!("\nContextCrawler configured for Pi (pi.dev).\n");
        println!("  Extension: {}", extension_path.display());
        println!("  Guidance:  {}", agents_md_path.display());
        println!("  Pi auto-loads the extension on the next session.");
        println!("  Restart pi. Test with: git status\n");
    }

    Ok(())
}

pub fn uninstall_pidev(ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    let agent_dir = resolve_pidev_agent_dir()?;
    let removed = uninstall_pidev_at(&agent_dir, ctx)?;

    if removed.is_empty() {
        println!("ContextCrawler Pi support was not installed (nothing to remove)");
    } else {
        let header = if dry_run {
            "[dry-run] would uninstall ContextCrawler for Pi:"
        } else {
            "ContextCrawler uninstalled for Pi:"
        };
        println!("{}", header);
        for item in removed {
            println!("  - {}", item);
        }
    }

    if dry_run {
        print_dry_run_footer();
    }

    Ok(())
}

fn uninstall_pidev_at(agent_dir: &Path, ctx: InitContext) -> Result<Vec<String>> {
    let InitContext { verbose, dry_run } = ctx;
    let mut removed = Vec::new();

    // Strip the ContextCrawler guidance block from ~/.pi/agent/AGENTS.md.
    // User content in AGENTS.md is preserved.
    let agents_md_path = pidev_agents_md_path(agent_dir);
    if let Some(desc) = strip_ctxcrl_block_from_file(&agents_md_path, "Pi guidance", ctx)? {
        removed.push(desc);
    }

    // Remove the extension file. The extensions/ directory itself is left
    // intact — the user may have other Pi extensions in there.
    let extension_path = pidev_extension_path(agent_dir);
    if extension_path.exists() {
        if dry_run {
            println!(
                "[dry-run] would remove Pi extension: {}",
                extension_path.display()
            );
        } else {
            // nosemgrep: filesystem-deletion -- uninstall intentionally removes only ContextCrawler's Pi extension file.
            fs::remove_file(&extension_path).with_context(|| {
                format!(
                    "Failed to remove Pi extension: {}",
                    extension_path.display()
                )
            })?;
            if verbose > 0 {
                eprintln!("Removed Pi extension: {}", extension_path.display());
            }
        }
        removed.push(format!("Pi extension: {}", extension_path.display()));
    }

    Ok(removed)
}

// ─── Cursor Agent support ─────────────────────────────────────────────

fn resolve_cursor_dir() -> Result<PathBuf> {
    resolve_home_subdir(CURSOR_DIR)
}

/// Cursor project-rules path components (.mdc format).
///
/// Cursor reads `<project>/.cursor/rules/*.mdc` files as Project Rules.
/// This directory is PROJECT-scoped (relative to the project root), not
/// `~/.cursor/`. Cursor has no file-based global rule store — global rules
/// live only in Cursor Settings → Rules. The `alwaysApply: true` frontmatter
/// makes the rule load for every session in that project.
const CURSOR_RULES_REL_DIR: &str = ".cursor/rules";
const CURSOR_GUIDANCE_FILE: &str = "contextcrawler.mdc";

/// YAML frontmatter required by Cursor's `.mdc` rule format.
const CURSOR_MDC_FRONTMATTER: &str = "\
---\n\
description: ContextCrawler token-optimised CLI proxy\n\
alwaysApply: true\n\
---\n\
\n";

/// Render the full `.cursor/rules/contextcrawler.mdc` body: YAML frontmatter
/// followed by the unified agent guidance.
fn cursor_mdc_content() -> Result<String> {
    Ok(format!(
        "{}{}",
        CURSOR_MDC_FRONTMATTER,
        agent_guidance(AGENT_CURSOR)?
    ))
}

/// Write Cursor's project-scoped guidance file at
/// `<project_root>/.cursor/rules/contextcrawler.mdc`.
fn write_cursor_guidance(project_root: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    let rules_dir = project_root.join(CURSOR_RULES_REL_DIR);
    let guidance_path = rules_dir.join(CURSOR_GUIDANCE_FILE);
    if !dry_run {
        fs::create_dir_all(&rules_dir).with_context(|| {
            format!(
                "Failed to create Cursor rules directory: {}",
                rules_dir.display()
            )
        })?;
    }
    write_if_changed(
        &guidance_path,
        &cursor_mdc_content()?,
        CURSOR_GUIDANCE_FILE,
        ctx,
    )?;
    if !dry_run {
        println!("  Guidance:   {}", guidance_path.display());
    }
    Ok(())
}

/// `true` if `dir` looks like a project root (has a `.git` directory or a
/// recognised project manifest). Used to decide whether to write Cursor's
/// project-scoped `.cursor/rules` file or fall back to a manual-setup note.
fn looks_like_project_root(dir: &Path) -> bool {
    if dir.join(".git").exists() {
        return true;
    }
    const MANIFESTS: &[&str] = &[
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        ".cursor",
    ];
    MANIFESTS.iter().any(|m| dir.join(m).exists())
}

/// Install Cursor hooks: register binary command in hooks.json + write guidance
fn install_cursor_hooks(ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    let cursor_dir = resolve_cursor_dir()?;

    // Migrate old hook script if present
    let old_hook = cursor_dir.join("hooks").join(REWRITE_HOOK_FILE);
    if old_hook.exists() {
        if dry_run {
            println!(
                "[dry-run] would remove old Cursor hook script: {}",
                old_hook.display()
            );
        } else {
            let _ = fs::remove_file(&old_hook);
            if verbose > 0 {
                eprintln!(
                    "  [ok] Removed old Cursor hook script: {}",
                    old_hook.display()
                );
            }
        }
        // Clean stale hooks.json entry pointing to the deleted script
        let hooks_json_path = cursor_dir.join(HOOKS_JSON);
        if let Err(e) = remove_legacy_cursor_hooks_json_entries(&hooks_json_path, ctx) {
            if verbose > 0 {
                eprintln!("  [warn] Failed to clean legacy Cursor hooks.json entry: {e}");
            }
        }
    }

    // Create or patch hooks.json with binary command
    let hooks_json_path = cursor_dir.join(HOOKS_JSON);
    let patched = patch_cursor_hooks_json(&hooks_json_path, ctx)?;

    // Guidance file is PROJECT-scoped (.cursor/rules/ lives at the project
    // root, not in ~/.cursor/). This is a global install, so only write the
    // .mdc file when the current directory is actually a project root —
    // otherwise print a manual-setup note. Cursor has no file-based global
    // rule store.
    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    let have_project = looks_like_project_root(&cwd);
    if have_project {
        write_cursor_guidance(&cwd, ctx)?;
    }

    // Report (skip in dry-run)
    if !dry_run {
        println!("\nCursor hook registered (global).\n");
        println!("  Command:    {}", CURSOR_HOOK_COMMAND);
        println!("  hooks.json: {}", hooks_json_path.display());

        if patched {
            println!("  hooks.json: ContextCrawler preToolUse entry added");
        } else {
            println!("  hooks.json: ContextCrawler preToolUse entry already present");
        }

        if !have_project {
            println!(
                "\n  Cursor guidance is project-scoped — no project detected in {}.",
                cwd.display()
            );
            println!(
                "  Add it manually via Cursor Settings → Rules, or re-run\n  \
                 `contextcrawler init -g --agent cursor` from a project root to write\n  \
                 .cursor/rules/contextcrawler.mdc."
            );
        }

        println!("  Cursor reloads hooks.json automatically. Test with: git status\n");
    }

    Ok(())
}

/// Patch ~/.cursor/hooks.json to add ContextCrawler preToolUse hook.
/// Returns true if the file was modified.
fn patch_cursor_hooks_json(path: &Path, ctx: InitContext) -> Result<bool> {
    let InitContext { verbose, dry_run } = ctx;
    let mut root = if path.exists() {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        if content.trim().is_empty() {
            serde_json::json!({ "version": 1 })
        } else {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {} as JSON", path.display()))?
        }
    } else {
        serde_json::json!({ "version": 1 })
    };

    // Check idempotency
    if cursor_hook_already_present(&root) {
        if verbose > 0 {
            eprintln!("Cursor hooks.json: ContextCrawler hook already present");
        }
        return Ok(false);
    }

    insert_cursor_hook_entry(&mut root)?;

    let serialized =
        serde_json::to_string_pretty(&root).context("Failed to serialize hooks.json")?;

    if dry_run {
        println!(
            "[dry-run] would patch Cursor hooks.json: {}",
            path.display()
        );
        if verbose > 0 {
            println!("[dry-run] content:\n{}", serialized);
        }
        return Ok(true);
    }

    // Backup if exists
    if path.exists() {
        let backup_path = path.with_extension("json.bak");
        fs::copy(path, &backup_path)
            .with_context(|| format!("Failed to backup to {}", backup_path.display()))?;
        if verbose > 0 {
            eprintln!("Backup: {}", backup_path.display());
        }
    }

    // Atomic write
    atomic_write(path, &serialized)?;

    Ok(true)
}

/// Check if ContextCrawler preToolUse hook is already present in Cursor hooks.json
/// Matches on legacy rtk-rewrite.sh path OR new `contextcrawler hook cursor` command
fn cursor_hook_already_present(root: &serde_json::Value) -> bool {
    let hooks = match root
        .get("hooks")
        .and_then(|h| h.get("preToolUse"))
        .and_then(|p| p.as_array())
    {
        Some(arr) => arr,
        None => return false,
    };

    hooks.iter().any(|entry| {
        entry
            .get("command")
            .and_then(|c| c.as_str())
            .is_some_and(|cmd| {
                // Match the legacy command too so users who installed before
                // the rebrand get correctly detected/removed.
                command_is_legacy_rewrite_hook(cmd)
                    || cmd == CURSOR_HOOK_COMMAND
                    || cmd == LEGACY_CURSOR_HOOK_COMMAND
            })
    })
}

/// Insert ContextCrawler preToolUse entry into Cursor hooks.json
fn insert_cursor_hook_entry(root: &mut serde_json::Value) -> Result<()> {
    let root_obj = match root.as_object_mut() {
        Some(obj) => obj,
        None => {
            *root = serde_json::json!({ "version": 1 });
            root.as_object_mut().expect("just-created json object")
        }
    };

    root_obj.entry("version").or_insert(serde_json::json!(1));

    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context("hooks value is not an object")?;

    let pre_tool_use = hooks
        .entry("preToolUse")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .context("preToolUse value is not an array")?;

    pre_tool_use.push(serde_json::json!({
        "command": CURSOR_HOOK_COMMAND,
        "matcher": "Shell"
    }));
    Ok(())
}

/// Remove only legacy `rtk-rewrite.sh` entries from Cursor hooks.json.
/// Preserves any existing `contextcrawler hook cursor` entries (new format).
fn remove_legacy_cursor_hooks_json_entries(path: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    if !path.exists() {
        return Ok(());
    }

    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(());
    }

    let mut root: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    if !remove_legacy_cursor_hook_entries_from_json(&mut root) {
        return Ok(());
    }

    if dry_run {
        println!(
            "[dry-run] would remove legacy rtk-rewrite.sh entry from Cursor hooks.json: {}",
            path.display()
        );
        return Ok(());
    }

    let serialized =
        serde_json::to_string_pretty(&root).context("Failed to serialize hooks.json")?;
    atomic_write(path, &serialized)?;

    if verbose > 0 {
        eprintln!("  [ok] Removed legacy rtk-rewrite.sh entry from Cursor hooks.json");
    }
    Ok(())
}

/// Remove only legacy `rtk-rewrite.sh` entries from parsed Cursor hooks.json.
/// Returns true if any entries were removed.
/// Does NOT remove `contextcrawler hook cursor` entries — those are the new format.
fn remove_legacy_cursor_hook_entries_from_json(root: &mut serde_json::Value) -> bool {
    let pre_tool_use = match root
        .get_mut("hooks")
        .and_then(|h| h.get_mut("preToolUse"))
        .and_then(|p| p.as_array_mut())
    {
        Some(arr) => arr,
        None => return false,
    };

    let original_len = pre_tool_use.len();
    pre_tool_use.retain(|entry| {
        !entry
            .get("command")
            .and_then(|c| c.as_str())
            .is_some_and(command_is_legacy_rewrite_hook)
    });

    pre_tool_use.len() < original_len
}

/// Remove Cursor ContextCrawler artifacts: hook script + hooks.json entry
fn remove_cursor_hooks(ctx: InitContext) -> Result<Vec<String>> {
    let InitContext { verbose, dry_run } = ctx;
    let cursor_dir = resolve_cursor_dir()?;
    let mut removed = Vec::new();

    // 1. Remove hook script
    let hook_path = cursor_dir.join(HOOKS_SUBDIR).join(REWRITE_HOOK_FILE);
    if hook_path.exists() {
        if dry_run {
            println!(
                "[dry-run] would remove Cursor hook: {}",
                hook_path.display()
            );
        } else {
            // nosemgrep: filesystem-deletion
            fs::remove_file(&hook_path).with_context(|| {
                format!("Failed to remove Cursor hook: {}", hook_path.display())
            })?;
        }
        removed.push(format!("Cursor hook: {}", hook_path.display()));
    }

    // 2. Remove ContextCrawler entry from hooks.json
    let hooks_json_path = cursor_dir.join(HOOKS_JSON);
    if hooks_json_path.exists() {
        let content = fs::read_to_string(&hooks_json_path)
            .with_context(|| format!("Failed to read {}", hooks_json_path.display()))?;

        if !content.trim().is_empty() {
            if let Ok(mut root) = serde_json::from_str::<serde_json::Value>(&content) {
                if remove_cursor_hook_from_json(&mut root) {
                    if dry_run {
                        println!(
                            "[dry-run] would remove ContextCrawler entry from Cursor hooks.json: {}",
                            hooks_json_path.display()
                        );
                    } else {
                        let backup_path = hooks_json_path.with_extension("json.bak");
                        fs::copy(&hooks_json_path, &backup_path).ok();

                        let serialized = serde_json::to_string_pretty(&root)
                            .context("Failed to serialize hooks.json")?;
                        atomic_write(&hooks_json_path, &serialized)?;

                        if verbose > 0 {
                            eprintln!("Removed ContextCrawler hook from Cursor hooks.json");
                        }
                    }
                    removed.push("Cursor hooks.json: removed ContextCrawler entry".to_string());
                }
            }
        }
    }

    Ok(removed)
}

/// Remove ContextCrawler preToolUse entry from Cursor hooks.json
/// Returns true if entry was found and removed
/// Matches both legacy script path and new binary command
fn remove_cursor_hook_from_json(root: &mut serde_json::Value) -> bool {
    let pre_tool_use = match root
        .get_mut("hooks")
        .and_then(|h| h.get_mut("preToolUse"))
        .and_then(|p| p.as_array_mut())
    {
        Some(arr) => arr,
        None => return false,
    };

    let original_len = pre_tool_use.len();
    pre_tool_use.retain(|entry| {
        !entry
            .get("command")
            .and_then(|c| c.as_str())
            .is_some_and(|cmd| {
                // Match the legacy command too so users who installed before
                // the rebrand get correctly detected/removed.
                command_is_legacy_rewrite_hook(cmd)
                    || cmd == CURSOR_HOOK_COMMAND
                    || cmd == LEGACY_CURSOR_HOOK_COMMAND
            })
    });

    pre_tool_use.len() < original_len
}

/// Show current ContextCrawler configuration
pub fn show_config(codex: bool) -> Result<()> {
    if codex {
        return show_codex_config();
    }

    show_claude_config()
}

fn show_claude_config() -> Result<()> {
    let claude_dir = resolve_claude_dir()?;
    let hook_path = claude_dir.join(HOOKS_SUBDIR).join(REWRITE_HOOK_FILE);
    let ctxcrl_md_path = claude_dir.join(CTXCRL_MD);
    let global_claude_md = claude_dir.join(CLAUDE_MD);
    let local_claude_md = PathBuf::from(CLAUDE_MD);

    println!("ContextCrawler Configuration:\n");

    // Check hook: prefer binary command detection, fall back to script file
    let settings_path = claude_dir.join(SETTINGS_JSON);
    let binary_hook_registered = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path).unwrap_or_default();
        if let Ok(root) = serde_json::from_str::<serde_json::Value>(&content) {
            hook_already_present(&root, CLAUDE_HOOK_COMMAND)
        } else {
            false
        }
    } else {
        false
    };

    if binary_hook_registered {
        println!("[ok] Hook: {} (native binary command)", CLAUDE_HOOK_COMMAND);
    } else if hook_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&hook_path)?;
            let perms = metadata.permissions();
            let is_executable = perms.mode() & 0o111 != 0;

            let hook_content = fs::read_to_string(&hook_path)?;
            let has_guards = (hook_content.contains("command -v contextcrawler")
                || hook_content.contains("command -v rtk"))
                && hook_content.contains("command -v jq");
            let is_thin_delegator = hook_content.contains("contextcrawler rewrite")
                || hook_content.contains("rtk rewrite");
            let hook_version = super::hook_check::parse_hook_version(&hook_content);

            if !is_executable {
                println!(
                    "[warn] Hook: {} (NOT executable - run: chmod +x)",
                    hook_path.display()
                );
            } else if !is_thin_delegator {
                println!(
                    "[warn] Hook: {} (outdated — run `contextcrawler init -g` to upgrade to native binary)",
                    hook_path.display()
                );
            } else if is_executable && has_guards {
                println!(
                    "[warn] Hook: {} (legacy script v{} — run `contextcrawler init -g` to upgrade)",
                    hook_path.display(),
                    hook_version
                );
            } else {
                println!(
                    "[warn] Hook: {} (no guards - outdated)",
                    hook_path.display()
                );
            }
        }

        #[cfg(not(unix))]
        {
            println!(
                "[warn] Hook: {} (legacy script — run `contextcrawler init -g` to upgrade)",
                hook_path.display()
            );
        }
    } else {
        println!("[--] Hook: not found");
    }

    // Check CONTEXTCRAWLER.md
    if ctxcrl_md_path.exists() {
        println!("[ok] CONTEXTCRAWLER.md: {} (slim mode)", ctxcrl_md_path.display());
    } else {
        println!("[--] CONTEXTCRAWLER.md: not found");
    }

    // Check hook integrity (only relevant for legacy script hooks)
    if hook_path.exists() && !binary_hook_registered {
        match integrity::verify_hook_at(&hook_path) {
            Ok(integrity::IntegrityStatus::Verified) => {
                println!("[ok] Integrity: hook hash verified");
            }
            Ok(integrity::IntegrityStatus::Tampered { .. }) => {
                println!("[FAIL] Integrity: hook modified outside contextcrawler init (run: contextcrawler verify)");
            }
            Ok(integrity::IntegrityStatus::NoBaseline) => {
                println!("[warn] Integrity: no baseline hash (run: contextcrawler init -g to establish)");
            }
            Ok(integrity::IntegrityStatus::NotInstalled)
            | Ok(integrity::IntegrityStatus::OrphanedHash) => {
                // Don't show integrity line if hook isn't installed
            }
            Err(_) => {
                println!("[warn] Integrity: check failed");
            }
        }
    }

    // Check global CLAUDE.md
    if global_claude_md.exists() {
        let content = fs::read_to_string(&global_claude_md)?;
        if content.contains(CTXCRL_MD_REF) {
            println!("[ok] Global (~/.claude/CLAUDE.md): @CONTEXTCRAWLER.md reference");
        } else if contains_ctxcrl_block(&content) {
            println!(
                "[warn] Global (~/.claude/CLAUDE.md): old ContextCrawler block (run: contextcrawler init -g to migrate)"
            );
        } else {
            println!("[--] Global (~/.claude/CLAUDE.md): exists but ContextCrawler not configured");
        }
    } else {
        println!("[--] Global (~/.claude/CLAUDE.md): not found");
    }

    // Check local CLAUDE.md.
    //
    // Detect via the exact block markers the installer writes
    // (`CTXCRL_MD_REF` / `CTXCRL_BLOCK_START`), not a bare `ctxcrl` substring — the
    // substring matched any unrelated mention of the word and misreported
    // status (#100 G2 NICE-TO-HAVE 10).
    if local_claude_md.exists() {
        let content = fs::read_to_string(&local_claude_md)?;
        if content.contains(CTXCRL_MD_REF) {
            println!("[ok] Local (./CLAUDE.md): @CONTEXTCRAWLER.md reference");
        } else if contains_ctxcrl_block(&content) {
            println!(
                "[warn] Local (./CLAUDE.md): old ContextCrawler block (run: contextcrawler init to migrate)"
            );
        } else {
            println!("[--] Local (./CLAUDE.md): exists but ContextCrawler not configured");
        }
    } else {
        println!("[--] Local (./CLAUDE.md): not found");
    }

    // Check settings.json (detailed status)
    if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        if !content.trim().is_empty() {
            if let Ok(root) = serde_json::from_str::<serde_json::Value>(&content) {
                if hook_already_present(&root, CLAUDE_HOOK_COMMAND) {
                    println!("[ok] settings.json: ContextCrawler hook configured");
                } else {
                    println!("[warn] settings.json: exists but ContextCrawler hook not configured");
                    println!("    Run: contextcrawler init -g --auto-patch");
                }
            } else {
                println!("[warn] settings.json: exists but invalid JSON");
            }
        } else {
            println!("[--] settings.json: empty");
        }
    } else {
        println!("[--] settings.json: not found");
    }

    // Check OpenCode plugin
    if let Ok(opencode_dir) = resolve_opencode_dir() {
        let plugin = opencode_plugin_path(&opencode_dir);
        if plugin.exists() {
            println!("[ok] OpenCode: plugin installed ({})", plugin.display());
        } else {
            println!("[--] OpenCode: plugin not found");
        }
    } else {
        println!("[--] OpenCode: config dir not found");
    }

    // Check Cursor hooks
    if let Ok(cursor_dir) = resolve_cursor_dir() {
        let cursor_hook = cursor_dir.join(HOOKS_SUBDIR).join(REWRITE_HOOK_FILE);
        let cursor_hooks_json = cursor_dir.join(HOOKS_JSON);

        // Check for binary command in hooks.json first
        let cursor_binary_registered = if cursor_hooks_json.exists() {
            let content = fs::read_to_string(&cursor_hooks_json).unwrap_or_default();
            if let Ok(root) = serde_json::from_str::<serde_json::Value>(&content) {
                cursor_hook_already_present(&root)
            } else {
                false
            }
        } else {
            false
        };

        if cursor_binary_registered {
            println!("[ok] Cursor hook: registered in hooks.json");
        } else if cursor_hook.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = fs::metadata(&cursor_hook)?;
                let is_executable = meta.permissions().mode() & 0o111 != 0;
                let content = fs::read_to_string(&cursor_hook)?;
                let _is_thin =
                    content.contains("contextcrawler rewrite") || content.contains("rtk rewrite");

                if !is_executable {
                    println!(
                        "[warn] Cursor hook: {} (legacy script, NOT executable)",
                        cursor_hook.display()
                    );
                } else {
                    println!(
                        "[warn] Cursor hook: {} (legacy script — run `contextcrawler init -g --agent cursor` to upgrade)",
                        cursor_hook.display()
                    );
                }
            }

            #[cfg(not(unix))]
            {
                println!("[warn] Cursor hook: {} (legacy script — run `contextcrawler init -g --agent cursor` to upgrade)", cursor_hook.display());
            }
        } else {
            println!("[--] Cursor hook: not found");
        }
    } else {
        println!("[--] Cursor: home dir not found");
    }

    println!("\nUsage:");
    println!("  contextcrawler init        # Full injection into local CLAUDE.md");
    println!("  contextcrawler init -g     # Hook + CONTEXTCRAWLER.md + @CONTEXTCRAWLER.md + settings.json (recommended)");
    println!("  contextcrawler init -g --auto-patch    # Same as above but no prompt");
    println!("  contextcrawler init -g --no-patch # Skip settings.json (manual setup)");
    println!("  contextcrawler init -g --uninstall # Remove all ContextCrawler artifacts");
    println!("  contextcrawler init -g --claude-md     # Legacy: full injection into ~/.claude/CLAUDE.md");
    println!("  contextcrawler init -g --hook-only # Hook only, no CONTEXTCRAWLER.md");
    println!("  contextcrawler init --codex      # Configure local AGENTS.md + CONTEXTCRAWLER.md");
    println!("  contextcrawler init -g --codex   # Configure $CODEX_HOME/AGENTS.md + $CODEX_HOME/CONTEXTCRAWLER.md (or ~/.codex/)");
    println!("  contextcrawler init -g --opencode      # OpenCode plugin only");
    println!("  contextcrawler init -g --agent cursor  # Install Cursor Agent hooks");

    Ok(())
}

fn show_codex_config() -> Result<()> {
    let codex_dir = resolve_codex_dir()?;
    let global_agents_md = codex_dir.join(AGENTS_MD);
    let global_ctxcrl_md = codex_dir.join(CTXCRL_MD);
    let global_ctxcrl_md_ref = codex_ctxcrl_md_ref(&codex_dir);
    let local_agents_md = PathBuf::from(AGENTS_MD);
    let local_ctxcrl_md = PathBuf::from(CTXCRL_MD);

    println!("ContextCrawler Configuration (Codex CLI):\n");

    if global_ctxcrl_md.exists() {
        println!("[ok] Global CONTEXTCRAWLER.md: {}", global_ctxcrl_md.display());
    } else {
        println!("[--] Global CONTEXTCRAWLER.md: not found");
    }
    // Also surface legacy artifacts so a user on a regressed install sees
    // them in `init --show` rather than wondering why init keeps recreating
    // files. Hint at the cleanup that runs on next `init`.
    for legacy in LEGACY_CTXCRL_MD_FILES {
        let legacy_path = codex_dir.join(legacy);
        if legacy_path.exists() {
            println!(
                "[!!] Global {} (legacy): {} — will be cleaned on next init",
                legacy,
                legacy_path.display()
            );
        }
    }

    if global_agents_md.exists() {
        let content = fs::read_to_string(&global_agents_md)?;
        // Build the full reference set (canonical + every legacy form) so a
        // regressed install isn't reported as "not configured".
        let mut all_refs: Vec<String> = vec![
            CTXCRL_MD_REF.to_string(),
            global_ctxcrl_md_ref.clone(),
        ];
        for legacy in LEGACY_CTXCRL_MD_FILES {
            all_refs.push(format!("@{}", legacy));
            all_refs.push(format!("@{}", codex_dir.join(legacy).display()));
        }
        let all_refs_borrowed: Vec<&str> = all_refs.iter().map(|s| s.as_str()).collect();
        if has_rtk_reference(&content, &all_refs_borrowed) {
            println!("[ok] Global AGENTS.md: CONTEXTCRAWLER.md reference");
        } else if contains_ctxcrl_block(&content) {
            println!("[!!] Global AGENTS.md: old inline ContextCrawler block");
        } else {
            println!("[--] Global AGENTS.md: exists but ContextCrawler not configured");
        }
    } else {
        println!("[--] Global AGENTS.md: not found");
    }

    if local_ctxcrl_md.exists() {
        println!("[ok] Local CONTEXTCRAWLER.md: {}", local_ctxcrl_md.display());
    } else {
        println!("[--] Local CONTEXTCRAWLER.md: not found");
    }

    if local_agents_md.exists() {
        let content = fs::read_to_string(&local_agents_md)?;
        let mut all_local_refs: Vec<String> = vec![CTXCRL_MD_REF.to_string()];
        for legacy in LEGACY_CTXCRL_MD_FILES {
            all_local_refs.push(format!("@{}", legacy));
        }
        let all_local_refs_borrowed: Vec<&str> =
            all_local_refs.iter().map(|s| s.as_str()).collect();
        if has_rtk_reference(&content, &all_local_refs_borrowed) {
            println!("[ok] Local AGENTS.md: @CONTEXTCRAWLER.md reference");
        } else if contains_ctxcrl_block(&content) {
            println!("[!!] Local AGENTS.md: old inline ContextCrawler block");
        } else {
            println!("[--] Local AGENTS.md: exists but ContextCrawler not configured");
        }
    } else {
        println!("[--] Local AGENTS.md: not found");
    }

    println!("\nUsage:");
    println!("  contextcrawler init --codex     # Configure local AGENTS.md + CONTEXTCRAWLER.md");
    println!("  contextcrawler init -g --codex  # Configure $CODEX_HOME/AGENTS.md + $CODEX_HOME/CONTEXTCRAWLER.md (or ~/.codex/)");
    println!("  contextcrawler init -g --codex --uninstall  # Remove global Codex ContextCrawler artifacts");

    Ok(())
}

/// Path to the OpenCode-loaded instructions file: `~/.config/opencode/AGENTS.md`.
///
/// OpenCode auto-loads `AGENTS.md` from its config directory at session start.
/// It does NOT load a standalone `CONTEXTCRAWLER.md`, so the guidance is
/// upserted as a marked block into AGENTS.md instead.
fn opencode_agents_md_path(opencode_dir: &Path) -> PathBuf {
    opencode_dir.join(AGENTS_MD)
}

fn run_opencode_only_mode(ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    let opencode_plugin_path = prepare_opencode_plugin_path()?;
    ensure_opencode_plugin_installed(&opencode_plugin_path, ctx)?;

    // Upsert guidance as a marked block into ~/.config/opencode/AGENTS.md
    // (OpenCode auto-loads AGENTS.md; it does not read a standalone file).
    let opencode_dir = resolve_opencode_dir()?;
    if !dry_run {
        fs::create_dir_all(&opencode_dir).with_context(|| {
            format!(
                "Failed to create OpenCode config directory: {}",
                opencode_dir.display()
            )
        })?;
    }
    let agents_md_path = opencode_agents_md_path(&opencode_dir);
    write_ctxcrl_block(
        &agents_md_path,
        &agent_guidance_block(AGENT_OPENCODE)?,
        "OpenCode guidance",
        "contextcrawler init -g --opencode",
        ctx,
    )?;

    if !dry_run {
        println!("\nOpenCode plugin installed (global).\n");
        println!("  OpenCode: {}", opencode_plugin_path.display());
        println!("  Guidance: {}", agents_md_path.display());
        println!("  Restart OpenCode. Test with: git status\n");
    }
    Ok(())
}

// ─── Gemini CLI support ───────────────────────────────────────────

/// Gemini hook wrapper script — delegates to `contextcrawler hook gemini`.
/// The exec target MUST match the installed binary name (`contextcrawler`),
/// not the upstream `rtk` name. Users have only `contextcrawler` on PATH.
const GEMINI_HOOK_SCRIPT: &str = r#"#!/bin/bash
exec contextcrawler hook gemini
"#;

fn resolve_gemini_dir() -> Result<PathBuf> {
    resolve_home_subdir(GEMINI_DIR)
}

/// Entry point for `contextcrawler init --gemini`
pub fn run_gemini(
    global: bool,
    hook_only: bool,
    patch_mode: PatchMode,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    if !global {
        anyhow::bail!("Gemini support is global-only. Use: contextcrawler init -g --gemini");
    }

    let gemini_dir = resolve_gemini_dir()?;
    if !dry_run {
        fs::create_dir_all(&gemini_dir).with_context(|| {
            format!(
                "Failed to create Gemini config dir: {}",
                gemini_dir.display()
            )
        })?;
    }

    // 1. Install hook script
    let hook_dir = gemini_dir.join("hooks");
    if !dry_run {
        fs::create_dir_all(&hook_dir)
            .with_context(|| format!("Failed to create hook dir: {}", hook_dir.display()))?;
    }
    let hook_path = hook_dir.join(GEMINI_HOOK_FILE);
    write_if_changed(&hook_path, GEMINI_HOOK_SCRIPT, "Gemini hook", ctx)?;

    #[cfg(unix)]
    if !dry_run {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Failed to set hook permissions: {}", hook_path.display()))?;
    }

    // Store integrity baseline for tamper detection (skip in dry-run)
    if !dry_run {
        integrity::store_hash(&hook_path).with_context(|| {
            format!("Failed to store integrity hash for {}", hook_path.display())
        })?;
    }

    // 2. Install GEMINI.md (ContextCrawler awareness for Gemini)
    if !hook_only {
        let gemini_md_path = gemini_dir.join(GEMINI_MD);
        write_if_changed(&gemini_md_path, &agent_guidance(AGENT_GEMINI)?, GEMINI_MD, ctx)?;
    }

    // 3. Patch ~/.gemini/settings.json
    patch_gemini_settings(&gemini_dir, &hook_path, patch_mode, ctx)?;

    if dry_run {
        print_dry_run_footer();
    } else {
        println!("\nGemini CLI hook installed (global).\n");
        println!("  Hook: {}", hook_path.display());
        if !hook_only {
            println!("  GEMINI.md: {}", gemini_dir.join(GEMINI_MD).display());
        }
        println!("  Restart Gemini CLI. Test with: git status\n");
    }
    Ok(())
}

/// Patch ~/.gemini/settings.json with the BeforeTool hook
fn patch_gemini_settings(
    gemini_dir: &Path,
    hook_path: &Path,
    patch_mode: PatchMode,
    ctx: InitContext,
) -> Result<()> {
    let InitContext { verbose, dry_run } = ctx;
    let settings_path = gemini_dir.join(SETTINGS_JSON);
    let hook_cmd = hook_path.to_string_lossy().to_string();

    // Read or create settings.json.
    //
    // SECURITY (#100 G2 IMPORTANT 4): on a parse failure return an error —
    // NEVER fall back to `{}`. Replacing an unparseable settings.json with
    // an empty object and reserialising silently destroys the user's whole
    // Gemini config. This matches the fail-on-parse-error behaviour of the
    // sibling `patch_settings_json_command` / `patch_cursor_hooks_json`.
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)
            .with_context(|| format!("Failed to read {}", settings_path.display()))?;
        if content.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {} as JSON", settings_path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    let before_tool_pointer = format!("/hooks/{}", BEFORE_TOOL_KEY);
    if let Some(hooks) = settings.pointer(&before_tool_pointer) {
        if let Some(arr) = hooks.as_array() {
            if arr.iter().any(|h| {
                h.pointer("/hooks/0/command")
                    .and_then(|v| v.as_str())
                    .is_some_and(|c| c.contains("rtk"))
            }) {
                if verbose > 0 {
                    eprintln!("Gemini settings.json already has ContextCrawler hook");
                }
                return Ok(());
            }
        }
    }

    // Ask user before patching
    if patch_mode == PatchMode::Skip {
        println!(
            "\nManual setup needed: add ContextCrawler hook to {}\n\
             See: https://github.com/rtk-ai/rtk#gemini-cli",
            settings_path.display()
        );
        return Ok(());
    }

    if patch_mode == PatchMode::Ask {
        if dry_run {
            println!(
                "[dry-run] would prompt before patching {}",
                settings_path.display()
            );
        } else {
            print!("Patch {} with ContextCrawler hook? [y/N] ", settings_path.display());
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                println!("Skipped. Add hook manually later.");
                return Ok(());
            }
        }
    }

    // Build hook entry matching Gemini CLI format
    let hook_entry = serde_json::json!({
        "matcher": "run_shell_command",
        "hooks": [{
            "type": "command",
            "command": hook_cmd
        }]
    });

    // Insert into settings
    let hooks = settings
        .as_object_mut()
        .context("settings.json is not an object")?
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let before_tool = hooks
        .as_object_mut()
        .context("hooks is not an object")?
        .entry(BEFORE_TOOL_KEY)
        .or_insert(serde_json::json!([]));

    before_tool
        .as_array_mut()
        .context("BeforeTool is not an array")?
        .push(hook_entry);

    let content = serde_json::to_string_pretty(&settings)?;

    if dry_run {
        println!(
            "[dry-run] would patch Gemini settings.json: {}",
            settings_path.display()
        );
        if verbose > 0 {
            println!("[dry-run] content:\n{}", content);
        }
        return Ok(());
    }

    // Write atomically
    let tmp = NamedTempFile::new_in(gemini_dir)?;
    fs::write(tmp.path(), &content)?;
    tmp.persist(&settings_path)
        .with_context(|| format!("Failed to write {}", settings_path.display()))?;

    if verbose > 0 {
        eprintln!("Patched {}", settings_path.display());
    }

    Ok(())
}

/// Remove Gemini artifacts during uninstall
fn uninstall_gemini(ctx: InitContext) -> Result<Vec<String>> {
    let InitContext { verbose, dry_run } = ctx;
    let mut removed = Vec::new();
    let gemini_dir = match resolve_gemini_dir() {
        Ok(d) => d,
        Err(_) => return Ok(removed),
    };

    // Remove hook
    let hook_path = gemini_dir.join(HOOKS_SUBDIR).join(GEMINI_HOOK_FILE);
    if hook_path.exists() {
        if dry_run {
            println!(
                "[dry-run] would remove Gemini hook: {}",
                hook_path.display()
            );
        } else {
            fs::remove_file(&hook_path)
                .with_context(|| format!("Failed to remove {}", hook_path.display()))?;
        }
        removed.push(format!("Gemini hook: {}", hook_path.display()));
    }

    // Remove GEMINI.md
    let gemini_md = gemini_dir.join(GEMINI_MD);
    if gemini_md.exists() {
        if dry_run {
            println!("[dry-run] would remove GEMINI.md: {}", gemini_md.display());
        } else {
            fs::remove_file(&gemini_md)
                .with_context(|| format!("Failed to remove {}", gemini_md.display()))?;
        }
        removed.push(format!("GEMINI.md: {}", gemini_md.display()));
    }

    // Remove hook from settings.json
    let settings_path = gemini_dir.join(SETTINGS_JSON);
    if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        if let Ok(mut settings) = serde_json::from_str::<serde_json::Value>(&content) {
            let bt_pointer = format!("/hooks/{}", BEFORE_TOOL_KEY);
            if let Some(arr) = settings
                .pointer_mut(&bt_pointer)
                .and_then(|v| v.as_array_mut())
            {
                let before = arr.len();
                arr.retain(|h| {
                    !h.pointer("/hooks/0/command")
                        .and_then(|v| v.as_str())
                        .is_some_and(|c| c.contains("rtk"))
                });
                if arr.len() < before {
                    if dry_run {
                        println!(
                            "[dry-run] would remove ContextCrawler hook from Gemini settings.json: {}",
                            settings_path.display()
                        );
                    } else {
                        let new_content = serde_json::to_string_pretty(&settings)?;
                        fs::write(&settings_path, new_content)?;
                    }
                    removed.push("Gemini settings.json: removed ContextCrawler hook entry".to_string());
                }
            }
        }
    }

    if verbose > 0 && !removed.is_empty() {
        eprintln!("Gemini artifacts removed");
    }

    Ok(removed)
}

// ── Copilot integration ─────────────────────────────────────

// The `command` value MUST be `contextcrawler hook copilot`, not the
// upstream `rtk hook copilot` — users have only `contextcrawler` on
// PATH, and Copilot will silently fail to invoke a non-existent `rtk`.
const COPILOT_HOOK_JSON: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "contextcrawler hook copilot",
        "cwd": ".",
        "timeout": 5
      }
    ]
  }
}
"#;

const COPILOT_INSTRUCTIONS: &str = r#"<!-- ctxcrl-instructions v3 -->
# ContextCrawler — Token-Optimized CLI

**contextcrawler** is a CLI proxy that filters and compresses command outputs, saving 60-90% tokens.

## Rule

Always prefix shell commands with `contextcrawler`:

```bash
# Instead of:              Use:
git status                 contextcrawler git status
git log -10                contextcrawler git log -10
cargo test                 contextcrawler cargo test
docker ps                  contextcrawler docker ps
kubectl get pods           contextcrawler kubectl pods
```

## Meta commands (use directly)

```bash
contextcrawler gain              # Token savings dashboard
contextcrawler gain --history    # Per-command savings history
contextcrawler gain --weak-filters # Rank tools by leaked tokens (where filters underperform)
contextcrawler discover          # Find missed contextcrawler opportunities
contextcrawler proxy <cmd>       # Run raw (no filtering) but track usage
```
<!-- /ctxcrl-instructions -->
"#;

/// Entry point for `contextcrawler init --copilot`.
///
/// Installs in the current working directory's `.github/` subdirectory.
pub fn run_copilot(ctx: InitContext) -> Result<()> {
    run_copilot_at(Path::new("."), ctx)
}

/// Same as [`run_copilot`] but operates relative to an explicit base path.
///
/// Used by tests to avoid mutating process-global `cwd` (which is racy under
/// `cargo test`'s default parallel execution).
fn run_copilot_at(base: &Path, ctx: InitContext) -> Result<()> {
    let InitContext { dry_run, .. } = ctx;
    let github_dir = base.join(".github");
    let hooks_dir = github_dir.join("hooks");

    if !dry_run {
        fs::create_dir_all(&hooks_dir)
            .with_context(|| format!("Failed to create {} directory", hooks_dir.display()))?;
    }

    // 1. Upsert ContextCrawler marker block in copilot-instructions.md (preserves user content).
    //    Done BEFORE writing the hook config so a malformed file aborts the install
    //    without leaving a stale hook on disk.
    let instructions_path = github_dir.join("copilot-instructions.md");
    write_ctxcrl_block(
        &instructions_path,
        COPILOT_INSTRUCTIONS,
        "Copilot instructions",
        "contextcrawler init --copilot",
        ctx,
    )?;

    // 2. Write hook config (only reached if the upsert above succeeded).
    let hook_path = hooks_dir.join("rtk-rewrite.json");
    write_if_changed(&hook_path, COPILOT_HOOK_JSON, "Copilot hook config", ctx)?;

    if dry_run {
        print_dry_run_footer();
    } else {
        println!("\nGitHub Copilot integration installed (project-scoped).\n");
        println!("  Hook config:    {}", hook_path.display());
        println!("  Instructions:   {}", instructions_path.display());
        println!("\n  Works with VS Code Copilot Chat (transparent rewrite)");
        println!("  and Copilot CLI (deny-with-suggestion).");
        println!("\n  Restart your IDE or Copilot CLI session to activate.\n");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ─── Drift-guard: agent_guidance() for every harness ────────────────────
    //
    // These tests are the regression guard for the guidance-unification
    // refactor. With a single source (`hooks/shared/guidance.md`), content
    // cannot drift between harnesses. Each assertion below verifies:
    //   1. Non-empty output
    //   2. Correct title line
    //   3. Core markers present (meta commands, security gate, gain command)
    //   4. Maintainer HTML comment NOT in the rendered output
    //
    // Adding a new harness requires:
    //   a. A new AGENT_* const
    //   b. A match arm in agent_guidance()
    //   c. A test case here
    //
    // Do NOT delete these tests to "fix" a failing build — fix the source.

    fn assert_guidance_invariants(agent: &str, guidance: &str) {
        // Non-empty
        assert!(
            !guidance.is_empty(),
            "agent_guidance({agent}): returned empty string"
        );
        // Title line — derived from agent_guidance()'s own first line rather
        // than a parallel match. The title format itself is asserted: it must
        // be a `# ContextCrawler (...)` heading.
        let first_line = guidance.lines().next().unwrap_or("<empty>");
        assert!(
            first_line.starts_with("# ContextCrawler (") && first_line.ends_with(')'),
            "agent_guidance({agent}): expected '# ContextCrawler (<title>)' heading, got: {first_line}"
        );
        // Core markers
        for marker in &["## Meta commands", "## Security gate", "contextcrawler gain"] {
            assert!(
                guidance.contains(marker),
                "agent_guidance({agent}): missing core marker '{marker}'"
            );
        }
        // Maintainer comment must NOT appear in rendered output
        assert!(
            !guidance.contains("CANONICAL ContextCrawler agent guidance"),
            "agent_guidance({agent}): maintainer HTML comment leaked into rendered output"
        );
        assert!(
            !guidance.contains("<!-- "),
            "agent_guidance({agent}): HTML comment leaked into rendered output"
        );
    }

    #[test]
    fn test_guidance_drift_guard_claude() {
        assert_guidance_invariants(
            AGENT_CLAUDE,
            &agent_guidance(AGENT_CLAUDE).expect("claude guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_codex() {
        let g = agent_guidance(AGENT_CODEX).expect("codex guidance");
        assert_guidance_invariants(AGENT_CODEX, &g);
        // Codex must include the mandatory self-prefix imperative content.
        assert!(
            g.contains("you must prefix every shell command"),
            "Codex guidance missing mandatory self-prefix rule"
        );
    }

    #[test]
    fn test_guidance_drift_guard_cursor() {
        assert_guidance_invariants(
            AGENT_CURSOR,
            &agent_guidance(AGENT_CURSOR).expect("cursor guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_windsurf() {
        assert_guidance_invariants(
            AGENT_WINDSURF,
            &agent_guidance(AGENT_WINDSURF).expect("windsurf guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_cline() {
        assert_guidance_invariants(
            AGENT_CLINE,
            &agent_guidance(AGENT_CLINE).expect("cline guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_kilocode() {
        assert_guidance_invariants(
            AGENT_KILOCODE,
            &agent_guidance(AGENT_KILOCODE).expect("kilocode guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_antigravity() {
        assert_guidance_invariants(
            AGENT_ANTIGRAVITY,
            &agent_guidance(AGENT_ANTIGRAVITY).expect("antigravity guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_hermes() {
        assert_guidance_invariants(
            AGENT_HERMES,
            &agent_guidance(AGENT_HERMES).expect("hermes guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_gemini() {
        assert_guidance_invariants(
            AGENT_GEMINI,
            &agent_guidance(AGENT_GEMINI).expect("gemini guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_copilot() {
        assert_guidance_invariants(
            AGENT_COPILOT,
            &agent_guidance(AGENT_COPILOT).expect("copilot guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_opencode() {
        assert_guidance_invariants(
            AGENT_OPENCODE,
            &agent_guidance(AGENT_OPENCODE).expect("opencode guidance"),
        );
    }

    #[test]
    fn test_guidance_drift_guard_pidev() {
        assert_guidance_invariants(
            AGENT_PIDEV,
            &agent_guidance(AGENT_PIDEV).expect("pidev guidance"),
        );
    }

    #[test]
    fn test_guidance_unknown_agent_returns_error() {
        // CTXCRL no-panic rule: an unknown key surfaces as Err, not a panic.
        let err = agent_guidance("not-a-real-agent").unwrap_err();
        assert!(
            err.to_string().contains("unknown agent key"),
            "expected 'unknown agent key' error, got: {err}"
        );
    }

    #[test]
    fn test_guidance_all_harnesses_unique_titles() {
        // Every harness must have a distinct title line.
        let agents = [
            AGENT_CLAUDE, AGENT_CODEX, AGENT_CURSOR, AGENT_WINDSURF, AGENT_CLINE,
            AGENT_KILOCODE, AGENT_ANTIGRAVITY, AGENT_HERMES, AGENT_GEMINI,
            AGENT_COPILOT, AGENT_OPENCODE, AGENT_PIDEV,
        ];
        let titles: Vec<String> = agents
            .iter()
            .map(|a| {
                agent_guidance(a)
                    .expect("guidance")
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        let unique: std::collections::HashSet<_> = titles.iter().collect();
        assert_eq!(
            unique.len(),
            agents.len(),
            "Duplicate title line detected among harnesses: {titles:?}"
        );
    }

    #[test]
    fn test_guidance_cursor_mdc_frontmatter_format() {
        // Cursor .mdc guidance must have the YAML frontmatter prepended.
        let mdc_content = cursor_mdc_content().expect("cursor mdc content");
        assert!(
            mdc_content.starts_with("---\n"),
            "Cursor .mdc content must start with YAML frontmatter"
        );
        assert!(
            mdc_content.contains("alwaysApply: true"),
            "Cursor .mdc frontmatter must contain alwaysApply: true"
        );
        // The guidance body must follow the frontmatter intact.
        assert!(
            mdc_content.contains("# ContextCrawler (Cursor)"),
            "Cursor .mdc must contain the guidance heading after frontmatter"
        );
    }

    #[test]
    fn test_agent_guidance_block_has_markers() {
        // The marked-block wrapper must produce both upsert markers so
        // upsert_ctxcrl_block can detect and replace it idempotently.
        let block = agent_guidance_block(AGENT_OPENCODE).expect("opencode block");
        assert!(
            block.contains(CTXCRL_BLOCK_START),
            "agent_guidance_block must contain CTXCRL_BLOCK_START marker"
        );
        assert!(
            block.contains(CTXCRL_BLOCK_END),
            "agent_guidance_block must contain CTXCRL_BLOCK_END marker"
        );
        // Round-trip: upsert into empty, then strip, returns to empty.
        let (with_block, action) = upsert_ctxcrl_block("", &block);
        assert_eq!(action, CtxcrlBlockUpsert::Added);
        let (stripped, removed) = remove_ctxcrl_block(&with_block);
        assert!(removed, "block must be strippable");
        assert!(
            stripped.trim().is_empty(),
            "stripping the only block should leave the file empty"
        );
    }

    #[test]
    fn test_init_mentions_all_top_level_commands() {
        for cmd in [
            "contextcrawler cargo",
            "contextcrawler gh",
            "contextcrawler vitest",
            "contextcrawler tsc",
            "contextcrawler lint",
            "contextcrawler prettier",
            "contextcrawler next",
            "contextcrawler playwright",
            "contextcrawler prisma",
            "contextcrawler pnpm",
            "contextcrawler npm",
            "contextcrawler curl",
            "contextcrawler git",
            "contextcrawler docker",
            "contextcrawler kubectl",
        ] {
            assert!(
                CTXCRL_INSTRUCTIONS.contains(cmd),
                "Missing {cmd} in CTXCRL_INSTRUCTIONS"
            );
        }
    }

    #[test]
    fn test_init_has_version_marker() {
        assert!(
            CTXCRL_INSTRUCTIONS.contains(CTXCRL_BLOCK_START),
            "CTXCRL_INSTRUCTIONS must start with CTXCRL_BLOCK_START marker"
        );
        assert!(
            CTXCRL_INSTRUCTIONS.contains(CTXCRL_BLOCK_END),
            "CTXCRL_INSTRUCTIONS must end with CTXCRL_BLOCK_END marker"
        );
    }

    #[test]
    fn test_copilot_instructions_has_markers() {
        // Without both markers, `upsert_ctxcrl_block` cannot detect an existing
        // block and would append a duplicate on every re-init.
        assert!(
            COPILOT_INSTRUCTIONS.contains(CTXCRL_BLOCK_START),
            "COPILOT_INSTRUCTIONS must contain CTXCRL_BLOCK_START marker"
        );
        assert!(
            COPILOT_INSTRUCTIONS.contains(CTXCRL_BLOCK_END),
            "COPILOT_INSTRUCTIONS must contain CTXCRL_BLOCK_END marker"
        );
    }

    #[test]
    fn test_migration_removes_old_block() {
        let input = format!(
            "# My Config\n\n{} v2 -->\nOLD CTXCRL STUFF\n{}\n\nMore content",
            CTXCRL_BLOCK_START, CTXCRL_BLOCK_END
        );

        let (result, migrated) = remove_ctxcrl_block(&input);
        assert!(migrated);
        assert!(!result.contains("OLD CTXCRL STUFF"));
        assert!(result.contains("# My Config"));
        assert!(result.contains("More content"));
    }

    #[test]
    fn test_opencode_plugin_install_and_update() {
        let temp = TempDir::new().unwrap();
        let opencode_dir = temp.path().join("opencode");
        let plugin_path = opencode_plugin_path(&opencode_dir);

        fs::create_dir_all(plugin_path.parent().unwrap()).unwrap();
        assert!(!plugin_path.exists());

        let changed =
            ensure_opencode_plugin_installed(&plugin_path, InitContext::default()).unwrap();
        assert!(changed);
        let content = fs::read_to_string(&plugin_path).unwrap();
        assert_eq!(content, OPENCODE_PLUGIN);

        fs::write(&plugin_path, "// old").unwrap();
        let changed_again =
            ensure_opencode_plugin_installed(&plugin_path, InitContext::default()).unwrap();
        assert!(changed_again);
        let content_updated = fs::read_to_string(&plugin_path).unwrap();
        assert_eq!(content_updated, OPENCODE_PLUGIN);
    }

    #[test]
    fn test_opencode_plugin_remove() {
        let temp = TempDir::new().unwrap();
        let opencode_dir = temp.path().join("opencode");
        let plugin_path = opencode_plugin_path(&opencode_dir);
        fs::create_dir_all(plugin_path.parent().unwrap()).unwrap();
        fs::write(&plugin_path, OPENCODE_PLUGIN).unwrap();

        assert!(plugin_path.exists());
        fs::remove_file(&plugin_path).unwrap();
        assert!(!plugin_path.exists());
    }

    #[test]
    fn test_opencode_guidance_upserts_block_into_agents_md() {
        // OpenCode auto-loads AGENTS.md, not a standalone CONTEXTCRAWLER.md.
        // Verify the upsert preserves user content and is idempotent, and the
        // uninstall stripping leaves user content intact.
        let temp = TempDir::new().unwrap();
        let opencode_dir = temp.path().join("opencode");
        fs::create_dir_all(&opencode_dir).unwrap();
        let agents_md = opencode_agents_md_path(&opencode_dir);
        fs::write(&agents_md, "# Project notes\n\nUser text.\n").unwrap();

        let block = agent_guidance_block(AGENT_OPENCODE).expect("opencode block");

        // Install: upsert.
        write_ctxcrl_block(&agents_md, &block, "OpenCode guidance", "x", InitContext::default())
            .unwrap();
        let first = fs::read_to_string(&agents_md).unwrap();
        // Re-install: idempotent.
        write_ctxcrl_block(&agents_md, &block, "OpenCode guidance", "x", InitContext::default())
            .unwrap();
        let second = fs::read_to_string(&agents_md).unwrap();
        assert_eq!(first, second, "OpenCode AGENTS.md upsert must be idempotent");
        assert!(first.contains("# Project notes"));
        assert!(first.contains("User text."));
        assert!(first.contains("# ContextCrawler (OpenCode)"));
        assert_eq!(first.matches(CTXCRL_BLOCK_START).count(), 1);

        // Uninstall stripping must keep user content.
        let desc = strip_ctxcrl_block_from_file(&agents_md, "OpenCode guidance", InitContext::default())
            .unwrap();
        assert!(desc.is_some(), "strip must report removal");
        let after = fs::read_to_string(&agents_md).unwrap();
        assert!(after.contains("# Project notes"));
        assert!(after.contains("User text."));
        assert!(!after.contains(CTXCRL_BLOCK_START));
    }

    #[test]
    fn test_pidev_mode_writes_extension_and_agents_md() {
        // Install: extension file lands in <agent_dir>/extensions/, AGENTS.md
        // block is upserted, both idempotently, and user content survives.
        let temp = TempDir::new().unwrap();
        let agent_dir = temp.path().join("pi-agent");

        // Pre-seed AGENTS.md with user content the install must not clobber.
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(
            pidev_agents_md_path(&agent_dir),
            "# My Pi project notes\n\nUser text.\n",
        )
        .unwrap();

        // First install.
        run_pidev_mode_at(&agent_dir, InitContext::default()).unwrap();

        let extension_path = pidev_extension_path(&agent_dir);
        assert!(extension_path.exists(), "extension file must be written");
        assert_eq!(
            fs::read_to_string(&extension_path).unwrap(),
            PI_EXTENSION,
            "extension file content must equal the embedded TS source"
        );

        let agents_md_path = pidev_agents_md_path(&agent_dir);
        let first = fs::read_to_string(&agents_md_path).unwrap();
        assert!(first.contains("# My Pi project notes"), "user content preserved");
        assert!(first.contains("User text."), "user content preserved");
        assert!(first.contains("# ContextCrawler (Pi)"), "block has Pi title");
        assert_eq!(
            first.matches(CTXCRL_BLOCK_START).count(),
            1,
            "exactly one marked block after first install"
        );

        // Re-install: must be idempotent.
        run_pidev_mode_at(&agent_dir, InitContext::default()).unwrap();
        let second = fs::read_to_string(&agents_md_path).unwrap();
        assert_eq!(first, second, "run_pidev_mode_at must be idempotent");
    }

    #[test]
    fn test_pidev_uninstall_strips_block_and_removes_extension() {
        let temp = TempDir::new().unwrap();
        let agent_dir = temp.path().join("pi-agent");
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(
            pidev_agents_md_path(&agent_dir),
            "# User notes\n\nKeep me.\n",
        )
        .unwrap();

        // Install, then uninstall.
        run_pidev_mode_at(&agent_dir, InitContext::default()).unwrap();
        let removed = uninstall_pidev_at(&agent_dir, InitContext::default()).unwrap();

        // Both artifacts reported as removed.
        assert!(
            removed.iter().any(|r| r.contains("Pi guidance")),
            "uninstall must report stripping the guidance block: {removed:?}"
        );
        assert!(
            removed.iter().any(|r| r.contains("Pi extension")),
            "uninstall must report removing the extension file: {removed:?}"
        );

        // Extension file is gone.
        assert!(
            !pidev_extension_path(&agent_dir).exists(),
            "extension file must be removed"
        );

        // AGENTS.md still has the user content; the marked block is gone.
        let after = fs::read_to_string(pidev_agents_md_path(&agent_dir)).unwrap();
        assert!(after.contains("# User notes"), "user content preserved");
        assert!(after.contains("Keep me."), "user content preserved");
        assert!(
            !after.contains(CTXCRL_BLOCK_START),
            "ContextCrawler marker must be gone after uninstall"
        );
    }

    #[test]
    fn test_pidev_uninstall_noop_when_not_installed() {
        // Uninstall on a clean agent_dir: nothing to remove, no error.
        let temp = TempDir::new().unwrap();
        let agent_dir = temp.path().join("pi-agent");
        let removed = uninstall_pidev_at(&agent_dir, InitContext::default()).unwrap();
        assert!(
            removed.is_empty(),
            "no-op uninstall on a clean dir must report nothing removed: {removed:?}"
        );
    }

    #[test]
    fn test_strip_ctxcrl_block_deletes_file_when_only_our_block() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        let block = agent_guidance_block(AGENT_OPENCODE).expect("opencode block");
        fs::write(&agents_md, &block).unwrap();

        let desc = strip_ctxcrl_block_from_file(&agents_md, "OpenCode guidance", InitContext::default())
            .unwrap();
        assert!(desc.is_some());
        assert!(
            !agents_md.exists(),
            "file holding only our block should be deleted"
        );
    }

    #[test]
    fn test_strip_ctxcrl_block_noop_when_no_block() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        fs::write(&agents_md, "# Just user content\n").unwrap();

        let desc = strip_ctxcrl_block_from_file(&agents_md, "guidance", InitContext::default())
            .unwrap();
        assert!(desc.is_none(), "no block present — strip is a no-op");
        assert_eq!(
            fs::read_to_string(&agents_md).unwrap(),
            "# Just user content\n",
            "file must be untouched"
        );
    }

    #[test]
    fn test_strip_ctxcrl_block_missing_file_is_noop() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("AGENTS.md");
        let desc = strip_ctxcrl_block_from_file(&missing, "guidance", InitContext::default())
            .unwrap();
        assert!(desc.is_none());
        assert!(!missing.exists());
    }

    #[test]
    fn test_cursor_guidance_written_to_project_root() {
        // .cursor/rules/ is project-scoped — guidance must land at the project
        // root, not in ~/.cursor/.
        let temp = TempDir::new().unwrap();
        write_cursor_guidance(temp.path(), InitContext::default()).unwrap();

        let mdc = temp.path().join(".cursor/rules/contextcrawler.mdc");
        assert!(mdc.exists(), "Cursor .mdc must be written under project root");
        let content = fs::read_to_string(&mdc).unwrap();
        assert!(content.starts_with("---\n"), "must have YAML frontmatter");
        assert!(content.contains("alwaysApply: true"));
        assert!(content.contains("# ContextCrawler (Cursor)"));
    }

    #[test]
    fn test_looks_like_project_root_detection() {
        let temp = TempDir::new().unwrap();
        assert!(
            !looks_like_project_root(temp.path()),
            "empty dir is not a project root"
        );
        fs::write(temp.path().join("Cargo.toml"), "[package]\n").unwrap();
        assert!(
            looks_like_project_root(temp.path()),
            "dir with Cargo.toml is a project root"
        );
    }

    #[test]
    fn test_migration_warns_on_missing_end_marker() {
        let input = format!("{} v2 -->\nOLD STUFF\nNo end marker", CTXCRL_BLOCK_START);
        let (result, migrated) = remove_ctxcrl_block(&input);
        assert!(!migrated);
        assert_eq!(result, input);
    }

    #[test]
    fn test_default_mode_creates_ctxcrl_md() {
        let temp = TempDir::new().unwrap();
        let ctxcrl_md_path = temp.path().join("CONTEXTCRAWLER.md");

        let claude_guidance = agent_guidance(AGENT_CLAUDE).expect("claude guidance");
        fs::write(&ctxcrl_md_path, &claude_guidance).unwrap();
        assert!(ctxcrl_md_path.exists());

        let content = fs::read_to_string(&ctxcrl_md_path).unwrap();
        assert_eq!(content, claude_guidance);
    }

    #[test]
    fn test_claude_md_mode_creates_full_injection() {
        // Just verify CTXCRL_INSTRUCTIONS constant has the right content
        assert!(CTXCRL_INSTRUCTIONS.contains(CTXCRL_BLOCK_START));
        assert!(CTXCRL_INSTRUCTIONS.contains("contextcrawler cargo test"));
        assert!(CTXCRL_INSTRUCTIONS.contains(CTXCRL_BLOCK_END));
        assert!(CTXCRL_INSTRUCTIONS.len() > 4000);
    }

    // --- upsert_ctxcrl_block tests ---

    #[test]
    fn test_upsert_ctxcrl_block_appends_when_missing() {
        let input = "# Team instructions";
        let (content, action) = upsert_ctxcrl_block(input, CTXCRL_INSTRUCTIONS);
        assert_eq!(action, CtxcrlBlockUpsert::Added);
        assert!(content.contains("# Team instructions"));
        assert!(content.contains(CTXCRL_BLOCK_START));
    }

    #[test]
    fn test_upsert_ctxcrl_block_updates_stale_block() {
        let input = format!(
            "# Team instructions\n\n{} v1 -->\nOLD CTXCRL CONTENT\n{}\n\nMore notes\n",
            CTXCRL_BLOCK_START, CTXCRL_BLOCK_END
        );

        let (content, action) = upsert_ctxcrl_block(&input, CTXCRL_INSTRUCTIONS);
        assert_eq!(action, CtxcrlBlockUpsert::Updated);
        assert!(!content.contains("OLD CTXCRL CONTENT"));
        assert!(content.contains("contextcrawler cargo test")); // from current CTXCRL_INSTRUCTIONS
        assert!(content.contains("# Team instructions"));
        assert!(content.contains("More notes"));
    }

    #[test]
    fn test_upsert_ctxcrl_block_noop_when_already_current() {
        let input = format!(
            "# Team instructions\n\n{}\n\nMore notes\n",
            CTXCRL_INSTRUCTIONS
        );
        let (content, action) = upsert_ctxcrl_block(&input, CTXCRL_INSTRUCTIONS);
        assert_eq!(action, CtxcrlBlockUpsert::Unchanged);
        assert_eq!(content, input);
    }

    #[test]
    fn test_upsert_ctxcrl_block_detects_malformed_block() {
        let input = format!("{} v2 -->\npartial", CTXCRL_BLOCK_START);
        let (content, action) = upsert_ctxcrl_block(&input, CTXCRL_INSTRUCTIONS);
        assert_eq!(action, CtxcrlBlockUpsert::Malformed);
        assert_eq!(content, input);
    }

    // Fix 1: a pre-0.3.0 install's legacy `rtk-instructions` block must be
    // REPLACED in place on upgrade (not appended-to), leaving exactly ONE block
    // under the new ctxcrl markers and no leftover legacy block.
    #[test]
    fn test_upsert_replaces_legacy_rtk_block_in_place() {
        let input = format!(
            "# Team instructions\n\n{} v3 -->\nOLD RTK CONTENT\n{}\n\nMore notes\n",
            LEGACY_BLOCK_START, LEGACY_BLOCK_END
        );

        let (content, action) = upsert_ctxcrl_block(&input, CTXCRL_INSTRUCTIONS);

        assert_eq!(action, CtxcrlBlockUpsert::Updated);
        // Legacy block gone — both the body and the legacy markers.
        assert!(!content.contains("OLD RTK CONTENT"));
        assert!(!content.contains(LEGACY_BLOCK_START), "legacy start marker left behind");
        assert!(!content.contains(LEGACY_BLOCK_END), "legacy end marker left behind");
        // Exactly ONE canonical block now present.
        assert_eq!(
            content.matches(CTXCRL_BLOCK_START).count(),
            1,
            "expected exactly one ctxcrl block after upgrade, got duplicates"
        );
        // User content preserved.
        assert!(content.contains("# Team instructions"));
        assert!(content.contains("More notes"));
    }

    // Fix 1: strip/uninstall must also remove a legacy `rtk-instructions` block.
    #[test]
    fn test_strip_removes_legacy_rtk_block() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        let body = format!(
            "# Notes\n\n{} v3 -->\nLEGACY BODY\n{}\n\nkeep me\n",
            LEGACY_BLOCK_START, LEGACY_BLOCK_END
        );
        fs::write(&agents_md, &body).unwrap();

        let desc = strip_ctxcrl_block_from_file(&agents_md, "guidance", InitContext::default())
            .unwrap();
        assert!(desc.is_some(), "strip should report removal of a legacy block");

        let after = fs::read_to_string(&agents_md).unwrap();
        assert!(!after.contains(LEGACY_BLOCK_START), "legacy block not stripped");
        assert!(!after.contains("LEGACY BODY"));
        assert!(after.contains("# Notes"));
        assert!(after.contains("keep me"));
    }

    #[test]
    fn test_init_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let claude_md = temp.path().join("CLAUDE.md");

        fs::write(&claude_md, format!("# My stuff\n\n{}\n", CTXCRL_MD_REF)).unwrap();

        let content = fs::read_to_string(&claude_md).unwrap();
        let count = content.matches(CTXCRL_MD_REF).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_patch_agents_md_adds_reference_once() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");

        fs::write(&agents_md, "# Team rules\n").unwrap();
        let first_added = patch_agents_md(&agents_md, CTXCRL_MD_REF, InitContext::default()).unwrap();
        let second_added = patch_agents_md(&agents_md, CTXCRL_MD_REF, InitContext::default()).unwrap();

        assert!(first_added);
        assert!(!second_added);

        let content = fs::read_to_string(&agents_md).unwrap();
        assert_eq!(content.matches(CTXCRL_MD_REF).count(), 1);
    }

    #[test]
    fn test_codex_mode_rejects_auto_patch() {
        let err = run(
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            PatchMode::Auto,
            InitContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "--codex cannot be combined with --auto-patch"
        );
    }

    #[test]
    fn test_codex_mode_rejects_no_patch() {
        let err = run(
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            PatchMode::Skip,
            InitContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "--codex cannot be combined with --no-patch"
        );
    }

    #[test]
    fn test_kilocode_mode_creates_rules_file() {
        let temp = TempDir::new().unwrap();
        run_kilocode_mode_at(temp.path(), InitContext::default()).unwrap();

        let rules_path = temp.path().join(".kilocode/rules/rtk-rules.md");
        assert!(rules_path.exists(), "Rules file should be created");
        let content = fs::read_to_string(&rules_path).unwrap();
        assert!(
            content.contains("RTK") || content.contains("ContextCrawler"),
            "Rules file should reference the rewrite tool (RTK or ContextCrawler brand)"
        );
    }

    #[test]
    fn test_kilocode_mode_is_idempotent() {
        let temp = TempDir::new().unwrap();
        run_kilocode_mode_at(temp.path(), InitContext::default()).unwrap();

        let path = temp.path().join(".kilocode/rules/rtk-rules.md");
        let first = fs::read_to_string(&path).unwrap();

        // Second run should not overwrite
        run_kilocode_mode_at(temp.path(), InitContext::default()).unwrap();
        let second = fs::read_to_string(&path).unwrap();
        assert_eq!(first, second, "Idempotent: content should not change");
    }

    #[test]
    fn test_antigravity_mode_creates_rules_file() {
        let temp = TempDir::new().unwrap();
        run_antigravity_mode_at(temp.path(), InitContext::default()).unwrap();

        let rules_path = temp.path().join(".agents/rules/antigravity-rtk-rules.md");
        assert!(rules_path.exists(), "Rules file should be created");
        let content = fs::read_to_string(&rules_path).unwrap();
        assert!(
            content.contains("RTK") || content.contains("ContextCrawler"),
            "Rules file should reference the rewrite tool (RTK or ContextCrawler brand)"
        );
    }

    #[test]
    fn test_antigravity_mode_is_idempotent() {
        let temp = TempDir::new().unwrap();
        run_antigravity_mode_at(temp.path(), InitContext::default()).unwrap();

        let path = temp.path().join(".agents/rules/antigravity-rtk-rules.md");
        let first = fs::read_to_string(&path).unwrap();

        // Second run should not overwrite
        run_antigravity_mode_at(temp.path(), InitContext::default()).unwrap();
        let second = fs::read_to_string(&path).unwrap();
        assert_eq!(first, second, "Idempotent: content should not change");
    }

    #[test]
    fn test_patch_agents_md_creates_missing_file() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");

        let added = patch_agents_md(&agents_md, CTXCRL_MD_REF, InitContext::default()).unwrap();

        assert!(added);
        let content = fs::read_to_string(&agents_md).unwrap();
        assert_eq!(content, format!("{}\n", CTXCRL_MD_REF));
    }

    #[test]
    fn test_patch_agents_md_migrates_inline_block() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        fs::write(
            &agents_md,
            format!(
                "# Team rules\n\n{} v2 -->\nold\n{}\n",
                CTXCRL_BLOCK_START, CTXCRL_BLOCK_END
            ),
        )
        .unwrap();

        let added = patch_agents_md(&agents_md, CTXCRL_MD_REF, InitContext::default()).unwrap();

        assert!(added);
        let content = fs::read_to_string(&agents_md).unwrap();
        assert!(!content.contains("old"));
        assert_eq!(content.matches(CTXCRL_MD_REF).count(), 1);
    }

    #[test]
    fn test_hermes_mode_creates_plugin_files() {
        let temp = TempDir::new().unwrap();
        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();

        let plugin_dir = temp.path().join("plugins/rtk-rewrite");
        let init_path = plugin_dir.join("__init__.py");
        let manifest_path = plugin_dir.join("plugin.yaml");
        let config_path = temp.path().join("config.yaml");

        assert!(init_path.exists(), "Python plugin should be created");
        assert!(manifest_path.exists(), "Plugin manifest should be created");
        assert_eq!(
            fs::read_to_string(&init_path).unwrap(),
            include_str!("../../hooks/hermes/ctxcrl-rewrite/__init__.py")
        );
        assert_eq!(
            fs::read_to_string(&manifest_path).unwrap(),
            include_str!("../../hooks/hermes/ctxcrl-rewrite/plugin.yaml")
        );

        let config = fs::read_to_string(&config_path).unwrap();
        assert!(config.contains("plugins:\n"));
        assert!(config.contains("  enabled:\n"));
        assert_eq!(config.matches("rtk-rewrite").count(), 1);

        // Guidance must be upserted as a MARKED BLOCK into AGENTS.md
        // (Hermes auto-loads AGENTS.md, not a standalone CONTEXTCRAWLER.md).
        let agents_md = temp.path().join("AGENTS.md");
        assert!(agents_md.exists(), "Hermes guidance AGENTS.md should be created");
        let agents = fs::read_to_string(&agents_md).unwrap();
        assert!(agents.contains(CTXCRL_BLOCK_START), "AGENTS.md must hold the CTXCRL block start marker");
        assert!(agents.contains(CTXCRL_BLOCK_END), "AGENTS.md must hold the CTXCRL block end marker");
        assert!(agents.contains("# ContextCrawler (Hermes)"), "AGENTS.md must hold Hermes guidance");
        // No standalone CONTEXTCRAWLER.md should be written.
        assert!(
            !temp.path().join(CTXCRL_MD).exists(),
            "Hermes must NOT write a standalone CONTEXTCRAWLER.md"
        );
    }

    #[test]
    fn test_hermes_mode_guidance_block_preserves_user_content_and_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        fs::write(&agents_md, "# Team rules\n\nDo the thing.\n").unwrap();

        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();
        let first = fs::read_to_string(&agents_md).unwrap();
        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();
        let second = fs::read_to_string(&agents_md).unwrap();

        assert_eq!(first, second, "Hermes AGENTS.md upsert must be idempotent");
        assert!(first.contains("# Team rules"), "user content must be preserved");
        assert!(first.contains("Do the thing."), "user content must be preserved");
        assert!(first.contains("# ContextCrawler (Hermes)"));
        assert_eq!(
            first.matches(CTXCRL_BLOCK_START).count(),
            1,
            "exactly one CTXCRL block — no duplicate on re-run"
        );
    }

    #[test]
    fn test_hermes_uninstall_strips_guidance_block_preserving_user_content() {
        let temp = TempDir::new().unwrap();
        let hermes_home = temp.path();
        let agents_md = hermes_home.join("AGENTS.md");
        fs::write(&agents_md, "# Team rules\n\nKeep me.\n").unwrap();

        run_hermes_mode_at(hermes_home, InitContext::default()).unwrap();
        assert!(fs::read_to_string(&agents_md).unwrap().contains("# ContextCrawler (Hermes)"));

        let removed = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();
        assert!(
            removed.iter().any(|r| r.contains("Hermes guidance")),
            "uninstall must report stripping the guidance block, got: {removed:?}"
        );

        // AGENTS.md must survive with user content intact, block gone.
        let after = fs::read_to_string(&agents_md).unwrap();
        assert!(after.contains("# Team rules"), "user content must survive uninstall");
        assert!(after.contains("Keep me."), "user content must survive uninstall");
        assert!(!after.contains(CTXCRL_BLOCK_START), "CTXCRL block must be removed");
        assert!(!after.contains("# ContextCrawler (Hermes)"), "guidance must be removed");
    }

    #[test]
    fn test_hermes_uninstall_deletes_agents_md_when_only_our_block() {
        let temp = TempDir::new().unwrap();
        let hermes_home = temp.path();
        let agents_md = hermes_home.join("AGENTS.md");

        // No pre-existing AGENTS.md — install creates one holding only our block.
        run_hermes_mode_at(hermes_home, InitContext::default()).unwrap();
        assert!(agents_md.exists());

        uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();
        assert!(
            !agents_md.exists(),
            "AGENTS.md holding only our block should be deleted on uninstall"
        );
    }

    #[test]
    fn test_hermes_mode_preserves_config_and_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        fs::write(
            &config_path,
            "theme: dark\nplugins:\n  enabled:\n    - existing-plugin\n  search_path: ./plugins\nother: true\n",
        )
        .unwrap();

        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();
        let first = fs::read_to_string(&config_path).unwrap();
        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();
        let second = fs::read_to_string(&config_path).unwrap();

        assert_eq!(first, second, "Hermes config patch should be idempotent");
        assert!(first.contains("theme: dark\n"));
        assert!(first.contains("    - existing-plugin\n"));
        assert!(first.contains("  search_path: ./plugins\n"));
        assert!(first.contains("other: true\n"));
        assert_eq!(first.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_mode_preserves_pyyaml_same_indent_config_and_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        fs::write(
            &config_path,
            "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n search_path: ./plugins\nother: true\n",
        )
        .unwrap();

        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();
        let first = fs::read_to_string(&config_path).unwrap();
        run_hermes_mode_at(temp.path(), InitContext::default()).unwrap();
        let second = fs::read_to_string(&config_path).unwrap();

        let expected = "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n - rtk-rewrite\n search_path: ./plugins\nother: true\n";
        assert_eq!(first, expected);
        assert_eq!(
            second, expected,
            "Hermes PyYAML config patch should be idempotent"
        );
        assert_eq!(first.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_mode_patches_and_uninstalls_pyyaml_same_indent_missing_enabled_idempotently() {
        let temp = TempDir::new().unwrap();
        let hermes_home = temp.path();
        let plugin_dir = hermes_home.join("plugins").join(HERMES_PLUGIN_NAME);
        let other_plugin_dir = hermes_home.join("plugins/keep-me");
        let other_plugin_file = other_plugin_dir.join("plugin.yaml");
        let config_path = hermes_home.join("config.yaml");

        fs::create_dir_all(&other_plugin_dir).unwrap();
        fs::write(&other_plugin_file, "keep").unwrap();
        fs::write(
            &config_path,
            "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n search_path: ./plugins\nother: true\n",
        )
        .unwrap();

        run_hermes_mode_at(hermes_home, InitContext::default()).unwrap();
        let first = fs::read_to_string(&config_path).unwrap();
        run_hermes_mode_at(hermes_home, InitContext::default()).unwrap();
        let second = fs::read_to_string(&config_path).unwrap();

        let installed = "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n search_path: ./plugins\n enabled:\n - rtk-rewrite\nother: true\n";
        assert_eq!(first, installed);
        assert_eq!(second, installed);
        assert_eq!(first.matches("rtk-rewrite").count(), 1);
        assert!(plugin_dir.exists());
        assert_eq!(fs::read_to_string(&other_plugin_file).unwrap(), "keep");

        let removed_first = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();
        let removed_second = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();

        // 3 artifacts: plugin dir, config entry, and the AGENTS.md guidance
        // block (run_hermes_mode_at now upserts guidance into AGENTS.md).
        assert_eq!(removed_first.len(), 3);
        assert!(removed_first.iter().any(|r| r.contains("Hermes guidance")));
        assert!(removed_second.is_empty());
        assert!(!plugin_dir.exists());
        assert!(other_plugin_dir.exists());
        assert_eq!(fs::read_to_string(&other_plugin_file).unwrap(), "keep");

        let uninstalled = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            uninstalled,
            "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n search_path: ./plugins\n enabled: []\nother: true\n"
        );
        assert!(!uninstalled.contains("\n - \n"));
        assert!(!uninstalled.contains("\n -\n"));
        assert_eq!(uninstalled.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_uninstall_hermes_at_removes_plugin_dir_and_cleans_config() {
        let temp = TempDir::new().unwrap();
        let hermes_home = temp.path();
        let plugin_dir = hermes_home.join("plugins").join(HERMES_PLUGIN_NAME);
        let nested_plugin_file = plugin_dir.join("nested/marker.txt");
        let other_plugin_dir = hermes_home.join("plugins/keep-me");
        let other_plugin_file = other_plugin_dir.join("plugin.yaml");
        let config_path = hermes_home.join("config.yaml");

        fs::create_dir_all(nested_plugin_file.parent().unwrap()).unwrap();
        fs::write(&nested_plugin_file, "rtk").unwrap();
        fs::create_dir_all(&other_plugin_dir).unwrap();
        fs::write(&other_plugin_file, "keep").unwrap();
        fs::write(
            &config_path,
            "theme: dark\nplugins:\n  enabled:\n    - existing-plugin\n    - rtk-rewrite\n  search_path: ./plugins\nother: true\n",
        )
        .unwrap();

        let removed_first = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();
        let removed_second = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();

        assert_eq!(removed_first.len(), 2);
        assert!(removed_second.is_empty());
        assert!(!plugin_dir.exists());
        assert!(other_plugin_dir.exists());
        assert_eq!(fs::read_to_string(&other_plugin_file).unwrap(), "keep");

        let config = fs::read_to_string(&config_path).unwrap();
        assert!(config.contains("theme: dark\n"));
        assert!(config.contains("    - existing-plugin\n"));
        assert!(config.contains("  search_path: ./plugins\n"));
        assert!(config.contains("other: true\n"));
        assert_eq!(config.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_uninstall_hermes_at_cleans_pyyaml_same_indent_config_idempotently() {
        let temp = TempDir::new().unwrap();
        let hermes_home = temp.path();
        let plugin_dir = hermes_home.join("plugins").join(HERMES_PLUGIN_NAME);
        let nested_plugin_file = plugin_dir.join("nested/marker.txt");
        let other_plugin_dir = hermes_home.join("plugins/keep-me");
        let other_plugin_file = other_plugin_dir.join("plugin.yaml");
        let config_path = hermes_home.join("config.yaml");

        fs::create_dir_all(nested_plugin_file.parent().unwrap()).unwrap();
        fs::write(&nested_plugin_file, "rtk").unwrap();
        fs::create_dir_all(&other_plugin_dir).unwrap();
        fs::write(&other_plugin_file, "keep").unwrap();
        fs::write(
            &config_path,
            "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n - rtk-rewrite\n search_path: ./plugins\nother: true\n",
        )
        .unwrap();

        let removed_first = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();
        let removed_second = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();

        assert_eq!(removed_first.len(), 2);
        assert!(removed_second.is_empty());
        assert!(!plugin_dir.exists());
        assert!(other_plugin_dir.exists());
        assert_eq!(fs::read_to_string(&other_plugin_file).unwrap(), "keep");

        let config = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            config,
            "theme: dark\nplugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n search_path: ./plugins\nother: true\n"
        );
        assert!(!config.contains("\n - \n"));
        assert!(!config.contains("\n -\n"));
        assert_eq!(config.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_uninstall_hermes_at_missing_files_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let hermes_home = temp.path();

        let removed_first = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();
        let removed_second = uninstall_hermes_at(hermes_home, InitContext::default()).unwrap();

        assert!(removed_first.is_empty());
        assert!(removed_second.is_empty());
        assert!(!hermes_home.join("plugins").exists());
        assert!(!hermes_home.join("config.yaml").exists());
    }

    #[test]
    fn test_hermes_config_patch_adds_missing_enabled_list() {
        let existing = "theme: dark\nplugins:\n  search_path: ./plugins\nother: true\n";
        let patched = patch_hermes_config(existing);

        assert!(patched.contains("theme: dark\n"));
        assert!(patched.contains("plugins:\n"));
        assert!(patched.contains("  search_path: ./plugins\n"));
        assert!(patched.contains("  enabled:\n    - rtk-rewrite\n"));
        assert!(patched.contains("other: true\n"));
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_removes_duplicate_rtk_rewrite() {
        let existing = "plugins:\n  enabled:\n    - rtk-rewrite\n    - other\n    - rtk-rewrite\n";
        let patched = patch_hermes_config(existing);

        assert!(patched.contains("    - other\n"));
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_pyyaml_indentationless_enabled_list() {
        let existing =
            "plugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n";

        let patched = patch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n - rtk-rewrite\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_pyyaml_default_compact_enabled_list() {
        let existing = "plugins:\n  enabled:\n  - foo\n";

        let patched = patch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled:\n  - foo\n  - rtk-rewrite\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_pyyaml_indentationless_missing_enabled_list() {
        let existing =
            "plugins:\n disabled:\n - google_meet\n - spotify\n search_path: ./plugins\n";

        let patched = patch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n disabled:\n - google_meet\n - spotify\n search_path: ./plugins\n enabled:\n - rtk-rewrite\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_pyyaml_indentationless_enabled_is_idempotent() {
        let existing = "plugins:\n enabled:\n - disk-cleanup\n disabled:\n - spotify\n";

        let patched_once = patch_hermes_config(existing);
        let patched_twice = patch_hermes_config(&patched_once);

        assert_eq!(
            patched_once,
            "plugins:\n enabled:\n - disk-cleanup\n - rtk-rewrite\n disabled:\n - spotify\n"
        );
        assert_eq!(patched_twice, patched_once);
        assert_eq!(patched_once.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_pyyaml_indentationless_final_line_without_newline() {
        let existing = "plugins:\n enabled:\n - disk-cleanup";

        let patched = patch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n enabled:\n - disk-cleanup\n - rtk-rewrite\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_block_enabled_final_line_without_newline() {
        let existing = "plugins:\n  enabled:\n    - existing-plugin";

        let patched = patch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n  enabled:\n    - existing-plugin\n    - rtk-rewrite\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_missing_enabled_after_final_child_without_newline() {
        let existing = "plugins:\n  search_path: ./plugins";

        let patched = patch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n  search_path: ./plugins\n  enabled:\n    - rtk-rewrite\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_empty_enabled_final_line_without_newline() {
        let existing = "plugins:\n  enabled:";

        let patched = patch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled:\n    - rtk-rewrite\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_inline_enabled_is_idempotent() {
        let existing = "theme: dark\nplugins:\n  enabled: [existing-plugin, rtk-rewrite] # keep\n  search_path: ./plugins\nother: true\n";

        let patched = patch_hermes_config(existing);

        assert_eq!(patched, existing);
        assert_eq!(patch_hermes_config(&patched), patched);
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_patch_inline_enabled_without_final_newline_is_idempotent() {
        let existing = "plugins:\n  enabled: [existing-plugin, rtk-rewrite]";

        let patched = patch_hermes_config(existing);

        assert_eq!(patched, existing);
        assert_eq!(patch_hermes_config(&patched), patched);
        assert_eq!(patched.matches("rtk-rewrite").count(), 1);
    }

    #[test]
    fn test_hermes_config_unpatch_inline_enabled_without_rtk_preserves_missing_final_newline() {
        let existing = "plugins:\n  enabled: [existing-plugin]";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, existing);
    }

    #[test]
    fn test_hermes_config_unpatch_inline_enabled_preserves_unrelated_entries() {
        let existing = "theme: dark\nplugins:\n  enabled: [alpha, rtk-rewrite, beta] # keep comment\n  search_path: ./plugins\nother: true\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(
            patched,
            "theme: dark\nplugins:\n  enabled: [alpha, beta] # keep comment\n  search_path: ./plugins\nother: true\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_inline_enabled_final_line_without_newline() {
        let existing = "plugins:\n  enabled: [existing-plugin, rtk-rewrite]";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled: [existing-plugin]");
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_removes_duplicate_inline_rtk_rewrite() {
        let existing = "plugins:\n  enabled: [alpha, rtk-rewrite, beta, rtk-rewrite]\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled: [alpha, beta]\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_removes_duplicate_block_rtk_rewrite() {
        let existing = "plugins:\n  enabled:\n    - rtk-rewrite\n    - other\n    - rtk-rewrite\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled:\n    - other\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_pyyaml_indentationless_enabled_list() {
        let existing = "plugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n - rtk-rewrite\n search_path: ./plugins\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n disabled:\n - google_meet\n - spotify\n enabled:\n - disk-cleanup\n search_path: ./plugins\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_pyyaml_indentationless_only_rtk_collapses_to_empty() {
        let existing = "plugins:\n enabled:\n - rtk-rewrite\n search_path: ./plugins\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n enabled: []\n search_path: ./plugins\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_block_enabled_final_line_without_newline() {
        let existing = "plugins:\n  enabled:\n    - existing-plugin\n    - rtk-rewrite";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled:\n    - existing-plugin\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_block_enabled_without_rtk_preserves_missing_final_newline() {
        let existing = "plugins:\n  enabled:\n    - existing-plugin";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, existing);
    }

    #[test]
    fn test_hermes_config_unpatch_preserves_quoted_exact_values() {
        let existing = "plugins:\n  enabled:\n    - 'alpha'\n    - \"rtk-rewrite\"\n    - 'beta'\n  search_path: ./plugins\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(
            patched,
            "plugins:\n  enabled:\n    - 'alpha'\n    - 'beta'\n  search_path: ./plugins\n"
        );
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_hermes_config_unpatch_leaves_missing_enabled_list_unchanged() {
        let existing = "theme: dark\nplugins:\n  search_path: ./plugins\nother: true\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, existing);
    }

    #[test]
    fn test_hermes_config_unpatch_collapses_empty_enabled_list() {
        let existing = "plugins:\n  enabled:\n    - rtk-rewrite\n";

        let patched = unpatch_hermes_config(existing);

        assert_eq!(patched, "plugins:\n  enabled: []\n");
        assert_eq!(patched.matches("rtk-rewrite").count(), 0);
    }

    #[test]
    fn test_run_codex_mode_global_writes_absolute_reference_to_codex_dir() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        // Use the constant so the fixture filename tracks any future rename
        // — and so cleanup_legacy_codex_files (which removes CONTEXTCRAWLER.md) doesn't
        // delete our test fixture.
        let ctxcrl_md = temp.path().join(CTXCRL_MD);

        run_codex_mode_with_paths(
            agents_md.clone(),
            ctxcrl_md.clone(),
            true,
            InitContext::default(),
        )
        .unwrap();

        assert!(ctxcrl_md.exists());
        assert_eq!(
            fs::read_to_string(&ctxcrl_md).unwrap(),
            agent_guidance(AGENT_CODEX).expect("codex guidance")
        );
        assert_eq!(
            fs::read_to_string(&agents_md).unwrap(),
            format!("{}\n", codex_ctxcrl_md_ref(temp.path()))
        );
    }

    #[test]
    fn test_ctxcrl_md_constant_pinned_to_contextcrawler_filename() {
        // REGRESSION GUARD (issue #19). The downstream rebrand requires the
        // slim instructions file to be named CONTEXTCRAWLER.md so it matches
        // the tool name on disk. Commit bcddd06 silently flipped this back
        // to "CONTEXTCRAWLER.md" during the upstream rebase and the rebrand sweep
        // missed it, breaking every existing user's `init -g --codex` and
        // leaving orphan files behind. If you're changing this assertion,
        // you're probably re-introducing the regression — read #19 first.
        assert_eq!(
            CTXCRL_MD,
            "CONTEXTCRAWLER.md",
            "filename regression: see issue #19"
        );
        assert_eq!(
            CTXCRL_MD_REF,
            "@CONTEXTCRAWLER.md",
            "filename regression: see issue #19"
        );
    }

    #[test]
    fn test_codex_template_pins_gap_patterns() {
        // REGRESSION GUARD (issue #53). The codex AGENTS.md template MUST
        // explicitly cover the three gap patterns measured in the post-v0.1.8
        // compliance audit:
        //   - `nl -ba … | sed -n` (composed pipe, ~35 raw/24h)
        //   - `git -C <dir>` (cross-directory git, ~25 raw/24h)
        //   - `rg -n` (short rg form, ~11 raw/24h)
        // If you're editing the template, KEEP these patterns — removing them
        // regresses the codex compliance lift driven by #53. Read the issue
        // before changing this assertion.
        let codex_guidance = agent_guidance(AGENT_CODEX).expect("codex guidance");
        for needle in &["git -C ", "rg -n ", "nl -ba "] {
            assert!(
                codex_guidance.contains(needle),
                "codex template missing gap pattern '{}' — see issue #53",
                needle
            );
        }
    }

    #[test]
    fn test_cleanup_legacy_codex_files_removes_orphan_ctxcrl_md() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        // Fixture must use the legacy filename so the test exercises the
        // codepath that the cleanup helper exists to handle.
        let legacy_ctxcrl_md = temp.path().join("RTK.md");
        fs::write(&legacy_ctxcrl_md, "old content").unwrap();
        fs::write(
            &agents_md,
            format!(
                "# header\n\n@{}\n\n@{}\n",
                legacy_ctxcrl_md.display(),
                temp.path().join("CONTEXTCRAWLER.md").display()
            ),
        )
        .unwrap();

        let notes = cleanup_legacy_codex_files(
            &agents_md,
            temp.path(),
            InitContext::default(),
        )
        .unwrap();

        assert!(!legacy_ctxcrl_md.exists(), "legacy RTK.md should be removed");
        let after = fs::read_to_string(&agents_md).unwrap();
        assert!(
            !after.contains(&format!("@{}", legacy_ctxcrl_md.display())),
            "absolute @-ref to legacy RTK.md should be stripped, got:\n{}",
            after
        );
        assert!(
            after.contains(&format!("@{}", temp.path().join("CONTEXTCRAWLER.md").display())),
            "canonical @CONTEXTCRAWLER.md reference should be preserved"
        );
        assert!(notes.iter().any(|n| n.contains("removed orphan")));
        assert!(notes.iter().any(|n| n.contains("AGENTS.md")));
    }

    #[test]
    fn test_cleanup_legacy_codex_files_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        fs::write(&agents_md, "# header\n").unwrap();

        let notes = cleanup_legacy_codex_files(
            &agents_md,
            temp.path(),
            InitContext::default(),
        )
        .unwrap();

        assert!(notes.is_empty(), "no-op cleanup should report nothing");
        assert_eq!(fs::read_to_string(&agents_md).unwrap(), "# header\n");
    }

    #[test]
    fn test_cleanup_legacy_codex_files_handles_relative_at_ref() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        // Some older installs used a relative `@RTK.md` rather than the
        // absolute path. Both forms must be stripped.
        fs::write(&agents_md, "# header\n\n@RTK.md\n").unwrap();

        let _ = cleanup_legacy_codex_files(
            &agents_md,
            temp.path(),
            InitContext::default(),
        )
        .unwrap();

        let after = fs::read_to_string(&agents_md).unwrap();
        assert!(!after.contains("@RTK.md"), "relative @RTK.md must be stripped");
    }

    #[test]
    fn test_strip_at_reference_line_collapses_surrounding_blanks() {
        let content = "alpha\n\n@RTK.md\n\nbeta\n";
        let out = strip_at_reference_line(content, "@RTK.md");
        assert_eq!(out, "alpha\n\nbeta\n");
    }

    #[test]
    fn test_patch_claude_md_migrates_legacy_at_ref_in_place() {
        // Codex review on #19: on upgraded installs, CLAUDE.md may still
        // contain `@RTK.md` (the legacy form). Without migration, the
        // contains-check below would miss it and the appender would add a
        // second `@CONTEXTCRAWLER.md` line, leaving both references in
        // place. This test asserts the legacy line is rewritten to the
        // canonical form rather than duplicated.
        let temp = TempDir::new().unwrap();
        let claude_md = temp.path().join("CLAUDE.md");
        fs::write(&claude_md, "# My stuff\n\n@RTK.md\n").unwrap();

        let migrated = patch_claude_md(&claude_md, InitContext::default()).unwrap();
        assert!(migrated);

        let content = fs::read_to_string(&claude_md).unwrap();
        assert!(
            content.contains(CTXCRL_MD_REF),
            "must end up with the canonical reference, got:\n{}",
            content
        );
        assert!(
            !content.contains("@RTK.md"),
            "legacy @RTK.md must be removed, got:\n{}",
            content
        );
        // And idempotent — a second run with the new content already in
        // place must not duplicate the line.
        let _ = patch_claude_md(&claude_md, InitContext::default()).unwrap();
        let content2 = fs::read_to_string(&claude_md).unwrap();
        assert_eq!(content2.matches(CTXCRL_MD_REF).count(), 1);
    }

    #[test]
    fn test_uninstall_codex_at_removes_legacy_ctxcrl_md_file_and_ref() {
        // Codex review on #19: an existing Codex home that still has
        // RTK.md / @RTK.md from a regressed install should be cleanable
        // via `uninstall --codex` without forcing the user to run a
        // fresh `init` first.
        let temp = TempDir::new().unwrap();
        let codex_dir = temp.path();
        let agents_md = codex_dir.join("AGENTS.md");
        let legacy_ctxcrl_md = codex_dir.join("RTK.md");

        fs::write(&agents_md, "# Team rules\n\n@RTK.md\n").unwrap();
        fs::write(&legacy_ctxcrl_md, "legacy codex config").unwrap();

        let removed = uninstall_codex_at(codex_dir, InitContext::default()).unwrap();

        assert!(!legacy_ctxcrl_md.exists(), "legacy RTK.md must be removed");
        let content = fs::read_to_string(&agents_md).unwrap();
        assert!(
            !content.contains("@RTK.md"),
            "legacy @RTK.md ref must be stripped, got:\n{}",
            content
        );
        assert!(content.contains("# Team rules"));
        // The removal should report at least the legacy file + the ref.
        assert!(removed.iter().any(|r| r.contains("RTK.md")));
        assert!(removed.iter().any(|r| r.contains("AGENTS.md")));
    }

    #[test]
    fn test_resolve_codex_dir_prefers_codex_home_and_ignores_empty_value() {
        // A CODEX_HOME *inside* $HOME is accepted without the opt-in.
        let home_dir = PathBuf::from("/tmp/home");
        let codex_home = home_dir.join("custom-codex-home");

        let preferred =
            resolve_codex_dir_from(Some(codex_home.clone()), Some(home_dir.clone()), false)
                .unwrap();
        let empty_falls_back =
            resolve_codex_dir_from(Some(PathBuf::new()), Some(home_dir.clone()), false).unwrap();
        let missing_falls_back =
            resolve_codex_dir_from(None, Some(home_dir.clone()), false).unwrap();

        assert_eq!(preferred, codex_home);
        assert_eq!(empty_falls_back, home_dir.join(".codex"));
        assert_eq!(missing_falls_back, home_dir.join(".codex"));
    }

    #[test]
    fn test_codex_home_path_escapes_home() {
        // REGRESSION (issue #27 defence-in-depth). Lexical fallback when
        // canonicalize fails (paths don't have to exist for this check;
        // canonicalize errors get swallowed and we compare raw paths).
        let home = PathBuf::from("/Users/test");

        // Outside-home accidents that should be flagged.
        assert!(
            root_escapes_home(&PathBuf::from("/etc"), &home),
            "/etc should be flagged as outside /Users/test"
        );
        assert!(
            root_escapes_home(&PathBuf::from("/tmp/evil"), &home),
            "/tmp/evil should be flagged"
        );
        assert!(
            root_escapes_home(&PathBuf::from("/var/folders"), &home),
            "/var/folders should be flagged"
        );

        // Inside-home: standard locations should NOT be flagged.
        assert!(
            !root_escapes_home(&PathBuf::from("/Users/test/.codex"), &home),
            "default ~/.codex must not be flagged"
        );
        assert!(
            !root_escapes_home(&PathBuf::from("/Users/test/custom-codex"), &home),
            "alt path inside home must not be flagged"
        );
    }

    #[test]
    fn test_resolve_codex_dir_rejects_path_outside_home() {
        // SECURITY (#100 G2 IMPORTANT 5): a $CODEX_HOME that escapes $HOME
        // must FAIL CLOSED — a poisoned env var must not redirect config
        // writes/deletes outside the user's home.
        let escapes = PathBuf::from("/etc/codex-fake");
        let home = PathBuf::from("/Users/test");
        let result = resolve_codex_dir_from(Some(escapes.clone()), Some(home.clone()), false);
        assert!(result.is_err(), "escaping CODEX_HOME must be rejected");

        // With the explicit opt-in, the escaping path is honoured.
        let allowed =
            resolve_codex_dir_from(Some(escapes.clone()), Some(home), true).unwrap();
        assert_eq!(allowed, escapes);
    }

    #[test]
    fn test_resolve_hermes_home_prefers_hermes_home() {
        // A HERMES_HOME inside $HOME is accepted without the opt-in.
        let home_dir = PathBuf::from("/tmp/home");
        let hermes_home = OsString::from("/tmp/home/custom hermes home");

        let resolved =
            resolve_hermes_home_from_env(Some(home_dir), Some(hermes_home.clone()), false)
                .unwrap();

        assert_eq!(resolved, PathBuf::from(hermes_home));
    }

    #[test]
    fn test_resolve_hermes_home_rejects_path_outside_home() {
        // SECURITY (#100 G2 IMPORTANT 5): an escaping $HERMES_HOME fails
        // closed unless the explicit opt-in is set.
        let home_dir = PathBuf::from("/Users/test");
        let escapes = OsString::from("/etc/hermes-fake");

        let rejected = resolve_hermes_home_from_env(
            Some(home_dir.clone()),
            Some(escapes.clone()),
            false,
        );
        assert!(rejected.is_err(), "escaping HERMES_HOME must be rejected");

        let allowed =
            resolve_hermes_home_from_env(Some(home_dir), Some(escapes.clone()), true).unwrap();
        assert_eq!(allowed, PathBuf::from(escapes));
    }

    #[test]
    fn test_patch_gemini_settings_errors_on_malformed_json() {
        // SECURITY (#100 G2 IMPORTANT 4): a malformed settings.json must
        // cause an error, NOT be silently replaced with `{}` and
        // reserialised (which destroys the user's whole Gemini config).
        let temp = TempDir::new().unwrap();
        let gemini_dir = temp.path();
        let settings_path = gemini_dir.join(SETTINGS_JSON);
        let original = "{ this is not valid json ";
        fs::write(&settings_path, original).unwrap();

        let hook_path = gemini_dir.join("hooks").join(GEMINI_HOOK_FILE);
        let result = patch_gemini_settings(
            gemini_dir,
            &hook_path,
            PatchMode::Auto,
            InitContext::default(),
        );

        assert!(result.is_err(), "malformed settings.json must error");
        // Critically — the original (malformed) file must be untouched.
        let after = fs::read_to_string(&settings_path).unwrap();
        assert_eq!(after, original, "user's settings.json must NOT be clobbered");
    }

    #[test]
    fn test_resolve_hermes_home_empty_env_falls_back_to_home() {
        let home_dir = PathBuf::from("/tmp/home");

        let empty_falls_back =
            resolve_hermes_home_from_env(Some(home_dir.clone()), Some(OsString::new()), false)
                .unwrap();
        let missing_falls_back =
            resolve_hermes_home_from_env(Some(home_dir.clone()), None, false).unwrap();

        assert_eq!(empty_falls_back, home_dir.join(".hermes"));
        assert_eq!(missing_falls_back, home_dir.join(".hermes"));
    }

    #[test]
    fn test_uninstall_codex_at_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let codex_dir = temp.path();
        let agents_md = codex_dir.join("AGENTS.md");
        let ctxcrl_md = codex_dir.join(CTXCRL_MD);

        fs::write(&agents_md, format!("# Team rules\n\n{}\n", CTXCRL_MD_REF)).unwrap();
        fs::write(&ctxcrl_md, "codex config").unwrap();

        let removed_first = uninstall_codex_at(codex_dir, InitContext::default()).unwrap();
        let removed_second = uninstall_codex_at(codex_dir, InitContext::default()).unwrap();

        assert_eq!(removed_first.len(), 2);
        assert!(removed_second.is_empty());
        assert!(!ctxcrl_md.exists());

        let content = fs::read_to_string(&agents_md).unwrap();
        assert!(!content.contains(CTXCRL_MD_REF));
        assert!(content.contains("# Team rules"));
    }

    #[test]
    fn test_uninstall_codex_at_removes_absolute_reference() {
        let temp = TempDir::new().unwrap();
        let codex_dir = temp.path();
        let agents_md = codex_dir.join("AGENTS.md");
        let ctxcrl_md = codex_dir.join(CTXCRL_MD);
        let absolute_ref = codex_ctxcrl_md_ref(codex_dir);

        fs::write(&agents_md, format!("# Team rules\n\n{}\n", absolute_ref)).unwrap();
        fs::write(&ctxcrl_md, "codex config").unwrap();

        let removed = uninstall_codex_at(codex_dir, InitContext::default()).unwrap();

        assert_eq!(removed.len(), 2);
        let content = fs::read_to_string(&agents_md).unwrap();
        assert!(!content.contains(&absolute_ref));
        assert!(content.contains("# Team rules"));
    }

    #[test]
    fn test_write_if_changed_dry_run_does_not_create_file() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("rtk-test.md");

        let changed = write_if_changed(
            &target,
            "some content",
            "test file",
            InitContext {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(
            changed,
            "dry-run should report would-change for missing file"
        );
        assert!(
            !target.exists(),
            "dry-run must not create file: {}",
            target.display()
        );
    }

    #[test]
    fn test_write_if_changed_dry_run_does_not_modify_existing_file() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("rtk-test.md");
        fs::write(&target, "original").unwrap();

        let changed = write_if_changed(
            &target,
            "new content",
            "test file",
            InitContext {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(changed, "dry-run should report would-change");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "original",
            "dry-run must not modify file contents"
        );
    }

    #[test]
    fn test_run_codex_mode_dry_run_writes_nothing() {
        let temp = TempDir::new().unwrap();
        let agents_md = temp.path().join("AGENTS.md");
        let ctxcrl_md = temp.path().join("CONTEXTCRAWLER.md");

        run_codex_mode_with_paths(
            agents_md.clone(),
            ctxcrl_md.clone(),
            true,
            InitContext {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(
            !ctxcrl_md.exists(),
            "dry-run must not create CONTEXTCRAWLER.md: {}",
            ctxcrl_md.display()
        );
        assert!(
            !agents_md.exists(),
            "dry-run must not create AGENTS.md: {}",
            agents_md.display()
        );
    }

    #[test]
    fn test_uninstall_codex_at_removes_rtk_instructions_block() {
        let temp = TempDir::new().unwrap();
        let codex_dir = temp.path();
        let agents_md = codex_dir.join("AGENTS.md");
        let ctxcrl_md = codex_dir.join("CONTEXTCRAWLER.md");

        fs::write(
            &agents_md,
            format!(
                "# Team rules\n\n{} v2 -->\nOLD CTXCRL STUFF\n{}\n\nMore content",
                CTXCRL_BLOCK_START, CTXCRL_BLOCK_END
            ),
        )
        .unwrap();
        fs::write(&ctxcrl_md, "codex config").unwrap();

        let removed = uninstall_codex_at(codex_dir, InitContext::default()).unwrap();

        let content = fs::read_to_string(&agents_md).unwrap();
        assert!(!content.contains("OLD CTXCRL STUFF"));
        assert!(content.contains("# Team rules"));
        assert!(content.contains("More content"));
        assert!(removed.iter().any(|r| r.contains("ctxcrl-instructions block")));
    }

    #[test]
    fn test_uninstall_codex_at_patches_agents_md_before_deleting_files() {
        // REGRESSION (issue #26). The previous order was delete-then-patch:
        // if the AGENTS.md patch failed (filesystem full, permission flip,
        // signal during write), the user was left with CONTEXTCRAWLER.md
        // gone but AGENTS.md still importing it → Codex warned on every
        // load AND re-running uninstall failed (delete of missing file).
        //
        // The fix collapses BOTH AGENTS.md mutations into one atomic_write,
        // then deletes files only after the patch succeeds. This test pins
        // the success-path behaviour AND the ordering invariant: it loads
        // a fixture where AGENTS.md has both a block AND a separate @-ref
        // line, runs uninstall, and asserts:
        //   1. AGENTS.md ends up clean (both mutations applied)
        //   2. CONTEXTCRAWLER.md was deleted
        //   3. The `removed` list contains entries for both AGENTS.md
        //      mutations + the file deletion
        let temp = TempDir::new().unwrap();
        let codex_dir = temp.path();
        let agents_md = codex_dir.join("AGENTS.md");
        let ctxcrl_md = codex_dir.join("CONTEXTCRAWLER.md");

        let fixture = format!(
            "# Team rules\n\n{} v2 -->\nOLD CTXCRL STUFF\n{}\n\n{}\n\nMore content\n",
            CTXCRL_BLOCK_START, CTXCRL_BLOCK_END, CTXCRL_MD_REF
        );
        fs::write(&agents_md, &fixture).unwrap();
        fs::write(&ctxcrl_md, "codex config").unwrap();

        let removed = uninstall_codex_at(codex_dir, InitContext::default()).unwrap();

        // 1. AGENTS.md is fully clean.
        let agents_content = fs::read_to_string(&agents_md).unwrap();
        assert!(!agents_content.contains(CTXCRL_BLOCK_START));
        assert!(!agents_content.contains("OLD CTXCRL STUFF"));
        assert!(!agents_content.contains(CTXCRL_MD_REF));
        assert!(agents_content.contains("# Team rules"));
        assert!(agents_content.contains("More content"));

        // 2. CONTEXTCRAWLER.md was deleted.
        assert!(!ctxcrl_md.exists(), "CONTEXTCRAWLER.md should be deleted");

        // 3. The removed list reports both mutations + the file.
        assert!(
            removed.iter().any(|r| r.contains("ctxcrl-instructions block")),
            "missing block-removal entry: {:?}",
            removed
        );
        assert!(
            removed.iter().any(|r| r.contains("@CONTEXTCRAWLER.md reference")),
            "missing @-ref removal entry: {:?}",
            removed
        );
        assert!(
            removed.iter().any(|r| r.contains("CONTEXTCRAWLER.md:")),
            "missing file deletion entry: {:?}",
            removed
        );
    }

    #[test]
    fn test_local_init_unchanged() {
        // Local init should use claude-md mode
        let temp = TempDir::new().unwrap();
        let claude_md = temp.path().join("CLAUDE.md");

        fs::write(&claude_md, CTXCRL_INSTRUCTIONS).unwrap();
        let content = fs::read_to_string(&claude_md).unwrap();

        assert!(content.contains(CTXCRL_BLOCK_START));
    }

    // Tests for hook_already_present()
    #[test]
    fn test_hook_already_present_exact_match() {
        let json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/Users/test/.claude/hooks/rtk-rewrite.sh"
                    }]
                }]
            }
        });

        let hook_command = "/Users/test/.claude/hooks/rtk-rewrite.sh";
        assert!(hook_already_present(&json_content, hook_command));
    }

    #[test]
    fn test_hook_already_present_different_path() {
        let json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/home/user/.claude/hooks/rtk-rewrite.sh"
                    }]
                }]
            }
        });

        let hook_command = "~/.claude/hooks/rtk-rewrite.sh";
        // Should match on rtk-rewrite.sh substring
        assert!(hook_already_present(&json_content, hook_command));
    }

    #[test]
    fn test_hook_not_present_empty() {
        let json_content = serde_json::json!({});
        let hook_command = "/Users/test/.claude/hooks/rtk-rewrite.sh";
        assert!(!hook_already_present(&json_content, hook_command));
    }

    #[test]
    fn test_hook_already_present_new_command() {
        let json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": CLAUDE_HOOK_COMMAND
                    }]
                }]
            }
        });

        assert!(hook_already_present(&json_content, CLAUDE_HOOK_COMMAND));
    }

    #[test]
    fn test_hook_not_present_other_hooks() {
        let json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/some/other/hook.sh"
                    }]
                }]
            }
        });

        let hook_command = "/Users/test/.claude/hooks/rtk-rewrite.sh";
        assert!(!hook_already_present(&json_content, hook_command));
    }

    // Tests for insert_hook_entry()
    #[test]
    fn test_insert_hook_entry_empty_root() {
        let mut json_content = serde_json::json!({});
        let hook_command = "/Users/test/.claude/hooks/rtk-rewrite.sh";

        insert_hook_entry(&mut json_content, hook_command).unwrap();

        // Should create full structure
        assert!(json_content.get("hooks").is_some());
        assert!(json_content
            .get("hooks")
            .unwrap()
            .get("PreToolUse")
            .is_some());

        let pre_tool_use = json_content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool_use.len(), 1);

        let command = pre_tool_use[0]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(command, hook_command);
    }

    #[test]
    fn test_insert_hook_entry_preserves_existing() {
        let mut json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/some/other/hook.sh"
                    }]
                }]
            }
        });

        let hook_command = "/Users/test/.claude/hooks/rtk-rewrite.sh";
        insert_hook_entry(&mut json_content, hook_command).unwrap();

        let pre_tool_use = json_content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool_use.len(), 2); // Should have both hooks

        // Check first hook is preserved
        let first_command = pre_tool_use[0]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(first_command, "/some/other/hook.sh");

        // Check second hook is ContextCrawler
        let second_command = pre_tool_use[1]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(second_command, hook_command);
    }

    #[test]
    fn test_insert_hook_preserves_other_keys() {
        let mut json_content = serde_json::json!({
            "env": {"PATH": "/custom/path"},
            "permissions": {"allowAll": true},
            "model": "claude-sonnet-4"
        });

        let hook_command = "/Users/test/.claude/hooks/rtk-rewrite.sh";
        insert_hook_entry(&mut json_content, hook_command).unwrap();

        // Should preserve all other keys
        assert_eq!(json_content["env"]["PATH"], "/custom/path");
        assert_eq!(json_content["permissions"]["allowAll"], true);
        assert_eq!(json_content["model"], "claude-sonnet-4");

        // And add hooks
        assert!(json_content.get("hooks").is_some());
    }

    // Tests for atomic_write()
    #[test]
    fn test_atomic_write() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.json");

        let content = r#"{"key": "value"}"#;
        atomic_write(&file_path, content).unwrap();

        assert!(file_path.exists());
        let written = fs::read_to_string(&file_path).unwrap();
        assert_eq!(written, content);
    }

    // Writing through an absolute symlink must preserve the link and update the
    // real file behind it — not clobber the symlink with a regular file.
    // (Guards hoff-profile's managed-block symlinked settings.)
    #[cfg(unix)]
    #[test]
    fn test_atomic_write_preserves_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let target_path = temp.path().join("real-settings.json");
        let link_path = temp.path().join("settings.json");

        fs::write(&target_path, "{}").expect("seed target file");
        symlink(&target_path, &link_path).expect("create symlink");

        atomic_write(&link_path, "{\"hooks\":{}}").unwrap();

        let meta = fs::symlink_metadata(&link_path).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must survive");
        let written = fs::read_to_string(&target_path).unwrap();
        assert_eq!(written, "{\"hooks\":{}}");
    }

    // Same guarantee for a relative symlink — canonicalize resolves the
    // relative target before the rename lands.
    #[cfg(unix)]
    #[test]
    fn test_atomic_write_preserves_relative_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let subdir = temp.path().join("real");
        fs::create_dir(&subdir).unwrap();
        let target_path = subdir.join("settings.json");
        let link_path = temp.path().join("settings.json");

        fs::write(&target_path, "{}").expect("seed target file");
        symlink(Path::new("real/settings.json"), &link_path).expect("create relative symlink");

        atomic_write(&link_path, "{\"patched\":true}").unwrap();

        let meta = fs::symlink_metadata(&link_path).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must survive");
        let written = fs::read_to_string(&target_path).unwrap();
        assert_eq!(written, "{\"patched\":true}");
    }

    // Test for preserve_order round-trip
    #[test]
    fn test_preserve_order_round_trip() {
        let original = r#"{"env": {"PATH": "/usr/bin"}, "permissions": {"allowAll": true}, "model": "claude-sonnet-4"}"#;
        let parsed: serde_json::Value = serde_json::from_str(original).unwrap();
        let serialized = serde_json::to_string(&parsed).unwrap();

        // Keys should appear in same order
        let _original_keys: Vec<&str> = original.split("\"").filter(|s| s.contains(":")).collect();
        let _serialized_keys: Vec<&str> =
            serialized.split("\"").filter(|s| s.contains(":")).collect();

        // Just check that keys exist (preserve_order doesn't guarantee exact order in nested objects)
        assert!(serialized.contains("\"env\""));
        assert!(serialized.contains("\"permissions\""));
        assert!(serialized.contains("\"model\""));
    }

    // Tests for clean_double_blanks()
    #[test]
    fn test_clean_double_blanks() {
        // Input: line1, 2 blank lines, line2, 1 blank line, line3, 3 blank lines, line4
        // Expected: line1, 2 blank lines (kept), line2, 1 blank line, line3, 2 blank lines (max), line4
        let input = "line1\n\n\nline2\n\nline3\n\n\n\nline4";
        // That's: line1 \n \n \n line2 \n \n line3 \n \n \n \n line4
        // Which is: line1, blank, blank, line2, blank, line3, blank, blank, blank, line4
        // So 2 blanks after line1 (keep both), 1 blank after line2 (keep), 3 blanks after line3 (keep 2)
        let expected = "line1\n\n\nline2\n\nline3\n\n\nline4";
        assert_eq!(clean_double_blanks(input), expected);
    }

    #[test]
    fn test_clean_double_blanks_preserves_single() {
        let input = "line1\n\nline2\n\nline3";
        assert_eq!(clean_double_blanks(input), input); // No change
    }

    // Tests for remove_hook_from_settings()
    #[test]
    fn test_remove_hook_from_json() {
        let mut json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "/some/other/hook.sh"
                        }]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "/Users/test/.claude/hooks/rtk-rewrite.sh"
                        }]
                    }
                ]
            }
        });

        let removed = remove_hook_from_json(&mut json_content);
        assert!(removed);

        // Should have only one hook left
        let pre_tool_use = json_content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool_use.len(), 1);

        // Check it's the other hook
        let command = pre_tool_use[0]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(command, "/some/other/hook.sh");
    }

    #[test]
    fn test_remove_hook_from_json_new_command() {
        let mut json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "/some/other/hook.sh"
                        }]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": CLAUDE_HOOK_COMMAND
                        }]
                    }
                ]
            }
        });

        let removed = remove_hook_from_json(&mut json_content);
        assert!(removed);

        let pre_tool_use = json_content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool_use.len(), 1);
        assert_eq!(
            pre_tool_use[0]["hooks"][0]["command"].as_str().unwrap(),
            "/some/other/hook.sh"
        );
    }

    #[test]
    fn test_remove_hook_when_not_present() {
        let mut json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/some/other/hook.sh"
                    }]
                }]
            }
        });

        let removed = remove_hook_from_json(&mut json_content);
        assert!(!removed);
    }

    // ─── #100 G2 IMPORTANT 6: precise legacy hook match ───

    #[test]
    fn test_command_is_legacy_rewrite_hook_matches_real_entry() {
        // The real installed legacy entry is a path to the script.
        assert!(command_is_legacy_rewrite_hook(
            "/home/user/.claude/hooks/rtk-rewrite.sh"
        ));
        assert!(command_is_legacy_rewrite_hook("rtk-rewrite.sh"));
        assert!(command_is_legacy_rewrite_hook(
            "\"/home/u/.claude/hooks/rtk-rewrite.sh\""
        ));
    }

    #[test]
    fn test_command_is_legacy_rewrite_hook_ignores_mere_mentions() {
        // An unrelated hook that merely MENTIONS the filename must NOT be
        // matched — the old `contains()` substring check deleted these.
        assert!(!command_is_legacy_rewrite_hook(
            "echo 'see rtk-rewrite.sh for details'"
        ));
        assert!(!command_is_legacy_rewrite_hook(
            "my-tool --note rtk-rewrite.sh-backup"
        ));
        assert!(!command_is_legacy_rewrite_hook("contextcrawler hook claude"));
    }

    #[test]
    fn test_remove_hook_preserves_unrelated_hook_mentioning_filename() {
        let mut json_content = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "echo rtk-rewrite.sh is great"
                    }]
                }]
            }
        });
        let removed = remove_hook_from_json(&mut json_content);
        assert!(
            !removed,
            "a hook merely mentioning rtk-rewrite.sh must not be deleted"
        );
    }

    // ─── Cursor hooks.json tests ───

    #[test]
    fn test_cursor_hook_already_present_legacy_script() {
        let json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "command": "./hooks/rtk-rewrite.sh",
                    "matcher": "Shell"
                }]
            }
        });
        assert!(cursor_hook_already_present(&json_content));
    }

    #[test]
    fn test_cursor_hook_already_present_new_command() {
        let json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "command": CURSOR_HOOK_COMMAND,
                    "matcher": "Shell"
                }]
            }
        });
        assert!(cursor_hook_already_present(&json_content));
    }

    #[test]
    fn test_cursor_hook_already_present_false_empty() {
        let json_content = serde_json::json!({ "version": 1 });
        assert!(!cursor_hook_already_present(&json_content));
    }

    #[test]
    fn test_cursor_hook_already_present_false_other_hooks() {
        let json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "command": "./hooks/some-other-hook.sh",
                    "matcher": "Shell"
                }]
            }
        });
        assert!(!cursor_hook_already_present(&json_content));
    }

    #[test]
    fn test_insert_cursor_hook_entry_empty() {
        let mut json_content = serde_json::json!({ "version": 1 });
        insert_cursor_hook_entry(&mut json_content).unwrap();

        let hooks = json_content["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["command"], CURSOR_HOOK_COMMAND);
        assert_eq!(hooks[0]["matcher"], "Shell");
        assert_eq!(json_content["version"], 1);
    }

    #[test]
    fn test_insert_cursor_hook_preserves_existing() {
        let mut json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "command": "./hooks/other.sh",
                    "matcher": "Shell"
                }],
                "afterFileEdit": [{
                    "command": "./hooks/format.sh"
                }]
            }
        });

        insert_cursor_hook_entry(&mut json_content).unwrap();

        let pre_tool_use = json_content["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(pre_tool_use.len(), 2);
        assert_eq!(pre_tool_use[0]["command"], "./hooks/other.sh");
        assert_eq!(pre_tool_use[1]["command"], CURSOR_HOOK_COMMAND);

        // afterFileEdit should be preserved
        assert!(json_content["hooks"]["afterFileEdit"].is_array());
    }

    #[test]
    fn test_remove_cursor_hook_from_json() {
        let mut json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    { "command": "./hooks/other.sh", "matcher": "Shell" },
                    { "command": "./hooks/rtk-rewrite.sh", "matcher": "Shell" }
                ]
            }
        });

        let removed = remove_cursor_hook_from_json(&mut json_content);
        assert!(removed);

        let hooks = json_content["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["command"], "./hooks/other.sh");
    }

    #[test]
    fn test_remove_cursor_hook_from_json_new_command() {
        let mut json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    { "command": "./hooks/other.sh", "matcher": "Shell" },
                    { "command": CURSOR_HOOK_COMMAND, "matcher": "Shell" }
                ]
            }
        });

        let removed = remove_cursor_hook_from_json(&mut json_content);
        assert!(removed);

        let hooks = json_content["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["command"], "./hooks/other.sh");
    }

    #[test]
    fn test_remove_cursor_hook_not_present() {
        let mut json_content = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    { "command": "./hooks/other.sh", "matcher": "Shell" }
                ]
            }
        });

        let removed = remove_cursor_hook_from_json(&mut json_content);
        assert!(!removed);
    }

    // ─── Legacy migration tests ──────────────────────────────────────

    #[test]
    fn test_remove_legacy_hook_entries_strips_old_script() {
        let mut root = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/home/user/.claude/hooks/rtk-rewrite.sh"
                    }]
                }]
            }
        });

        assert!(remove_legacy_hook_entries_from_json(&mut root));
        let arr = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn test_remove_legacy_hook_entries_preserves_new_command() {
        let mut root = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "/home/user/.claude/hooks/rtk-rewrite.sh"
                        }]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": CLAUDE_HOOK_COMMAND
                        }]
                    }
                ]
            }
        });

        assert!(remove_legacy_hook_entries_from_json(&mut root));
        let arr = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let cmd = arr[0]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(cmd, CLAUDE_HOOK_COMMAND);
    }

    #[test]
    fn test_remove_legacy_hook_entries_noop_when_no_legacy() {
        let mut root = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": CLAUDE_HOOK_COMMAND
                    }]
                }]
            }
        });

        assert!(!remove_legacy_hook_entries_from_json(&mut root));
        let arr = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn test_remove_legacy_hook_entries_preserves_third_party_hooks() {
        let mut root = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "/home/user/.claude/hooks/rtk-rewrite.sh"
                        }]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "some-other-tool --hook"
                        }]
                    }
                ]
            }
        });

        assert!(remove_legacy_hook_entries_from_json(&mut root));
        let arr = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let cmd = arr[0]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(cmd, "some-other-tool --hook");
    }

    #[test]
    fn test_remove_legacy_cursor_entries_strips_old_script() {
        let mut root = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "command": "./hooks/rtk-rewrite.sh",
                    "matcher": "Shell"
                }]
            }
        });

        assert!(remove_legacy_cursor_hook_entries_from_json(&mut root));
        let arr = root["hooks"]["preToolUse"].as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn test_remove_legacy_cursor_entries_preserves_new_command() {
        let mut root = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {
                        "command": "./hooks/rtk-rewrite.sh",
                        "matcher": "Shell"
                    },
                    {
                        "command": CURSOR_HOOK_COMMAND,
                        "matcher": "Shell"
                    }
                ]
            }
        });

        assert!(remove_legacy_cursor_hook_entries_from_json(&mut root));
        let arr = root["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"].as_str().unwrap(), CURSOR_HOOK_COMMAND);
    }

    use std::sync::Mutex;
    static CLAUDE_DIR_LOCK: Mutex<()> = Mutex::new(());

    fn with_claude_dir_override<F: FnOnce(&Path)>(tmp: &TempDir, f: F) {
        let _guard = CLAUDE_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let claude_dir = tmp.path().join(CLAUDE_DIR);
        fs::create_dir_all(&claude_dir).unwrap();

        let orig = std::env::var_os("RTK_CLAUDE_DIR");
        // Tests point RTK_CLAUDE_DIR at a tempdir outside $HOME; opt in to
        // the non-home root so `validate_env_root` (#100 G2 IMPORTANT 5)
        // doesn't reject it.
        let orig_allow = std::env::var_os(ALLOW_NONHOME_ROOT_ENV);
        std::env::set_var(ALLOW_NONHOME_ROOT_ENV, "1");
        std::env::set_var("RTK_CLAUDE_DIR", &claude_dir);
        f(&claude_dir);
        match orig {
            Some(v) => std::env::set_var("RTK_CLAUDE_DIR", v),
            None => std::env::remove_var("RTK_CLAUDE_DIR"),
        }
        match orig_allow {
            Some(v) => std::env::set_var(ALLOW_NONHOME_ROOT_ENV, v),
            None => std::env::remove_var(ALLOW_NONHOME_ROOT_ENV),
        }
    }

    #[test]
    fn test_global_default_mode_creates_artifacts() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            run_default_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();

            assert!(claude_dir.join(CTXCRL_MD).exists(), "CONTEXTCRAWLER.md must be created");
            assert!(
                claude_dir.join(CLAUDE_MD).exists(),
                "CLAUDE.md must be created"
            );

            let settings = claude_dir.join(SETTINGS_JSON);
            assert!(settings.exists(), "settings.json must be created");
            let content = fs::read_to_string(&settings).unwrap();
            assert!(
                content.contains(CLAUDE_HOOK_COMMAND),
                "settings.json must contain hook command"
            );
        });
    }

    #[test]
    fn test_global_uninstall_removes_artifacts() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            run_default_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();
            uninstall(true, false, false, false, InitContext::default()).unwrap();

            assert!(!claude_dir.join(CTXCRL_MD).exists(), "CONTEXTCRAWLER.md must be removed");
            let settings_content =
                fs::read_to_string(claude_dir.join(SETTINGS_JSON)).unwrap_or_default();
            assert!(
                !settings_content.contains(CLAUDE_HOOK_COMMAND),
                "hook entry must be removed from settings.json"
            );
        });
    }

    #[test]
    fn test_global_default_mode_idempotent() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            run_default_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();
            run_default_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();

            let settings = fs::read_to_string(claude_dir.join(SETTINGS_JSON)).unwrap();
            let count = settings.matches(CLAUDE_HOOK_COMMAND).count();
            assert_eq!(count, 1, "hook command must appear exactly once");
        });
    }

    #[test]
    fn test_upgrade_from_claude_md_to_hook_mode() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            run_claude_md_mode(true, false, InitContext::default()).unwrap();
            let claude_md_content = fs::read_to_string(claude_dir.join(CLAUDE_MD)).unwrap();
            assert!(
                claude_md_content.contains(CTXCRL_BLOCK_START),
                "pre-condition: old block must exist"
            );

            run_default_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();

            assert!(claude_dir.join(CTXCRL_MD).exists(), "CONTEXTCRAWLER.md must be created");
            let settings = fs::read_to_string(claude_dir.join(SETTINGS_JSON)).unwrap();
            assert!(
                settings.contains(CLAUDE_HOOK_COMMAND),
                "hook must be in settings.json after upgrade"
            );
        });
    }

    #[test]
    fn test_local_init_no_hook() {
        let tmp = TempDir::new().unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let result = run_default_mode(false, PatchMode::Auto, false, InitContext::default());
        std::env::set_current_dir(&cwd).unwrap();

        result.unwrap();
        assert!(
            tmp.path().join(CLAUDE_MD).exists(),
            "local CLAUDE.md must be created"
        );
        assert!(
            !tmp.path().join(SETTINGS_JSON).exists(),
            "settings.json must not be created for local init"
        );
    }

    #[test]
    fn test_global_hook_only_mode_creates_settings() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            run_hook_only_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();

            assert!(
                !claude_dir.join(CTXCRL_MD).exists(),
                "CONTEXTCRAWLER.md must NOT be created in hook-only mode"
            );
            let settings = fs::read_to_string(claude_dir.join(SETTINGS_JSON)).unwrap();
            assert!(
                settings.contains(CLAUDE_HOOK_COMMAND),
                "settings.json must contain hook command"
            );
        });
    }

    #[test]
    fn test_run_default_mode_dry_run_writes_nothing() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            let dry = InitContext {
                dry_run: true,
                ..Default::default()
            };
            run_default_mode(true, PatchMode::Auto, false, dry).unwrap();

            assert!(
                !claude_dir.join(CTXCRL_MD).exists(),
                "dry-run must not create CONTEXTCRAWLER.md"
            );
            assert!(
                !claude_dir.join(CLAUDE_MD).exists(),
                "dry-run must not create CLAUDE.md"
            );
            assert!(
                !claude_dir.join(SETTINGS_JSON).exists(),
                "dry-run must not create settings.json"
            );
        });
    }

    #[test]
    fn test_uninstall_dry_run_preserves_artifacts() {
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            // Stage a real install first
            run_default_mode(true, PatchMode::Auto, false, InitContext::default()).unwrap();
            assert!(claude_dir.join(CTXCRL_MD).exists());
            assert!(claude_dir.join(SETTINGS_JSON).exists());

            let settings_before = fs::read_to_string(claude_dir.join(SETTINGS_JSON)).unwrap();
            let ctxcrl_md_before = fs::read_to_string(claude_dir.join(CTXCRL_MD)).unwrap();

            // Dry-run uninstall
            let dry = InitContext {
                dry_run: true,
                ..Default::default()
            };
            uninstall(true, false, false, false, dry).unwrap();

            // Files must still exist with identical content
            assert!(
                claude_dir.join(CTXCRL_MD).exists(),
                "dry-run uninstall must not remove CONTEXTCRAWLER.md"
            );
            assert!(
                claude_dir.join(SETTINGS_JSON).exists(),
                "dry-run uninstall must not remove settings.json"
            );
            assert_eq!(
                fs::read_to_string(claude_dir.join(CTXCRL_MD)).unwrap(),
                ctxcrl_md_before,
                "dry-run uninstall must not modify CONTEXTCRAWLER.md"
            );
            assert_eq!(
                fs::read_to_string(claude_dir.join(SETTINGS_JSON)).unwrap(),
                settings_before,
                "dry-run uninstall must not modify settings.json"
            );
        });
    }

    #[test]
    fn test_uninstall_removes_rtk_instructions_block() {
        let temp = TempDir::new().unwrap();
        let claude_md = temp.path().join("CLAUDE.md");

        fs::write(&claude_md, CTXCRL_INSTRUCTIONS).unwrap();
        assert!(claude_md.exists());

        let content = fs::read_to_string(&claude_md).unwrap();
        assert!(content.contains(CTXCRL_BLOCK_START));

        let (cleaned, did_remove) = remove_ctxcrl_block(&content);
        assert!(did_remove);
        assert!(!cleaned.contains(CTXCRL_BLOCK_START));
        assert!(!cleaned.contains("contextcrawler cargo test"));
    }

    #[test]
    fn test_uninstall_preserves_non_rtk_content() {
        let content = format!(
            "# My Project\n\nSome custom instructions.\n\n{}\n\n## Other Notes\n\nKeep this.",
            CTXCRL_INSTRUCTIONS
        );

        let (cleaned, did_remove) = remove_ctxcrl_block(&content);

        assert!(did_remove);
        assert!(cleaned.contains("# My Project"));
        assert!(cleaned.contains("Some custom instructions."));
        assert!(cleaned.contains("## Other Notes"));
        assert!(cleaned.contains("Keep this."));
        assert!(!cleaned.contains(CTXCRL_BLOCK_START));
    }

    #[test]
    fn test_uninstall_handles_both_artifacts() {
        let content = format!("# Config\n\n@CONTEXTCRAWLER.md\n\n{}\n\nMore stuff", CTXCRL_INSTRUCTIONS);

        let after_at_removal: String = content
            .lines()
            .filter(|line| !line.trim().starts_with("@CONTEXTCRAWLER.md"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!after_at_removal.contains("@CONTEXTCRAWLER.md"));
        assert!(after_at_removal.contains(CTXCRL_BLOCK_START));

        let (final_content, did_remove) = remove_ctxcrl_block(&after_at_removal);
        assert!(did_remove);
        assert!(!final_content.contains(CTXCRL_BLOCK_START));
        assert!(final_content.contains("# Config"));
        assert!(final_content.contains("More stuff"));
    }

    #[test]
    fn test_uninstall_integration_claude_md_only() {
        let (cleaned, did_remove) = remove_ctxcrl_block(CTXCRL_INSTRUCTIONS);
        assert!(did_remove, "remove_ctxcrl_block must succeed for valid block");
        assert!(
            cleaned.trim().is_empty(),
            "CLAUDE.md with only CTXCRL content should be empty after removal"
        );
    }

    #[test]
    fn test_uninstall_integration_preserves_user_content() {
        let user_content = "# My Project Rules\n\nAlways use snake_case.";
        let installed = format!("{}\n\n{}", user_content, CTXCRL_INSTRUCTIONS);

        let (cleaned, did_remove) = remove_ctxcrl_block(&installed);
        assert!(did_remove);
        assert!(!cleaned.trim().is_empty(), "user content should remain");
        assert!(
            cleaned.contains("My Project Rules"),
            "user content must be preserved"
        );
        assert!(
            cleaned.contains("snake_case"),
            "user content must be preserved"
        );
        assert!(
            !cleaned.contains(CTXCRL_BLOCK_START),
            "CTXCRL block must be fully removed"
        );
        assert!(
            !cleaned.contains(CTXCRL_BLOCK_END),
            "CTXCRL end marker must be removed"
        );
    }

    // --- copilot-instructions.md preservation (port of upstream d108165) ---

    #[test]
    fn test_copilot_init_preserves_existing_instructions() {
        // Regression: run_copilot previously truncated a pre-existing
        // user-authored copilot-instructions.md via write_if_changed.
        let temp = TempDir::new().unwrap();
        let github_dir = temp.path().join(".github");
        fs::create_dir_all(&github_dir).unwrap();

        let instructions_path = github_dir.join("copilot-instructions.md");
        let user_content = "# My Copilot Instructions\n\n\
            Always respond in Spanish.\n\
            Never suggest npm; prefer pnpm.\n";
        fs::write(&instructions_path, user_content).unwrap();

        run_copilot_at(temp.path(), InitContext::default()).unwrap();

        let final_content = fs::read_to_string(&instructions_path).unwrap();

        assert!(
            final_content.contains("Always respond in Spanish."),
            "User custom rule was destroyed. Got: {final_content}"
        );
        assert!(
            final_content.contains("Never suggest npm; prefer pnpm."),
            "User custom rule was destroyed. Got: {final_content}"
        );
        assert!(
            final_content.contains(CTXCRL_BLOCK_START),
            "CTXCRL block start marker missing"
        );
        assert!(
            final_content.contains(CTXCRL_BLOCK_END),
            "CTXCRL block end marker missing"
        );
    }

    #[test]
    fn test_copilot_init_idempotent_repeats() {
        let temp = TempDir::new().unwrap();
        let github_dir = temp.path().join(".github");
        fs::create_dir_all(&github_dir).unwrap();

        run_copilot_at(temp.path(), InitContext::default()).unwrap();
        let after_first = fs::read_to_string(github_dir.join("copilot-instructions.md")).unwrap();

        run_copilot_at(temp.path(), InitContext::default()).unwrap();
        let after_second = fs::read_to_string(github_dir.join("copilot-instructions.md")).unwrap();

        assert_eq!(
            after_first, after_second,
            "Second init must be a no-op (idempotent)"
        );

        let count_start = after_first.matches(CTXCRL_BLOCK_START).count();
        let count_end = after_first.matches(CTXCRL_BLOCK_END).count();
        assert_eq!(
            count_start, 1,
            "CTXCRL_BLOCK_START must appear once, got {count_start}"
        );
        assert_eq!(count_end, 1, "CTXCRL_BLOCK_END must appear once, got {count_end}");
    }

    #[test]
    fn test_copilot_init_updates_stale_block() {
        let temp = TempDir::new().unwrap();
        let github_dir = temp.path().join(".github");
        fs::create_dir_all(&github_dir).unwrap();

        let instructions_path = github_dir.join("copilot-instructions.md");
        let stale = format!(
            "# Project rules\n\nUse rg.\n\n{} v2 -->\n# OLD CTXCRL CONTENT\nctxcrl foo\n{}\n",
            CTXCRL_BLOCK_START, CTXCRL_BLOCK_END
        );
        fs::write(&instructions_path, &stale).unwrap();

        run_copilot_at(temp.path(), InitContext::default()).unwrap();

        let updated = fs::read_to_string(&instructions_path).unwrap();

        assert!(
            updated.contains("Use rg."),
            "User content outside the block must be preserved"
        );
        assert!(
            !updated.contains("# OLD CTXCRL CONTENT"),
            "Stale CTXCRL block content must be removed"
        );
        assert!(
            updated.contains("contextcrawler gain"),
            "Fresh COPILOT_INSTRUCTIONS content must be present"
        );
    }

    #[test]
    fn test_copilot_init_dry_run_no_write() {
        let temp = TempDir::new().unwrap();
        let github_dir = temp.path().join(".github");
        fs::create_dir_all(&github_dir).unwrap();

        let instructions_path = github_dir.join("copilot-instructions.md");
        assert!(!instructions_path.exists());

        let ctx = InitContext {
            dry_run: true,
            ..InitContext::default()
        };
        run_copilot_at(temp.path(), ctx).unwrap();

        assert!(
            !instructions_path.exists(),
            "Dry-run must not create copilot-instructions.md"
        );
    }

    #[test]
    fn test_copilot_init_fresh_install_creates_file() {
        let temp = TempDir::new().unwrap();
        let instructions_path = temp.path().join(".github").join("copilot-instructions.md");
        assert!(!instructions_path.exists());

        run_copilot_at(temp.path(), InitContext::default()).unwrap();

        assert!(
            instructions_path.exists(),
            "Fresh install must create copilot-instructions.md"
        );
        let content = fs::read_to_string(&instructions_path).unwrap();
        assert!(content.contains(CTXCRL_BLOCK_START), "marker block missing");
        assert!(content.contains(CTXCRL_BLOCK_END), "end marker missing");
    }

    #[test]
    fn test_copilot_init_refuses_malformed_block() {
        let temp = TempDir::new().unwrap();
        let github_dir = temp.path().join(".github");
        fs::create_dir_all(&github_dir).unwrap();

        let instructions_path = github_dir.join("copilot-instructions.md");
        let malformed = format!("# My rules\n\n{}\nincomplete CTXCRL block\n", CTXCRL_BLOCK_START);
        fs::write(&instructions_path, &malformed).unwrap();

        let result = run_copilot_at(temp.path(), InitContext::default());

        assert!(
            result.is_err(),
            "Malformed file must cause a hard error, not a silent rewrite"
        );
        let after = fs::read_to_string(&instructions_path).unwrap();
        assert_eq!(after, malformed, "Malformed file must not be modified");
    }

    #[test]
    fn test_copilot_init_malformed_leaves_no_hook_on_disk() {
        // The upsert runs before the hook config is written, so a malformed
        // copilot-instructions.md must abort the install before any hook
        // config lands on disk.
        let temp = TempDir::new().unwrap();
        let github_dir = temp.path().join(".github");
        fs::create_dir_all(&github_dir).unwrap();

        let instructions_path = github_dir.join("copilot-instructions.md");
        let malformed = format!("# My rules\n\n{}\nincomplete CTXCRL block\n", CTXCRL_BLOCK_START);
        fs::write(&instructions_path, &malformed).unwrap();

        let hook_path = github_dir.join("hooks").join("rtk-rewrite.json");

        let result = run_copilot_at(temp.path(), InitContext::default());

        assert!(result.is_err(), "Malformed file must cause a hard error");
        assert!(
            !hook_path.exists(),
            "Hook config must not be written when the upsert aborts: {}",
            hook_path.display()
        );
    }

    #[test]
    fn test_claude_md_mode_refuses_malformed_block() {
        // Mirrors `test_copilot_init_refuses_malformed_block`: a malformed
        // CLAUDE.md previously emitted a warning and exited 0, silently
        // skipping the OpenCode plugin step. The shared `write_ctxcrl_block`
        // dispatcher now bails for both paths.
        let tmp = TempDir::new().unwrap();
        with_claude_dir_override(&tmp, |claude_dir| {
            let claude_md = claude_dir.join(CLAUDE_MD);
            let malformed = format!(
                "# Existing notes\n\n{}\nincomplete CTXCRL block\n",
                CTXCRL_BLOCK_START
            );
            fs::write(&claude_md, &malformed).unwrap();

            let result = run_claude_md_mode(true, false, InitContext::default());

            assert!(
                result.is_err(),
                "Malformed CLAUDE.md must cause a hard error, not silent skip"
            );

            let after = fs::read_to_string(&claude_md).unwrap();
            assert_eq!(after, malformed, "File must not be modified when malformed");
        });
    }
}
