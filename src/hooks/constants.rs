pub const REWRITE_HOOK_FILE: &str = "rtk-rewrite.sh";
pub const GEMINI_HOOK_FILE: &str = "rtk-hook-gemini.sh";
pub const CLAUDE_DIR: &str = ".claude";
pub const HOOKS_SUBDIR: &str = "hooks";
pub const SETTINGS_JSON: &str = "settings.json";
pub const SETTINGS_LOCAL_JSON: &str = "settings.local.json";
pub const HOOKS_JSON: &str = "hooks.json";
pub const PRE_TOOL_USE_KEY: &str = "PreToolUse";
pub const BEFORE_TOOL_KEY: &str = "BeforeTool";

/// Native Rust hook command for Claude Code (replaces rtk-rewrite.sh).
/// ContextCrawler: binary renamed; the settings.json command must call
/// `contextcrawler hook claude`, not `rtk`, or the hook silently fails.
pub const CLAUDE_HOOK_COMMAND: &str = "contextcrawler hook claude";
/// Native Rust hook command for Cursor (replaces rtk-rewrite.sh).
pub const CURSOR_HOOK_COMMAND: &str = "contextcrawler hook cursor";

/// Legacy command string from upstream rtk / earlier ContextCrawler. The
/// init code recognises this when scanning existing settings.json entries
/// so it can replace them with [`CLAUDE_HOOK_COMMAND`].
pub const LEGACY_CLAUDE_HOOK_COMMAND: &str = "rtk hook claude";
pub const LEGACY_CURSOR_HOOK_COMMAND: &str = "rtk hook cursor";

pub const CONFIG_DIR: &str = ".config";
pub const OPENCODE_SUBDIR: &str = "opencode";
pub const PLUGIN_SUBDIR: &str = "plugins";
pub const OPENCODE_PLUGIN_FILE: &str = "rtk.ts";

pub const CURSOR_DIR: &str = ".cursor";
pub const CODEX_DIR: &str = ".codex";
pub const GEMINI_DIR: &str = ".gemini";
pub const HERMES_DIR: &str = ".hermes";
pub const HERMES_PLUGINS_SUBDIR: &str = "plugins";
pub const HERMES_PLUGIN_NAME: &str = "rtk-rewrite";
pub const HERMES_PLUGIN_INIT_FILE: &str = "__init__.py";
pub const HERMES_PLUGIN_MANIFEST_FILE: &str = "plugin.yaml";

/// Pi coding agent (pi.dev). Pi auto-loads AGENTS.md from `~/.pi/agent/`,
/// parent dirs, and cwd; extensions are TypeScript modules auto-discovered
/// from `~/.pi/agent/extensions/`.
pub const PI_DIR: &str = ".pi";
pub const PI_AGENT_SUBDIR: &str = "agent";
pub const PI_EXTENSIONS_SUBDIR: &str = "extensions";
pub const PI_EXTENSION_FILE: &str = "contextcrawler.ts";

/// Oh My Pi (OMP). The agent directory is `~/.omp/agent/`. `AGENTS.md` there
/// includes `fragments/CONTEXTCRAWLER.md`. The extension is auto-discovered
/// from `extensions/`. `RULES.md` holds the same text in a marked block so
/// the binding law and the fragment cannot drift.
pub const OMP_DIR: &str = ".omp";
pub const OMP_AGENT_SUBDIR: &str = "agent";
pub const OMP_EXTENSIONS_SUBDIR: &str = "extensions";
pub const OMP_EXTENSION_FILE: &str = "contextcrawler.ts";
pub const OMP_FRAGMENTS_SUBDIR: &str = "fragments";
pub const OMP_FRAGMENT_FILE: &str = "CONTEXTCRAWLER.md";
pub const OMP_RULES_FILE: &str = "RULES.md";
