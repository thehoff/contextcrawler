---
title: Command & Filter Reference
description: Every command contextcrawler intercepts, what each filter strips and keeps, and the token savings, verified against the source.
sidebar:
  order: 2
---

# Command & Filter Reference

This is the complete reference for what contextcrawler does to each command it
handles: what it filters, what it keeps, and the token savings you can expect.
The canonical list of covered commands lives in `src/discover/rules.rs`
(73 rule entries) and the per-command filter behaviour lives in `src/cmds/`.
This document is written against that source.

## How the proxy works

contextcrawler is a transparent proxy. You (or your AI assistant) run an
ordinary command, the Claude Code `PreToolUse` hook rewrites it to the
contextcrawler equivalent, contextcrawler runs the real tool, filters the
output down to what matters, and the assistant sees the compact version.

```
Assistant runs:   git status
                       |
            Hook intercepts (PreToolUse)
                       |
            contextcrawler git status     (transparent rewrite)
                       |
   Raw output: 40 lines    ->    Filtered: a few lines
                       |
            Assistant sees the compact output
```

The rewrite itself costs zero extra tokens: the hook substitutes the command
string before it runs, so there is no preamble or wrapper text added to the
context. If contextcrawler cannot improve a command, or a filter fails, it
falls back to running the command unchanged. It never blocks your command.

### The fallback contract

Three things are worth knowing up front:

- If a command is not in the rule set, it runs raw (passthrough, 0 savings).
- If a filter parser fails on unexpected input, the raw output is passed
  through unchanged rather than dropped (the "never block the user" rule).
- A piped filter (`contextcrawler pipe`) only ever sees text, never the
  command's exit code, so failure-aware behaviour like "show errors only on
  non-zero exit" is not available in pipe mode. It is available when
  contextcrawler runs the command itself.

## A note on the savings figures

Two different numbers appear in this document, and they mean different things.

- **Estimated savings** come from `estimated_savings_pct` in
  `src/discover/rules.rs`. They are planning estimates used by
  `contextcrawler discover` to rank missed opportunities. They are not
  guarantees.
- **Verified floors** come from `savings >= N` assertions in the per-command
  test modules, run against real captured fixtures. These are the honest lower
  bounds the test suite enforces.

Savings vary enormously with the input. A `git status` in a clean tree saves
almost nothing because there is almost nothing to filter; a `cargo test` run
with one failure buried in 500 lines of pass output saves over 90%. Some
filters are modest by design (AWS log tailing, `glab` release lists) because
the upstream output is already terse or is mostly irreducible data. Where that
is the case it is called out below.

## Meta commands

These are contextcrawler's own commands. Always call them through
`contextcrawler` directly (they are not rewrites of other tools).

| Command | What it does |
|---|---|
| `contextcrawler gain` | Total token savings across all recorded sessions. |
| `contextcrawler gain --history` | Recent command history with per-command savings (`-H`). |
| `contextcrawler gain --daily` / `--weekly` / `--monthly` / `--all` | Time-bucketed breakdowns. |
| `contextcrawler gain --project` | Scope stats to the current working directory. |
| `contextcrawler gain --graph` | ASCII graph of daily savings. |
| `contextcrawler gain --quota --tier <pro\|5x\|20x>` | Monthly quota savings estimate. |
| `contextcrawler gain --failures` | Commands that fell back to raw execution (`-F`). |
| `contextcrawler gain --weak-filters` | Rank tools by leaked tokens, where a better filter would help most (`-W`). |
| `contextcrawler gain --format <text\|json\|csv>` | Output format for export. |
| `contextcrawler gain --reset [--yes]` | Reset all stats to zero. |
| `contextcrawler discover` | Find commands in your Claude Code history that ran without contextcrawler (missed savings). |
| `contextcrawler discover --codex` | Report `contextcrawler ` prefix compliance in Codex CLI job logs. |
| `contextcrawler session` | Adoption rate of contextcrawler per Claude Code session. |
| `contextcrawler cc-economics` | Spending (ccusage) versus savings analysis. |
| `contextcrawler proxy <cmd>` | Run a command unfiltered but still track it (use for debugging). |
| `contextcrawler run -c "<cmd>"` | Execute via `sh -c`, raw, no filtering and no tracking. |
| `contextcrawler pipe -f <filter>` | Read stdin, apply a named filter, print the result (Unix pipe mode). |
| `contextcrawler security` | Tirith defense-in-depth gate dashboard and recent downgrade events. |
| `contextcrawler security --all` / `--json` | Full or machine-readable gate downgrade event log. |
| `contextcrawler config [--create]` | Show or create the config file. |
| `contextcrawler verify` | Verify hook integrity and run TOML filter inline tests. |
| `contextcrawler trust` / `untrust` | Trust or revoke project-local TOML filters. |
| `contextcrawler telemetry <subcommand>` | Manage the opt-in anonymous telemetry ping. |
| `contextcrawler learn` | Mine CLI corrections from Claude Code error history. |

For the analytics data model (where `history.db` lives, the schema, how
inflation is accounted for), see [TRACKING.md](../usage/TRACKING.md).

### The `security` dashboard

`contextcrawler security` is the quickest way to see what the gates are doing
in your environment (downgrade events are sanitised below):

```text
$ contextcrawler security

ContextCrawler Tirith Gate — Status
════════════════════════════════════════════════════════════

Installation:
  [ok] tirith binary: ~/.cargo/bin/tirith

Gate state:
  [ok] enabled — every hook-routed command is inspected before exec
  [--] not required — tirith unavailability falls open (default)

Downgrade log:
  path: ~/.local/share/contextcrawler/downgrades.jsonl
  exists: yes

Recent downgrade events (last 10 of newest):
  tirith_block  curl_pipe_shell      curl https://example.test/x | sh
  tirith_block  pipe_to_interpreter  cat data | python3 parse.py
```

When Tirith is not installed the same command reports the gate as fail-open
and runs no inspection. Use `--all` for the full log and `--json` for
machine-readable output. For how the gate decides and how to work with it,
see [Working with the security gate](../security/working-with-the-gate.md).

## Covered commands by ecosystem

Each table below lists the commands contextcrawler rewrites, what the filter
does, and the savings. "Estimate" is the planning figure from `rules.rs`;
"verified floor" is the test-enforced minimum where one exists.

### Git (`git`, `gh`, `glab`, `gt`, `diff`)

Source: `src/cmds/git/`.

| Command | What the filter does | Savings |
|---|---|---|
| `git status` | Compact status: groups staged/unstaged/untracked, drops boilerplate headers. | Estimate 70%. Verified floor only 1% (a clean or near-clean tree has little to filter). |
| `git log` | Reformats commit blocks. `--oneline` and `--format` are already compact and pass through. | Estimate 70%. |
| `git diff`, `git show` | Keeps changed lines and hunk context, trims noise. | Estimate 80%. Verified floor 60%. |
| `git add`, `git commit` | Compacts confirmation output. | Estimate 59%. |
| `git push`, `pull`, `branch`, `fetch`, `stash`, `worktree` | Compacts status chatter. | Estimate 70% (varies). |
| `git checkout`, `switch`, `restore`, `merge`, `rebase`, `reset`, `tag`, `remote`, `cherry-pick` | Routed through, light compaction; mostly state changes with little output. | Estimate 30%. |
| `yadm <subcommand>` | Same rule as `git` (dotfile manager wrapper). | As git. |
| `gh pr`, `gh issue`, `gh run`, `gh repo`, `gh api`, `gh release` | Extracts essentials from `gh`'s verbose JSON; strips ASCII art, badges, HTML comments from PR/issue bodies; keeps code blocks. | Estimate 82% (pr 87%, run 82%, issue 80%). Verified floor 30% on the markdown-body filter alone. |
| `glab mr`, `glab issue`, `glab ci`, `glab pipeline`, `glab api`, `glab release` | GitLab equivalent of the `gh` filter, adapted to glab JSON field names. | Estimate 82% (mr 87%). Verified floors: MR list 60%, issue list 60%, CI trace 30%, release list/view 20% (release output is mostly irreducible data). |
| `gt <subcommand>` | Graphite stacking CLI: compacts log/submit/sync/create/restack output. | Estimate 70%. Verified floor 60%. |
| `diff <file1> <file2>` | Ultra-condensed diff: only changed lines, no surrounding context. | Estimate 60%. |

Example (`gh pr view`, illustrative):

```
Before:  ~80 lines of boxed metadata, badges, HTML comments, full body
After:   title, state, author, branch, a clean body, review status
```

### Rust (`cargo`, `err`, `test`)

Source: `src/cmds/rust/`.

| Command | What the filter does | Savings |
|---|---|---|
| `cargo build` | Shows errors and warnings; drops `Compiling`/`Finished` progress. ANSI stripped (forced colour cannot fool failure detection). | Estimate 80%. |
| `cargo test` | Shows only failures plus the summary line. | Estimate 90%. |
| `cargo check` | Errors and warnings only. | Estimate 80%. |
| `cargo clippy` | Lint findings only. | Estimate 80%. |
| `cargo install` | Compacts install progress. | Estimate 80%. |
| `cargo fmt` | Passthrough (status `Passthrough`): formatting output is not filtered. | n/a |
| `contextcrawler err <cmd>` | Runs an arbitrary command and captures only stderr / errors. Argv-mode by default; `--shell` opts into `sh -c`. | varies |
| `contextcrawler test <cmd>` | Runs a test command and shows only failures. `--shell` as above. | varies |

A rustup toolchain selector (`cargo +nightly test`) is tolerated: it is
stripped for classification and re-attached when the real command runs.

Example (`cargo test`, illustrative):

```
Before:  500 lines, 199 passing dots, 1 failure, summary
After:   the 1 failure with its assertion + the summary line  (>90% saved)
```

### JavaScript / TypeScript (`npm`, `pnpm`, `npx`, `tsc`, `lint`, `prettier`, `jest`, `vitest`, `playwright`, `prisma`, `next`)

Source: `src/cmds/js/`. Each of these also matches when run through a package
runner (`npx`, `pnpm exec`, `npm run`, `pnpm dlx`, and the common typo forms
`npm rum`/`npm urn`).

| Command | What the filter does | Savings (estimate) |
|---|---|---|
| `npm run <script>` | Strips npm boilerplate; auto-injects `run` where appropriate. | 70% |
| `npm exec`, `npx <tool>` | Routes to the specialised filter for the wrapped tool (tsc, eslint, prisma, etc.). | 70% |
| `pnpm install`, `list`, `ls`, `outdated`, `run`, `exec` | Compacts dependency trees, install logs, outdated tables. | 80% |
| `tsc` | Groups TypeScript errors by file and error code. | 83% |
| `eslint`, `biome`, `lint` | Groups violations by rule. | 84% |
| `prettier` | Shows only the files that need formatting. | 70% |
| `jest` | Shows only failures. | 99% |
| `vitest` | Shows only failures. | 99% |
| `playwright` | Shows only failures. | 94% |
| `prisma` | Strips ASCII art and verbose decoration. | 88% |
| `next build` | Reduces to route metrics and bundle sizes. | 87% |

The very high jest/vitest figures reflect the all-pass case: a full suite that
prints one line per passing test collapses to a single summary line.

### Python (`ruff`, `pytest`, `mypy`, `pip`/`uv pip`)

Source: `src/cmds/python/`. `pytest` and `mypy` also match the
`python -m <tool>` / `python3 -m <tool>` forms.

| Command | What the filter does | Savings |
|---|---|---|
| `ruff check` | Lint findings only. | Estimate 80%. |
| `ruff format` | Files changed only. | Estimate 75%. |
| `pytest` | Shows only failures and the summary line. | Estimate 90%. |
| `mypy` | Groups type errors by file. | Estimate 80%. |
| `pip list`, `pip show` | Compacts package listings. | Estimate 75%. |
| `pip outdated` | Compacts the outdated table. | Estimate 80%. |
| `uv pip install`, `uv sync` | Compacts uv output. | Estimate 65%. |

### Go (`go`, `golangci-lint`)

Source: `src/cmds/go/`.

| Command | What the filter does | Savings |
|---|---|---|
| `go test` | Shows only failures. | Estimate 90%. |
| `go build` | Build errors only. | Estimate 80%. |
| `go vet` | Vet warnings only. | Estimate 75%. |
| `golangci-lint run` | Groups issues by rule. | Estimate 85%. Verified floor 60%. |

### JVM (`gradlew` / `gradle`)

Source: `src/cmds/jvm/`. Matches `./gradlew`, `gradlew`, `gradlew.bat`, and
`gradle`.

| Command | What the filter does | Savings |
|---|---|---|
| `gradlew build` | Build errors/warnings; drops task progress. | Estimate 80%. Verified floor 70%. |
| `gradlew test`, `check` | Test/check failures only. | Estimate 90% / 80%. Verified floor 60%. |
| `gradlew clean`, `assemble*`, `install*`, `lint*`, `dependencies` | Light compaction. | Estimate 75%. |

### .NET (`dotnet`)

Source: `src/cmds/dotnet/`.

| Command | What the filter does | Savings |
|---|---|---|
| `dotnet build` | Build errors and test results from CLI output. | Estimate 70%. |

The .NET module also parses MSBuild binary logs (`binlog`), `.trx` test result
XML, and `dotnet format` JSON reports into compact summaries when those
artefacts are present.

### Ruby (`rake`/`rails test`, `rspec`, `rubocop`, `bundle`)

Source: `src/cmds/ruby/`. Each matches the `bundle exec` and `bin/` prefixed
forms.

| Command | What the filter does | Savings |
|---|---|---|
| `rake test`, `rails test` | Parses Minitest output to failures/errors plus the summary. | Estimate 85% (test 90%). Verified floor 80%. |
| `rspec` | Injects `--format json`, shows only failures; falls back to a text state machine for documentation format. | Estimate 65%. Verified floors: all-pass 60%, failures 60%, text fallback 30%. |
| `rubocop` | Injects `--format json`, groups offenses by file sorted by severity; text fallback for autocorrect mode. | Estimate 65%. Verified floor 60%. |
| `bundle install`, `bundle update` | Compacts gem install output. | Estimate 70%. |

### Cloud and infrastructure (`aws`, `docker`, `kubectl`, `curl`, `wget`, `psql`)

Source: `src/cmds/cloud/`.

| Command | What the filter does | Savings |
|---|---|---|
| `aws <service> ...` | Forces JSON output (replacing verbose table/text), then compresses. Specialised filters for high-frequency services. | Estimate 80%, but highly per-service. Verified floors: EC2 60%, STS 60%, IAM 60%, security groups 60%, Lambda list 60%, CloudFormation events 40%, DynamoDB 30%, CloudWatch Logs only 15% (log lines are mostly irreducible). |
| `docker ps`, `images`, `logs`, `run`, `exec`, `build`, `compose ps\|logs\|build` | Essential fields only, compact summaries. | Estimate 85%. |
| `kubectl get`, `logs`, `describe`, `apply` | Compact summaries. | Estimate 85%. |
| `curl <url>` | Auto-detects JSON and HTML. JSON bodies and any piped/redirected (non-TTY) output pass through unchanged so downstream parsers do not break. HTML on a real terminal is extracted to readable text with a tee hint for raw recovery. | Estimate 70%. Verified floor 60% on HTML extraction. |
| `wget <url>` | Strips progress bars, shows only the result. | Estimate 65%. |
| `psql` | Detects table and expanded display formats, strips borders/padding, emits compact tab-separated or key=value output. | Estimate 75%. Verified floors: table 40%, expanded 60%. |

The cloud module also carries rules for `gcloud`, `helm`, `terraform`, `tofu`,
`ansible-playbook`, `iptables`, `fail2ban-client`, `sops`, and `liquibase`,
mostly at the conservative 60 to 70% estimate band.

### System and files (`ls`, `tree`, `read`, `grep`, `rg`, `find`, `wc`, `cat`/`head`/`tail`, `env`, `json`, `log`, `deps`, `diff`, `du`, `df`, `ps`, `systemctl`)

Source: `src/cmds/system/`.

| Command | What the filter does | Savings |
|---|---|---|
| `ls` | Compact tree-style listing. | Estimate 65%. |
| `tree` | Proxies native `tree`, auto-excludes noise directories via `-I` unless `-a` is given. | Estimate 70%. |
| `read <files>` | Reads source files with optional language-aware filtering (`--level none\|minimal\|aggressive`), `--max-lines` / `--tail-lines`, `--line-numbers`, and `--intent "<terms>"` surgical extraction (scores heading-anchored sections, returns top matches plus head/tail bookends; only for files over 5 KB with 3+ sections). | Estimate 60%. Verified floor 60% (intent path 50 to 80%). |
| `cat`, `head`, `tail` | Mapped to `contextcrawler read`. `head -3 file`, `head -n 3 file`, `head --lines N file` and the `tail` equivalents are recognised. See coverage gaps below. | Estimate 60%. |
| `grep`, `rg` | Groups matches by file instead of one line per match. | Estimate 75%. Verified floor 60%. |
| `find` | Groups files by directory. | Estimate 70%. |
| `wc` | Strips redundant paths and alignment padding (`wc file.py` -> `30L 96W 978B`). | Estimate 60%. |
| `env` | Filters environment variables, masks secrets, hides noise. `--filter <name>`, `--show-all`. | n/a (utility) |
| `json <file>` | Inspects JSON structure; `--keys-only` shows shape without values; `--depth N`. | varies, large on big payloads |
| `log [file]` | Deduplicates repeated log lines and shows counts. | varies |
| `deps [path]` | Summarises project dependencies from lock files and manifests. | n/a (utility) |
| `summary <cmd>` | Runs a command and produces a heuristic summary of its output. | varies |
| `smart <file>` | Heuristic two-line technical summary of a file, no external model. | n/a |

The conservative system utilities (`du`, `df`, `ps`, `systemctl status`, plus
build/lint tools like `make`, `shellcheck`, `yamllint`, `markdownlint`,
`hadolint`, `pre-commit`) sit at the 60 to 65% estimate band.

## Pipe mode

`contextcrawler pipe` reads stdin, applies a filter, and writes the result to
stdout. Use it when you have already captured output and want to compact it, or
in a shell pipeline. It is exit-blind (text only, no exit code) and panic-safe
(raw input passes through if a filter panics).

```bash
cargo test 2>&1 | contextcrawler pipe -f cargo-test
some-tool | contextcrawler pipe            # no -f: auto-detect the shape
```

With no `-f`, contextcrawler sniffs the first ~1 KiB to detect the output shape
(cargo test, pytest, grep, go test JSON, mypy, vitest, find, etc.) and applies
the matching filter. If nothing matches, input passes through unchanged.

The named filters accepted by `-f` (from `available_filters()` in
`src/api.rs`, kept in sync with `pipe_cmd::resolve_filter`):

| Filter name | Maps to |
|---|---|
| `cargo-test`, `cargo` | cargo test filter |
| `pytest` | pytest filter |
| `go-test` | go test filter |
| `go-build` | go build filter |
| `tsc` | TypeScript error grouping |
| `vitest` | vitest failures |
| `grep`, `rg` | grep match grouping |
| `find`, `fd` | find directory grouping |
| `git-log` | git log reformat |
| `git-diff` | git diff condense |
| `git-status` | git status compaction |
| `mypy` | mypy error grouping |
| `ruff-check` | ruff check (JSON) |
| `ruff-format` | ruff format |
| `prettier` | prettier files-changed |

The same machinery is exposed to Rust embedders as a library API:
`contextcrawler::filter_output(name, raw)`,
`auto_filter_output(raw)`, and `available_filters()`.

## Coverage gaps and honest limits

These are deliberate or known, not bugs:

- **`head -c` (byte form) passes through.** The `head`/`tail` rules match the
  line-count forms (`-3`, `-n 3`, `--lines N`) with a single file argument.
  Byte counts and multi-file invocations fall through to the native binary,
  which already handles them (multi-file `==> name <==` banners that
  `read --max-lines` cannot reproduce).
- **`cat`/`head`/`tail` with a redirect are not filtered.** A `>` or `>>` makes
  the command a write, not a read, so it is classified Unsupported and runs raw.
- **Modest-savings filters are modest for a reason.** AWS CloudWatch Logs
  (~15%), DynamoDB scans (~30%), `glab` release lists (~20%), and `git status`
  on a clean tree are mostly irreducible data. The filter still tidies them but
  cannot invent compressibility that is not there.
- **Pipe mode cannot do failure-aware filtering.** Filters that key off a
  non-zero exit code only behave that way when contextcrawler runs the command
  itself, not in `contextcrawler pipe`.
- **Passthrough is silent and counts as 0% savings.** `cargo fmt`, unknown
  subcommands, and anything not in the rule set run raw. `contextcrawler gain
  --failures` and `--weak-filters` surface where this is happening.

## See also

- [TRACKING.md](../usage/TRACKING.md) for the analytics data model and schema.
- `src/discover/rules.rs` for the authoritative rule list.
- `src/cmds/` for per-command filter implementations.
- [ARCHITECTURE.md](https://github.com/rtk-ai/rtk/blob/master/ARCHITECTURE.md)
  for system design.
