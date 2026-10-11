# ContextCrawler — product strategy

Date: 2026-10-10
Status: current. Supersedes the unverified checkbox lists in `docs/ROADMAP.md`
(Backlog A and Backlog B). Those lists stay as history. Do not treat them as
a plan.

## What this is

ContextCrawler is a personal instrument for one operator running coding
agents. It sits on the shell path and does two jobs:

1. **Shrink** command output before it enters the model's context.
2. **Interrupt** auto-approval when a command is actually dangerous.

The user is the author, on this machine. There is no market, no hosted
service, and no second product hiding in the dashboard. A change is in
scope only when it changes tokens an agent actually receives, or a gate
decision an agent actually hits.

Speed is part of the product. If the proxy is noticeable, it gets
disabled. The existing constraint stands: no async runtime, no config
read on the hot path.

## What this is not

- Not a SaaS, not a team tool, not a Windows product, not a semver-stable
  library. The library API stays experimental.
- Not an upstream of `rtk`. Upstream is a source to harvest. The
  0.46–0.51 defect pass is the pattern: cherry-pick, review as if written
  here, stop.
- Not a control panel. `gain --web` is a loopback mirror of savings the
  CLI already computed. It is read-only, on 127.0.0.1, and it is not a
  release gate.

## The decision already made about the dashboard

`develop` carries the #162 surface only: summary, by day, weak filters,
parse failures, release boundaries, and an insights placeholder.

The security pane (#171) and the install ledger (#172) were built on
`feat/gain-web-162` and deliberately left out of the rebuild. Cost,
trust-manager, and supply-chain-manager panes (#175, #176, #177) would
turn that mirror into a place that writes config and trust. That is a
different product. Those five issues stay open and unscheduled.

Insights stays a stub until `gain --insights` exists as a CLI command.
The page does not grow a pane ahead of the command.

## The work, in order

Nothing below is a release promise. It is the order in which work earns
a place on `develop`.

1. **Coverage before features.** A filter the agent never calls saves
   nothing. OMP's native `grep` and `glob`, and bash output the rewrite
   missed, are compacted by `contextcrawler observe` after the tool
   returns (#247). `read` and semantic `find` stay as the tool returned
   them: replacing those tools drops hashline anchors and the ranked
   digest. The Pi guidance says the same thing (#248). OMP rebinds
   that extension into child sessions, so OMP subagents are covered.
   Claude Code does not inherit the parent
   PreToolUse hook into a subagent (#204); `contextcrawler session`
   counts those transcripts and the workaround is in the threat model.
2. **Filters that currently save ~0%.** Recursive and context `grep`
   now filter (#193). Format flags (`-c`, `-l`, `-o`, `-Z`) and the
   flags that collide with rg (`-H`, `-h`, `-G`) stay raw: the output
   is already one line per file, or forwarding the flag makes rg print
   help or drop filenames. `sh` and `sudo` already unwrap to the inner
   command (#195). The `^npx` catch-all is deleted: it claimed 70% and
   saved nothing. `npx tsc` and the other named tools still match their
   own rules. Do not add a sixty-first filter while a live rule reports
   nothing.
3. **The gate stays empirical.** The false-positive corpus (#243) is
   the stopping rule for #191, and it is in place: `cargo test
   gate_corpus` replays `tests/fixtures/gate_corpus.jsonl` and pins the
   suppressed count. No further classifier cleverness without a replay
   that shows ordinary work prompting less often and the known
   adversarial shapes still prompting.
4. **The instrument must not rot.** `downgrades.jsonl` rotates on write
   (#240). A clap failure on `read` exits through clap instead of execing
   a shell builtin and reporting success (#238). The user config and data
   directories are `~/.config/contextcrawler` and
   `~/.local/share/contextcrawler`, and the current release pin is
   v0.5.1 (#242). Project-local filters load from
   `.contextcrawler/filters.toml`, and from `.ctxcrl/filters.toml` only
   when that file is absent. Trust is checked on the file that was opened.

## How a later idea gets in

Write down which of the two jobs it changes, and which agent path it
sits on. If the answer is "a new pane", "a setting", or "a doc", it
waits until the four items above are boring.

`develop` is the trunk. There is no `main`. A release is a tag on
`develop` once the binary in use matches that commit, not a second
branch created to feel finished.
