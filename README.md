<p align="center">
  <img src="docs/assets/logo.png" alt="ContextCrawler. Princess Donut says: Dammit exec()!" width="480">
</p>

### A note from the author

[rtk-ai/rtk](https://github.com/rtk-ai/rtk) gave me the clean CLI proxy. [contextzip](https://github.com/jee599/contextzip) folded in the session and stacktrace compactors I kept reaching for. [Tirith](https://tirith.sh) gave me a real shell-syntax gate. I was meant to just *use* them. Instead I keep bolting more crap on: supply-chain gate, discover command, web extractor, session manager. I genuinely cannot stop.

The fluffy ragdoll up top is my recurring mascot, same one on the blog, same one anywhere I need a logo. Hat tip to **Matt Dinniman** ([Dungeon Crawler Carl](https://en.wikipedia.org/wiki/Dungeon_Crawler_Carl)) for the recent-reading inspiration behind the "Dammit exec()!" line.

Thanks **[rtk](https://github.com/rtk-ai/rtk)**, **[contextzip](https://github.com/jee599/contextzip)** and **[Tirith](https://tirith.sh)** for the bones. Sorry upstream for the bolt-ons. Not sorry for the cat.

# ContextCrawler

> [!WARNING]
> **Active development. Might work, might not. Use at your own risk.**
>
> This is a fast-moving downstream fork by one person. Before depending on
> it: build it yourself, test it against your own workflow, read the diff
> on top of upstream rtk, and run the code through your favourite LLM for
> a second opinion (why not). **Don't trust me. Verify.** Bug reports
> welcome; expectations of stability shouldn't be.

ContextCrawler is a CLI proxy for AI coding agents (Claude Code, Cursor,
Copilot, Gemini, …) that does two things:

1. **Compresses** noisy command output before it eats your LLM context window.
2. **Gates** risky shell commands and supply-chain installs before any
   auto-approval reaches the agent.

One binary, one name: **`contextcrawler`**. Since 0.4.0 the same crate is
also a small Rust **library** (see [Use as a library](#use-as-a-library)).

**Built from** [rtk-ai/rtk](https://github.com/rtk-ai/rtk) (the core CLI
proxy and 60+ command filters, tracked by rebase), [jee599/contextzip](https://github.com/jee599/contextzip)
(the session compactor, stacktrace compressor, and HTML extractor, carried
over with per-file SPDX headers), and [Tirith](https://tirith.sh) (a
shell-syntax security gate, invoked subprocess-only). The supply-chain gate
is built in-tree. See [Architecture](docs/guide/architecture.md) for the lineage diagram.

## Goal

Make AI coding agents both **cheaper** and **safer** without changing how you
work: compress noisy output before it eats your context window, and run
agent-proposed commands past two optional, opt-in gates (shell-syntax
inspection, pre-install supply-chain checks) before auto-approving them.

## Capabilities

Everything is one binary; the full command and filter reference lives in
[`docs/guide/commands.md`](docs/guide/commands.md).

- **Token-saving filters**: 60+ command filters (git, cargo, npm, kubectl,
  docker, …) plus per-language stacktrace trimming and HTML chrome
  stripping. Typically 60-90% fewer tokens per command.
- **Security gate** (optional): routes auto-allow rewrites through Tirith;
  block-level findings downgrade the verdict to *Ask*. Fail-open by default.
- **Supply-chain control** (opt-in): pre-install age-of-release + OSV CVE
  lookup for `npm`/`pnpm`/`yarn` and `pip`/`uv`/`poetry`/`pipx` installs.
- **Analytics**: `contextcrawler gain` for token-savings stats and
  `contextcrawler discover` for filtering opportunities you missed.
- **Library API**: apply the filters to text you already have, from Rust,
  without spawning the CLI.

For the gates (env knobs, false positives, the gate-safe network-fetch
pattern, `tirith trust`), see
[`docs/security/working-with-the-gate.md`](docs/security/working-with-the-gate.md).

## Use as a library

Since 0.4.0 the crate publishes a small curated Rust API so a downstream tool
can apply ContextCrawler's filters to text it already has, no CLI subprocess.

> [!WARNING]
> **The public API is experimental and NOT yet semver-guaranteed.** It may
> change between 0.x releases. There are no pre-built crates, so depend on
> it from source and pin an exact tag.

```toml
[dependencies]
contextcrawler = { git = "https://github.com/thehoff/contextcrawler", tag = "v0.4.0" }
```

The curated entry points (re-exported from the crate root) are
`filter_output`, `auto_filter_output`, `available_filters`,
`summarize_command_output` (with `CommandOutputSummaryOptions`), and
`no_bloat`. The filtering helpers are panic-safe and exit-blind (text only,
never the command's exit code). Full surface, signatures, and examples:
[`docs/guide/library.md`](docs/guide/library.md) and the rustdoc
(`cargo doc --open`).

## Install

Requires a Rust toolchain (`rustup`, stable, 1.80+). **There are no
pre-built binaries** (single-maintainer fork); you build from source.
Installation is always through Cargo, never by copying a binary around.

```sh
# From a clone (recommended, read the diff first):
git clone https://github.com/thehoff/contextcrawler.git
cd contextcrawler && git checkout v0.4.0
cargo install --path .

# Or straight from git:
cargo install --git https://github.com/thehoff/contextcrawler --tag v0.4.0 --locked
```

Then wire up the agent hook. Run `contextcrawler init -g` for Claude Code,
or the per-agent flag for the others. Full walkthrough (the rtk/contextzip
migration step, every agent, the optional Tirith and supply-chain gates):
[Installation](docs/guide/getting-started/installation.md) and
[Supported agents](docs/guide/getting-started/supported-agents.md).

## Configuration & data locations

Config lives under `~/.config/ctxcrl/`, savings history at
`~/.local/share/ctxcrl/history.db`. Environment variables use the `CTXCRL_*`
prefix; legacy `RTK_*` names are still honoured via a shim. See
[Configuration](docs/guide/getting-started/configuration.md) for the full list.

## Documentation

- [Documentation hub](docs/guide/index.md): start here
- [Installation](docs/guide/getting-started/installation.md) · [Quick start](docs/guide/getting-started/quick-start.md) · [Configuration](docs/guide/getting-started/configuration.md) · [Supported agents](docs/guide/getting-started/supported-agents.md)
- [Command & filter reference](docs/guide/commands.md): every command, what it strips, the savings
- [Use as a library](docs/guide/library.md): the experimental Rust API
- [Architecture](docs/guide/architecture.md): lib+bin split, the hook gate, diagrams
- [Working with the security gate](docs/security/working-with-the-gate.md): false positives, `tirith trust`, the network-fetch pattern
- [Tracking & analytics](docs/usage/TRACKING.md): the savings data model and schema

## License

The downstream parts of this repository are MIT.

- Upstream rtk content remains under its original license terms (see
  the root `LICENSE`). Note that upstream rtk's repo is internally
  inconsistent (`LICENSE` says Apache-2.0; `Cargo.toml` says MIT). We
  preserve those upstream files as-is.
- Source files we add or carry over carry per-file SPDX-License-Identifier
  headers citing their origin (jee599/contextzip MIT for ported modules;
  ContextCrawler contributors MIT for new additions).
- Tirith is AGPL-3.0 and is **only invoked via subprocess**; no statically
  linked AGPL code in this distribution.

## Attribution

- [rtk-ai/rtk](https://github.com/rtk-ai/rtk): upstream base. Active,
  47K stars, current release v0.39.0. ContextCrawler tracks their tagged
  releases.
- [jee599/contextzip](https://github.com/jee599/contextzip): source of the
  session compactor, stacktrace compressor, and HTML extractor. Each
  carried-over file has a per-file SPDX header citing this upstream.
- [sheeki03/tirith](https://github.com/sheeki03/tirith): invoked via
  subprocess for the optional defense-in-depth gate.

## Status

v0.4.0 is the library pivot: the binary is now a thin shim over the
`contextcrawler` library crate, which also exposes the experimental
filter/summary API above. See [`CHANGELOG.md`](CHANGELOG.md).
