# Performance profile — feat/gain-web-162

**Date**: 2026-05-25
**Branch**: feat/gain-web-162 (10 commits ahead of develop)
**Toolchain**: rustc 1.95.0, macOS aarch64, profiling build (`cargo build --profile profiling`)

## Why this exists

The hardening pass on the dashboard branch flagged 15.8 ms of overhead
on `contextcrawler git status` vs raw `git status` (27.3 ms vs 11.5 ms).
Before optimising anything, profile to find where the time actually goes
— Claude's gut-feel guess was "Tracker / SQLite is the bottleneck", which
the data below disproves.

## Method

1. New `[profile.profiling]` in Cargo.toml — inherits release, keeps debug
   syms, no strip. Build with `cargo build --profile profiling`.
2. `hyperfine --warmup 5 --runs 20` across five layered configurations to
   isolate cost per stage.
3. `samply record --rate 10000 --unstable-presymbolicate` on a single
   `contextcrawler git status` invocation for function-level resolution
   (single-shot at 10 kHz gives ~30 samples over the 26 ms run — enough
   to identify the dominant 1-2 ms slices).
4. Manual symbol resolution via `nm` + `rustfilt` (samply's `load` opens
   a browser; for headless writeup we resolve offsets directly).

All runs against the sanitised demo env from
`scripts/seed-demo-env.sh` so the SQLite has realistic content (2035
commands, 464 installs across 5 generic project paths).

## Hyperfine layer breakdown

| Stage | Wall time | Delta over previous | Cumulative cost |
|---|---|---|---|
| `contextcrawler --help` (CLI only) | 3.2 ms ± 0.3 | — | clap parse + binary load |
| raw `git status` (control) | 11.7 ms ± 0.4 | — | git's own work |
| `contextcrawler proxy git status` | 17.2 ms ± 1.2 | **+5.5 ms** over raw | fork-exec git + read-to-end + ANSI strip |
| `contextcrawler git status` (full) | 26.3 ms ± 0.7 | **+9.1 ms** over proxy | filter + Tracker write |
| `contextcrawler git status` (gates off) | 27.7 ms ± 2.6 | **same as full** | gates are zero-cost when not configured |

### Findings from hyperfine alone

- **Gates are not the bottleneck.** Disabling both Tirith
  (`CONTEXTCRAWLER_TIRITH_DISABLED=1`) and the supply-chain gate
  (`CONTEXTCRAWLER_SUPPLY_CHAIN=off`) produced no measurable speedup. Both
  short-circuit cleanly when not configured. ✅
- **Proxy overhead is mostly the subprocess.** The +5.5 ms from raw → proxy
  is fork-exec + reading git's stdout + ANSI stripping. Hard to remove
  without changing what ContextCrawler does fundamentally.
- **Optimisable surface is the +9.1 ms slice** between proxy and full:
  filter + Tracker. The samply profile (below) tells us how that splits.

## Samply leaf-time profile (function self-time)

Sampled at 10 kHz over one `git status` run, ~30 samples total. Hot leaf
frames (where the CPU was actually spending time inside, not just
through):

| Self samples | Function | Layer |
|---|---|---|
| 16 | `MinimalFilter::filter` | Filter dispatcher |
| 4 | `serde_core::de::MapAccess::next_value` | Config TOML deserialisation |
| 2 | `VitestParser::parse` | Parser dispatch |
| 2 | `core::str::pattern::CharSearcher::next_match_back` | Regex back-matching |
| 1 each | various stdlib (drop, dealloc, vec growth) | Allocator churn |

## Samply inclusive-time profile (function on stack)

Top stack frames by how often they appeared anywhere on the stack:

| Samples | Function | Reading |
|---|---|---|
| 17 | `_main` / `contextcrawler::main` / `run_cli` | Entry path — everything is downstream of this |
| 10 | `contextcrawler::core::stream::exec_capture` | **Subprocess execution + stdout capture (~5.5 ms)** |
| 8 | `std::io::default_read_to_end` | Reading git's output (subset of exec_capture cost) |
| 6 | `contextcrawler::core::stream::exec_capture_with_limits` | Same family, bounded read |
| 5 | `contextcrawler::cmds::git::git::run` | git filter entry |
| 4 | `std::sys::process::unix::Command::spawn` | fork-exec of git itself |
| 4 | `std::process::Child::wait` | Waiting on git's exit |
| 4 | `serde_core::de::MapAccess::next_value` | Config load (TOML) |

## What's NOT in the profile

- **`rusqlite`, `Tracker::new`, `Tracker::record`, `ensure_release_boundary`** —
  zero samples. The DB write is small enough (a few INSERTs into WAL-mode
  SQLite on local SSD) that it never lands in the sampling window.
- **`backfill_installs_from_jsonl`** — guarded by `EXISTS LIMIT 1`; the
  short-circuit path costs nothing measurable after first boot.
- **`supply_chain_gate::check`, `tirith_gate::check`** — fail-open when not
  configured; the short-circuit branches are inlined and never sampled.

## Revised optimisation priorities

Based on actual data, not the earlier guess:

### 🔴 Real wins (file as #178)

1. **Memoise TOML config load** — `serde_core::de::MapAccess::next_value`
   eats ~4 samples (≈0.4 ms) every invocation. Config rarely changes between
   calls within the same shell session, but each `contextcrawler X`
   re-loads from disk + re-deserialises. Fix: `OnceLock<Arc<Config>>` lazy
   load on first use. Saves ~0.5 ms / call.

2. **Parser dispatch indexing** — `VitestParser::parse` shows up on a
   `git status` invocation, meaning the parser dispatcher is trying parsers
   until one matches (O(n) in parser count). Fix: index parsers by `rtk_cmd`
   prefix in a `HashMap` at init time; one lookup instead of n trials.
   Saves a variable amount depending on parser order — could be 1-3 ms on
   fast commands.

3. **`MinimalFilter::filter` hot path** — 16 self-samples is the single
   largest cost. Need a deeper look: is it doing unnecessary work on small
   outputs? A short-circuit on `stdout.len() < N` could skip the whole
   filter for the smallest inputs. Saves 1-2 ms.

### 🟡 Worth filing but lower priority

4. **Reduce subprocess overhead** — `exec_capture` is ~5.5 ms. Most of
   that is fork-exec + read-to-end which is fundamental, but `posix_spawn`
   instead of fork+exec saves a small amount on macOS. `std::process` on
   modern Rust already prefers `posix_spawn` so probably nothing here.

5. **Binary size: 8 MB → ~5 MB** — independent of runtime perf but the
   Hoff flagged it. Levers: `rusqlite` without `bundled` (use system
   SQLite, ~1.5 MB), `regex-lite` instead of `regex` where Unicode isn't
   needed (~1 MB). Risk: portability across Linux distros that may not
   ship a recent libsqlite3.

### ⚫ Not worth doing (debunked guesses)

6. ~~**Background-thread tracker writes**~~ — Tracker doesn't appear in the
   profile. The 5-10 ms savings I claimed earlier was wrong. The DB write
   is already cheap (WAL mode, small INSERT). Skip.

7. ~~**Skip backfill probe after first success**~~ — `EXISTS LIMIT 1` short-
   circuit is already free. Skip.

## Reproducibility

```bash
# Build profiling binary
cargo build --profile profiling --bin contextcrawler

# Seed sanitised env (writes to a fresh tempdir, prints HOME)
eval "$(bash scripts/seed-demo-env.sh)"

# Layer breakdown
hyperfine --warmup 5 --runs 20 \
  -n "raw git status"                       'git status >/dev/null' \
  -n "contextcrawler proxy git status"      "target/profiling/contextcrawler proxy git status >/dev/null 2>&1" \
  -n "contextcrawler git status (full)"     "target/profiling/contextcrawler git status >/dev/null 2>&1" \
  -n "contextcrawler git status (no gate)"  "CONTEXTCRAWLER_TIRITH_DISABLED=1 CONTEXTCRAWLER_SUPPLY_CHAIN=off target/profiling/contextcrawler git status >/dev/null 2>&1" \
  -n "contextcrawler --help"                "target/profiling/contextcrawler --help >/dev/null"

# samply profile
samply record --rate 10000 --save-only --unstable-presymbolicate \
  --output docs/perf/cc-git-status.profile.json \
  -- target/profiling/contextcrawler git status

# View the profile in the browser (loads against the binary for symbols)
samply load docs/perf/cc-git-status.profile.json
```

## Artefacts

- `docs/perf/layer-breakdown.md` — hyperfine markdown export
- `docs/perf/cc-git-status.profile.json` — samply profile, full path
- `docs/perf/cc-git-status.profile.syms.json` — symbol sidecar
- `docs/perf/contextcrawler-git-status.profile.json` — raw initial run (no syms)
- `docs/perf/contextcrawler-proxy-git-status.profile.json` — proxy-path profile
