---
title: ContextCrawler as a Library
description: Embedding the ContextCrawler filtering and summarisation API in a downstream Rust program - curated public functions, signatures, and examples.
sidebar:
  order: 6
---

# ContextCrawler as a library

As of 0.4.0 ContextCrawler is a `lib` + `bin` crate. The `contextcrawler`
binary is a thin shim over the library, so anything the CLI does on the
deterministic filtering path is also reachable from Rust without spawning a
subprocess.

This page documents the curated public API: the small set of functions that
downstream Rust tools are meant to embed.

## EXPERIMENTAL - not yet semver-stable

The public API is **unstable and NOT yet semver-guaranteed**. It may change
between any two 0.x releases. If you depend on it, pin an exact version:

```toml
[dependencies]
contextcrawler = { git = "https://github.com/thehoff/contextcrawler", tag = "v0.4.0" }
```

The crate is published from source only; there is no pre-built artifact to
install. Build it through Cargo like any other dependency.

## Adding it as a dependency

ContextCrawler is consumed as a git dependency. Add it to your `Cargo.toml`:

```toml
[dependencies]
# Track a fixed tag (recommended while the API is experimental):
contextcrawler = { git = "https://github.com/thehoff/contextcrawler", tag = "v0.4.0" }

# Or pin to an exact commit for full reproducibility:
# contextcrawler = { git = "https://github.com/thehoff/contextcrawler", rev = "<sha>" }
```

The crate name is `contextcrawler`, so you `use contextcrawler::...` in code.

## The curated surface

The library re-exports exactly these items from its crate root
(`src/lib.rs`):

| Item | Kind | Source module |
|------|------|---------------|
| `filter_output` | fn | `api` |
| `auto_filter_output` | fn | `api` |
| `available_filters` | fn | `api` |
| `summarize_command_output` | fn | `core::output_summary` |
| `CommandOutputSummaryOptions` | struct | `core::output_summary` |
| `no_bloat` | fn | `core::runner` |
| `run` | fn | `cli` (the CLI entry point the binary calls) |

Everything else is internal. The `core` module is technically `pub` so the
in-tree doctests keep compiling, but it is marked `#[doc(hidden)]` and is **not**
part of the supported surface. Do not reach into `contextcrawler::core::...`;
treat the items above as the whole API.

## Why embed instead of spawning the CLI

You could shell out to `contextcrawler pipe` and feed it stdin. Embedding the
library directly is preferable when:

- **You already have the text in memory.** `filter_output` / `auto_filter_output`
  take a `&str` and return a `String`. No pipe plumbing, no second process, no
  stdin/stdout marshalling.
- **You want determinism in a hot path.** `summarize_command_output` is a pure,
  local heuristic. It never spawns a process or calls a model, so it is safe to
  run in a tool-preview path on every invocation.
- **You want to avoid process-spawn overhead and PATH ambiguity.** No dependency
  on a `contextcrawler` binary being installed and resolvable at runtime.

Spawning the CLI is still the right call when you want the full command-aware
pipeline (run the real tool, capture its output, apply the matching filter,
record token savings). The library functions below are the deterministic,
text-in/text-out subset of that pipeline.

## Filtering API

### `filter_output`

```rust
pub fn filter_output(filter_name: &str, raw: &str) -> String
```

Apply a **named** filter to text you have already captured.

- **`filter_name`** - one of the names returned by [`available_filters`]
  (for example `"grep"`, `"cargo-test"`, `"git-diff"`). Aliases such as `"rg"`
  and `"fd"` are accepted.
- **`raw`** - the text to compact, typically the stdout you captured from
  running the corresponding command yourself.
- **Returns** - the filtered (token-reduced) text. If `filter_name` is not
  recognised, `raw` is returned unchanged.

This mirrors `contextcrawler pipe -f <filter_name>` exactly. Two properties to
keep in mind:

- **Exit-blind.** A piped filter only ever sees text, never the command's exit
  code. Failure-aware behaviour (for example "show errors only on a non-zero
  exit") is not available through this entry point. If you need exit-aware
  filtering, run the command through the CLI itself.
- **Panic-safe.** If the underlying filter panics, the raw input is passed
  through unchanged (a warning is written to stderr) rather than unwinding into
  your program.

```rust
use contextcrawler::filter_output;

let raw = "\
src/main.rs:42:    let result = do_work(ctx, payload)?;
src/main.rs:43:    let result = do_work(ctx, payload)?;
src/lib.rs:7:pub fn helper() {}
";

let compact = filter_output("grep", raw);
println!("{compact}");

// An unknown filter name is a no-op passthrough:
assert_eq!(filter_output("not-a-real-filter", raw), raw);
```

### `auto_filter_output`

```rust
pub fn auto_filter_output(raw: &str) -> String
```

Apply a filter chosen by **sniffing the content** of `raw`.

- **`raw`** - the captured text. The detector inspects roughly the first 1 KiB
  to recognise the output shape (cargo test, pytest, grep, go test JSON, mypy,
  vitest, find, and so on) and applies the matching filter.
- **Returns** - the compacted text. If nothing matches, `raw` is returned
  unchanged.

Mirrors `contextcrawler pipe` with no `-f` flag. Like `filter_output` it is
exit-blind and panic-safe.

```rust
use contextcrawler::auto_filter_output;

let mut raw = String::new();
for i in 1..=40 {
    raw.push_str(&format!("src/lib.rs:{i}:    handler.dispatch(request)?;\n"));
}

let compact = auto_filter_output(&raw);
assert!(compact.len() < raw.len());
```

### `available_filters`

```rust
pub fn available_filters() -> Vec<&'static str>
```

Return every filter name (and alias) that [`filter_output`] will resolve, so an
embedder can present or validate the choices. Any name not in this list causes
`filter_output` to pass input through unchanged.

As of 0.4.0 the list is:

```text
cargo-test, cargo, pytest, go-test, go-build, tsc, vitest,
grep, rg, find, fd, git-log, git-diff, git-status,
mypy, ruff-check, ruff-format, prettier
```

```rust
use contextcrawler::available_filters;

let names = available_filters();
assert!(names.contains(&"grep"));
assert!(names.contains(&"git-diff"));
```

## Summarisation API

### `summarize_command_output` and `CommandOutputSummaryOptions`

```rust
#[derive(Debug, Clone, Copy)]
pub struct CommandOutputSummaryOptions<'a> {
    pub command: &'a str,
    pub success: bool,
}

impl<'a> CommandOutputSummaryOptions<'a> {
    pub fn new(command: &'a str, success: bool) -> Self;
}

pub fn summarize_command_output(
    output: &str,
    options: CommandOutputSummaryOptions<'_>,
) -> String
```

Produce a compact, heuristic summary of command output. This is the same code
the CLI `summary` command uses, exposed so embedders share one consistent
heuristic instead of forking a copy.

- **`output`** - the raw command output to summarise.
- **`options.command`** - a human-readable command or tool label, used only for
  context in the summary header (it is truncated to 60 characters for display).
- **`options.success`** - whether the command completed successfully. Drives the
  `[ok]` versus `[FAIL]` status marker in the header.
- **`Returns`** - a multi-line `String`. The summariser classifies the output
  (test results, build output, logs, list, JSON, or generic) and renders the
  relevant compact view: counts of passed/failed/skipped, error and warning
  tallies with a handful of example lines, JSON key or array shape, list head,
  or a head-and-tail excerpt for generic text.

It is deliberately deterministic and local: no subprocess, no model call. That
makes it safe for hot tool-preview paths.

```rust
use contextcrawler::{summarize_command_output, CommandOutputSummaryOptions};

let output = "Compiling demo\nerror: expected expression\nwarning: unused variable";
let opts = CommandOutputSummaryOptions::new("cargo build", false);
let summary = summarize_command_output(output, opts);

assert!(summary.contains("[FAIL] Command: cargo build"));
assert!(summary.contains("Build Summary:"));
println!("{summary}");
```

## No-bloat guard

### `no_bloat`

```rust
pub fn no_bloat<'a>(baseline: &'a str, filtered: &'a str) -> &'a str
```

Return whichever of `baseline` or `filtered` costs **fewer tokens**, so a filter
never costs more than it saves.

- **`baseline`** - the text the filter is measured against (usually the raw
  command output, but sometimes a synthetic baseline a filter chose to track
  against).
- **`filtered`** - the output the filter produced.
- **Returns** - `filtered` when it is strictly cheaper than `baseline`;
  otherwise `baseline`. When the filtered form is the same size or larger, the
  wrapper added framing or a summary without saving anything, so the raw
  baseline wins.

The comparison uses the same token-estimation unit the tracking layer records
savings in, so the emitted text and the recorded savings always agree on
direction.

```rust
use contextcrawler::no_bloat;

let raw = "line a\nline b\nline c\nline d\n";
let summary = "4 lines"; // cheaper than the raw baseline
assert_eq!(no_bloat(raw, summary), summary);

let inflated = "this summary is somehow longer than the raw input it replaced";
assert_eq!(no_bloat(raw, inflated), raw); // baseline wins on a tie or inflation
```

## The CLI entry point

```rust
pub fn run() -> i32
```

`run` is the entire CLI: it parses `std::env::args`, runs the command, and
returns the process exit code. The binary is nothing more than:

```rust
fn main() {
    std::process::exit(contextcrawler::run());
}
```

You will rarely call `run` from a library context - it reads the real process
arguments and writes to the real stdout. It is exported so the binary can stay a
five-line shim and dogfood the exact library code path. For embedding, prefer
the text-in/text-out functions above.

## See also

- [Architecture](./architecture.md) - how the lib+bin split, the hook gate, and
  the filter pipeline fit together.
