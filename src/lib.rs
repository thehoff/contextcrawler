//! # ContextCrawler
//!
//! ContextCrawler is a token-optimising CLI proxy: it intercepts common
//! developer commands (git, cargo, pytest, grep, …) and rewrites their verbose
//! output into a compact form, typically saving 60–90% of the tokens an LLM
//! would otherwise spend reading them. It is a downstream fork of
//! [`rtk-ai/rtk`](https://github.com/rtk-ai/rtk) with a session compactor,
//! stacktrace compressor, HTML extractor and an opt-in security gate folded in.
//!
//! The binary is a thin shim over [`run`]. **This library** additionally exposes
//! the deterministic pieces that downstream Rust tools want to embed directly:
//!
//! - **Output summarisation** — [`summarize_command_output`] /
//!   [`CommandOutputSummaryOptions`] / [`no_bloat`].
//! - **Filtering** — [`filter_output`], [`auto_filter_output`] and
//!   [`available_filters`], which apply a named (or auto-detected) filter to
//!   text you have already captured, without spawning the CLI.
//!
//! ## ⚠️ EXPERIMENTAL
//!
//! The public API is **unstable and NOT yet semver-guaranteed**; it may change
//! between 0.x releases. Pin an exact version if you depend on it.
//!
//! ## Example
//!
//! ```no_run
//! // Compact the output of a command you ran yourself.
//! let raw = "src/main.rs:42:fn main() {}\nsrc/lib.rs:7:pub fn helper() {}\n";
//! let compact = contextcrawler::filter_output("grep", raw);
//! println!("{compact}");
//!
//! // Or summarise arbitrary command output deterministically.
//! use contextcrawler::{summarize_command_output, CommandOutputSummaryOptions};
//! let opts = CommandOutputSummaryOptions::new("grep -rn fn src/", true);
//! let summary = summarize_command_output(raw, opts);
//! println!("{summary}");
//! ```
mod analytics;
mod api;
mod cmds;
// `core` is kept `pub` so the ~24 doctests inside `src/core/**` (which reference
// `contextcrawler::core::…` paths with no curated public alias) keep compiling,
// but `#[doc(hidden)]` removes it from the *rendered* public API surface. This
// is the pragmatic narrowing: the curated entry points below are the supported
// surface; `core` remains reachable but undocumented.
#[doc(hidden)]
pub mod core;
mod discover;
mod hooks;
mod learn;
mod parser;
mod cli;

pub use api::{auto_filter_output, available_filters, filter_output};
pub use cli::run;
pub use core::output_summary::{summarize_command_output, CommandOutputSummaryOptions};
pub use core::runner::no_bloat;

// Crate-root re-exports preserved from the original binary crate root (old
// src/main.rs). The command submodules reference these short names via
// `crate::<name>`; when the crate root was main.rs its `use` statements made
// them visible to all descendants. Now that lib.rs is the root, restore the
// same crate-root namespace. Pure path plumbing — no behaviour change.
pub(crate) use cli::Commands;
use cmds::git::git;
use cmds::go::golangci_cmd;
use cmds::js::prettier_cmd;
use cmds::python::{mypy_cmd, ruff_cmd};
use cmds::system::{json_cmd, log_cmd};
