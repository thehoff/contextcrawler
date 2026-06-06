//! ContextCrawler library. The binary is a thin shim over `run()`; downstream
//! Rust tools can embed the deterministic output summariser/filters here.
mod analytics;
mod cmds;
// `core` stays `pub` for now: ~24 doctests inside `src/core/**` reference
// `contextcrawler::core::…` paths that have no curated public alias. Narrowing
// this to private (for meaningful dead-code analysis on core) is deferred to the
// visibility phase, where those doctests get rehomed or the paths re-pointed.
pub mod core;
mod discover;
mod hooks;
mod learn;
mod parser;
mod cli;

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
