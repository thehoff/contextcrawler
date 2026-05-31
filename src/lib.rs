//! ContextCrawler library entry point.
//!
//! The binary remains the primary product, but downstream tools can depend on
//! this crate for deterministic output summarization/filtering without spawning
//! the CLI and reparsing stdout.

pub mod core;

pub use core::output_summary::{summarize_command_output, CommandOutputSummaryOptions};
pub use core::runner::no_bloat;
