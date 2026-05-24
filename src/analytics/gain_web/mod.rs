//! Local 127.0.0.1 dashboard for `contextcrawler gain --web` (#162).
//!
//! Read-only HTTP surface over the existing `Tracker` query funcs. Binds to
//! loopback only — no auth, no HTTPS, no cross-machine access by design. The
//! server auto-shuts-down after [`IDLE_TIMEOUT`] of zero requests so the
//! process never lingers after the user closes the tab.
//!
//! Issue: https://github.com/thehoff/contextcrawler/issues/162

mod api;
mod security_log;
mod server;

use anyhow::Result;

/// Boot the dashboard. Blocks until the server idles out or is interrupted.
pub fn run(port: Option<u16>, no_browser: bool) -> Result<()> {
    server::run(port, no_browser)
}
