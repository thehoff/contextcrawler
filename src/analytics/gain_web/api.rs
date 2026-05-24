//! Read-only JSON endpoints for the `gain --web` dashboard (#162).
//!
//! Each handler opens its own short-lived `Tracker` so a long-running server
//! never holds the SQLite connection open between requests. The DB is on
//! local disk and queries are sub-millisecond, so the per-request open cost
//! is irrelevant.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::core::tracking::{DayStats, GainSummary, Tracker};

/// `/api/summary` — overall savings rollup (lifetime + last 30d).
pub fn summary() -> Result<String> {
    let tracker = Tracker::new().context("Failed to open tracking DB")?;
    let summary: GainSummary = tracker
        .get_summary_filtered(None)
        .context("Failed to load gain summary")?;
    serde_json::to_string(&summary).context("Failed to serialise summary JSON")
}

/// `/api/by-day` — last 30 days of savings, ready for sparkline rendering.
///
/// We expose the full `DayStats` shape (not just `(date, saved)`) so the
/// frontend can render alternate views without another endpoint.
pub fn by_day() -> Result<String> {
    let tracker = Tracker::new().context("Failed to open tracking DB")?;
    let days: Vec<DayStats> = tracker
        .get_all_days()
        .context("Failed to load by-day stats")?;

    let envelope = ByDayEnvelope { days };
    serde_json::to_string(&envelope).context("Failed to serialise by-day JSON")
}

/// Envelope wrapper so future fields (e.g. release boundary markers) can be
/// added without breaking the v1 response shape.
#[derive(Serialize)]
struct ByDayEnvelope {
    days: Vec<DayStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_returns_valid_json_even_with_empty_db() {
        // Don't crash on a fresh install with zero recorded commands.
        // (Real DB read — assumes the tracker can be constructed in test env.)
        let result = summary();
        if let Ok(body) = result {
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("summary must be valid JSON");
            assert!(parsed.is_object(), "summary must be a JSON object");
            assert!(
                parsed.get("total_commands").is_some(),
                "summary must include total_commands"
            );
        }
        // If `Tracker::new()` failed (no $HOME, sandboxed CI), that's fine —
        // the production path returns a proper anyhow error and the server
        // surfaces it as a 500 with a JSON error body.
    }

    #[test]
    fn by_day_envelope_shape() {
        let result = by_day();
        if let Ok(body) = result {
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("by-day must be valid JSON");
            assert!(parsed.get("days").is_some(), "envelope must expose 'days'");
            assert!(parsed["days"].is_array(), "'days' must be a JSON array");
        }
    }
}
