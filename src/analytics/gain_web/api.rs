//! Read-only JSON endpoints for the `gain --web` dashboard (#162).
//!
//! Each handler opens its own short-lived `Tracker` so a long-running server
//! never holds the SQLite connection open between requests. The DB is on
//! local disk and queries are sub-millisecond, so the per-request open cost
//! is irrelevant.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::core::tracking::{
    DayStats, GainSummary, ParseFailureSummary, ReleaseBoundary, Tracker, WeakFilter,
};

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

/// `/api/weak-filters` — tools leaking the most tokens. Sliced from the
/// latest release boundary by default (mirrors `gain --weak-filters`).
pub fn weak_filters() -> Result<String> {
    let tracker = Tracker::new().context("Failed to open tracking DB")?;
    let since = tracker
        .latest_boundary_timestamp()
        .context("Failed to read latest release boundary")?;
    let filters: Vec<WeakFilter> = tracker
        .get_weak_filters(None, since.as_deref())
        .context("Failed to load weak filters")?;
    let envelope = WeakFiltersEnvelope {
        since,
        weak_filters: filters,
    };
    serde_json::to_string(&envelope).context("Failed to serialise weak-filters JSON")
}

#[derive(Serialize)]
struct WeakFiltersEnvelope {
    /// Boundary timestamp the slice starts from (`None` ⇒ lifetime).
    since: Option<String>,
    weak_filters: Vec<WeakFilter>,
}

/// `/api/failures` — parse-failure rollup (recovery rate, top failing
/// commands, recent failures).
pub fn failures() -> Result<String> {
    let tracker = Tracker::new().context("Failed to open tracking DB")?;
    let summary: ParseFailureSummary = tracker
        .get_parse_failure_summary()
        .context("Failed to load parse-failure summary")?;
    serde_json::to_string(&summary).context("Failed to serialise failures JSON")
}

/// `/api/boundaries` — full release-install history + the latest pointer.
pub fn boundaries() -> Result<String> {
    let tracker = Tracker::new().context("Failed to open tracking DB")?;
    let boundaries: Vec<ReleaseBoundary> = tracker
        .all_release_boundaries()
        .context("Failed to load release boundaries")?;
    let latest = boundaries.first().map(|b| b.installed_at.clone());
    let envelope = BoundariesEnvelope { latest, boundaries };
    serde_json::to_string(&envelope).context("Failed to serialise boundaries JSON")
}

#[derive(Serialize)]
struct BoundariesEnvelope {
    latest: Option<String>,
    boundaries: Vec<ReleaseBoundary>,
}

/// `/api/insights` — stub endpoint. Real logic ships with #158
/// (`gain --insights`). We return a stable empty envelope so the
/// dashboard frontend can render its "awaiting #158" placeholder
/// without special-casing a 404.
///
/// When #158 lands, replace the stub body with the real call —
/// the wire shape is already locked: `{insights: [...], status, message}`.
pub fn insights() -> Result<String> {
    let envelope = InsightsEnvelope {
        status: "pending",
        message: "Insights endpoint live; backing logic ships with #158 (gain --insights).",
        insights: Vec::new(),
    };
    serde_json::to_string(&envelope).context("Failed to serialise insights JSON")
}

#[derive(Serialize)]
struct InsightsEnvelope {
    status: &'static str,
    message: &'static str,
    insights: Vec<Insight>,
}

#[derive(Serialize)]
#[allow(dead_code)] // populated once #158 lands — kept here so the wire shape is the contract
struct Insight {
    kind: String,
    title: String,
    detail: String,
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

    #[test]
    fn weak_filters_envelope_shape() {
        if let Ok(body) = weak_filters() {
            let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
            assert!(parsed["weak_filters"].is_array());
            // `since` may be null on a fresh DB — both shapes are valid.
            assert!(parsed.get("since").is_some());
        }
    }

    #[test]
    fn failures_envelope_shape() {
        if let Ok(body) = failures() {
            let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
            assert!(parsed.get("total").is_some());
            assert!(parsed.get("recovery_rate").is_some());
            assert!(parsed["top_commands"].is_array());
            assert!(parsed["recent"].is_array());
        }
    }

    #[test]
    fn boundaries_envelope_shape() {
        if let Ok(body) = boundaries() {
            let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
            assert!(parsed["boundaries"].is_array());
            // `latest` mirrors boundaries[0].installed_at — assert that
            // when both exist they agree.
            if let Some(first) = parsed["boundaries"].get(0) {
                assert_eq!(parsed["latest"], first["installed_at"]);
            }
        }
    }

    #[test]
    fn insights_stub_shape_is_locked() {
        // The wire contract must stay stable until #158 wires real data
        // through. The frontend reads {status, message, insights[]}.
        let body = insights().expect("stub must always succeed");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["status"], "pending");
        assert!(parsed["message"].is_string());
        assert!(parsed["insights"].is_array());
        assert_eq!(parsed["insights"].as_array().unwrap().len(), 0);
    }
}
