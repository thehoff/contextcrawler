//! Tail-readers + aggregators for the two JSONL security logs (#171).
//!
//! Both logs live under the user data dir alongside `history.db`:
//!
//!   ~/Library/Application Support/contextcrawler/downgrades.jsonl
//!   ~/Library/Application Support/contextcrawler/supply_chain.jsonl
//!
//! The hook side (`hooks::tirith_gate`, `hooks::supply_chain_gate`) appends
//! to these files; here we read the tail for the dashboard. We deliberately
//! cap the read at [`TAIL_BYTES`] — the supply-chain log on a busy machine
//! already crosses 20MB and will keep growing forever.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// 1 MiB tail cap. Covers a few thousand records of either log — enough
/// for the dashboard's "recent / histogram" surface without an unbounded
/// allocation when the file is huge or has been tampered with.
const TAIL_BYTES: u64 = 1024 * 1024;

/// How many "recent" events the API surface returns by default.
const RECENT_LIMIT: usize = 20;

/// How many entries to keep in the "top blocked packages" leaderboard.
const TOP_LIMIT: usize = 10;

fn downgrades_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("contextcrawler/downgrades.jsonl"))
}

fn supply_chain_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("contextcrawler/supply_chain.jsonl"))
}

/// Read at most the last `max_bytes` of `path` as a UTF-8 string. A tail
/// that begins mid-multibyte-sequence is recovered via lossy conversion;
/// the first (possibly truncated) line is discarded by the parser.
///
/// Mirrors `tirith_gate::read_file_tail` deliberately — duplicated rather
/// than re-exported so the hook layer stays free of analytics-side
/// dependencies. Twelve lines isn't worth a cross-module pub(crate).
fn read_file_tail(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > max_bytes {
        f.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut buf = Vec::with_capacity(max_bytes.min(len) as usize);
    f.take(max_bytes).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Parse a JSONL tail into `Value`s, skipping anything that doesn't parse
/// (typically the first truncated line after a tail-seek).
fn parse_jsonl(content: &str) -> Vec<Value> {
    content
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.is_empty() {
                return None;
            }
            serde_json::from_str::<Value>(t).ok()
        })
        .collect()
}

/// `/api/security/gate` payload — aggregated Tirith downgrades log.
#[derive(Serialize)]
pub struct GateSummary {
    pub total: usize,
    pub by_action: Vec<(String, usize)>,
    pub by_rule: Vec<(String, usize)>,
    pub recent: Vec<GateEvent>,
    /// `true` when the read was tail-capped and we may have missed older
    /// records — frontend uses this to render an "approximate" pill.
    pub tail_capped: bool,
}

#[derive(Serialize)]
pub struct GateEvent {
    pub ts: String,
    pub cmd: String,
    pub reason: String,
    pub rule_ids: Vec<String>,
}

pub fn gate_summary() -> Result<GateSummary> {
    let Some(path) = downgrades_path() else {
        return Ok(empty_gate());
    };
    if !path.exists() {
        return Ok(empty_gate());
    }
    let file_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let content = read_file_tail(&path, TAIL_BYTES)?;
    let records = parse_jsonl(&content);

    let mut by_action: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut by_rule: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut events: Vec<GateEvent> = Vec::new();

    for r in &records {
        let reason = r
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *by_action.entry(reason.clone()).or_insert(0) += 1;

        let rule_ids: Vec<String> = r
            .get("tirith")
            .and_then(|t| t.get("findings"))
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| f.get("rule_id").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        for rule in &rule_ids {
            *by_rule.entry(rule.clone()).or_insert(0) += 1;
        }

        events.push(GateEvent {
            ts: r
                .get("ts")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            cmd: r
                .get("cmd")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            reason,
            rule_ids,
        });
    }

    Ok(GateSummary {
        total: records.len(),
        by_action: sorted_desc(by_action),
        by_rule: top_n(by_rule, TOP_LIMIT),
        recent: tail_n(events, RECENT_LIMIT),
        tail_capped: file_len > TAIL_BYTES,
    })
}

fn empty_gate() -> GateSummary {
    GateSummary {
        total: 0,
        by_action: vec![],
        by_rule: vec![],
        recent: vec![],
        tail_capped: false,
    }
}

/// `/api/security/supply-chain` payload — aggregated install-gate log.
#[derive(Serialize)]
pub struct SupplyChainSummary {
    pub total: usize,
    pub by_verdict: Vec<(String, usize)>,
    pub top_blocked_packages: Vec<(String, usize)>,
    pub recent_blocks: Vec<SupplyChainEvent>,
    pub tail_capped: bool,
}

#[derive(Serialize)]
pub struct SupplyChainEvent {
    pub ts: String,
    pub cmd: String,
    pub verdict: String,
    /// `(package, ecosystem, severity, reason_kind)` for each finding.
    pub findings: Vec<FindingDigest>,
}

#[derive(Serialize)]
pub struct FindingDigest {
    pub package: String,
    pub ecosystem: String,
    pub severity: String,
    pub reason_kind: String,
}

pub fn supply_chain_summary() -> Result<SupplyChainSummary> {
    let Some(path) = supply_chain_path() else {
        return Ok(empty_supply_chain());
    };
    if !path.exists() {
        return Ok(empty_supply_chain());
    }
    let file_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let content = read_file_tail(&path, TAIL_BYTES)?;
    let records = parse_jsonl(&content);

    let mut by_verdict: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut blocked_packages: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut block_events: Vec<SupplyChainEvent> = Vec::new();

    for r in &records {
        let verdict = r
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *by_verdict.entry(verdict.clone()).or_insert(0) += 1;

        if verdict == "block" {
            let findings_digest = extract_findings(r);
            for f in &findings_digest {
                *blocked_packages.entry(f.package.clone()).or_insert(0) += 1;
            }
            block_events.push(SupplyChainEvent {
                ts: r
                    .get("ts")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                cmd: r
                    .get("cmd")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                verdict,
                findings: findings_digest,
            });
        }
    }

    Ok(SupplyChainSummary {
        total: records.len(),
        by_verdict: sorted_desc(by_verdict),
        top_blocked_packages: top_n(blocked_packages, TOP_LIMIT),
        recent_blocks: tail_n(block_events, RECENT_LIMIT),
        tail_capped: file_len > TAIL_BYTES,
    })
}

fn empty_supply_chain() -> SupplyChainSummary {
    SupplyChainSummary {
        total: 0,
        by_verdict: vec![],
        top_blocked_packages: vec![],
        recent_blocks: vec![],
        tail_capped: false,
    }
}

fn extract_findings(record: &Value) -> Vec<FindingDigest> {
    record
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .map(|f| FindingDigest {
                    package: f
                        .get("package")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    ecosystem: f
                        .get("ecosystem")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    severity: f
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    reason_kind: f
                        .get("reason")
                        .and_then(|r| r.get("kind"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn sorted_desc(map: std::collections::HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

fn top_n(map: std::collections::HashMap<String, usize>, n: usize) -> Vec<(String, usize)> {
    let mut v = sorted_desc(map);
    v.truncate(n);
    v
}

fn tail_n<T>(mut v: Vec<T>, n: usize) -> Vec<T> {
    if v.len() > n {
        v.drain(..v.len() - n);
    }
    v.reverse(); // newest first
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jsonl_skips_truncated_first_line() {
        let s = "ail-end-of-truncated-row\n{\"ts\":\"x\",\"verdict\":\"allow\"}\n";
        let records = parse_jsonl(s);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["verdict"], "allow");
    }

    #[test]
    fn parse_jsonl_skips_blank_lines() {
        let s = "\n{\"a\":1}\n\n";
        assert_eq!(parse_jsonl(s).len(), 1);
    }

    #[test]
    fn tail_n_returns_newest_first() {
        let v: Vec<i32> = (1..=5).collect();
        let out = tail_n(v, 3);
        assert_eq!(out, vec![5, 4, 3]);
    }

    #[test]
    fn sorted_desc_breaks_ties_alphabetically() {
        let mut m = std::collections::HashMap::new();
        m.insert("b".to_string(), 5);
        m.insert("a".to_string(), 5);
        m.insert("c".to_string(), 9);
        assert_eq!(
            sorted_desc(m),
            vec![
                ("c".to_string(), 9),
                ("a".to_string(), 5),
                ("b".to_string(), 5),
            ]
        );
    }

    #[test]
    fn empty_paths_yield_zero_summaries() {
        // The paths only exist on machines with prior gate activity.
        // Either branch is acceptable here — we only assert no panic.
        let _ = gate_summary().expect("must not error on missing file");
        let _ = supply_chain_summary().expect("must not error on missing file");
    }
}
