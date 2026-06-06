//! Shows users how many tokens CTXCRL has saved them over time.

use crate::core::display_helpers::{format_duration, print_period_table};
use crate::core::tracking::{DayStats, MonthStats, Tracker, WeekStats};
use crate::core::utils::{format_tokens, truncate};
use crate::hooks::hook_check;
use anyhow::{Context, Result};
use chrono::Local;
use colored::Colorize;
use serde::Serialize;
use std::io::IsTerminal;
use std::path::PathBuf;

// Drop the redundant tool-name prefix at display time. Tracked commands
// have one of TWO prefixes depending on when they were recorded:
//   - `rtk X`            — pre-#62 (kept for historical rows + tracking
//                          labels in cmd modules that haven't migrated yet)
//   - `contextcrawler X` — post-#62 (current rewrite output + new tracking)
// Strip whichever prefix the row has so old + new bucket together.
fn display_cmd(s: &str) -> &str {
    s.strip_prefix("contextcrawler ")
        .or_else(|| s.strip_prefix("rtk "))
        .unwrap_or(s)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    project: bool, // added: per-project scope flag
    graph: bool,
    history: bool,
    quota: bool,
    tier: &str,
    daily: bool,
    weekly: bool,
    monthly: bool,
    all: bool,
    format: &str,
    failures: bool,
    weak_filters: bool,
    reset: bool,
    yes: bool,
    _verbose: u8,
    all_time: bool, // added: bypass release-boundary slicing for weak-filters
) -> Result<()> {
    let tracker = Tracker::new().context("Failed to initialize tracking database")?;
    let project_scope = resolve_project_scope(project)?; // added: resolve project path

    if reset {
        if !yes && !confirm_reset()? {
            println!("Aborted.");
            return Ok(());
        }
        tracker
            .reset_all()
            .context("Failed to reset token savings")?;
        println!("{}", styled("Token savings stats reset to zero.", true));
        return Ok(());
    }

    if failures {
        return show_failures(&tracker);
    }

    if weak_filters {
        return show_weak_filters(&tracker, project_scope.as_deref(), all_time);
    }

    // Handle export formats
    match format {
        "json" => {
            return export_json(
                &tracker,
                daily,
                weekly,
                monthly,
                all,
                project_scope.as_deref(), // added: pass project scope
            );
        }
        "csv" => {
            return export_csv(
                &tracker,
                daily,
                weekly,
                monthly,
                all,
                project_scope.as_deref(), // added: pass project scope
            );
        }
        _ => {} // Continue with text format
    }

    let summary = tracker
        .get_summary_filtered(project_scope.as_deref()) // changed: use filtered variant
        .context("Failed to load token savings summary from database")?;

    if summary.total_commands == 0 {
        println!("No tracking data yet.");
        println!("Run some ContextCrawler commands to start tracking savings.");
        return Ok(());
    }

    // Default view (summary)
    if !daily && !weekly && !monthly && !all {
        // added: scope-aware styled header // changed: merged upstream styled + project scope
        let title = if project_scope.is_some() {
            "ContextCrawler Token Savings (Project Scope)"
        } else {
            "ContextCrawler Token Savings (Global Scope)"
        };
        println!("{}", styled(title, true));
        println!("{}", "═".repeat(60));
        // added: show project path when scoped
        if let Some(ref scope) = project_scope {
            println!("Scope: {}", shorten_path(scope));
        }
        println!();

        // added: KPI-style aligned output
        print_kpi("Total commands", summary.total_commands.to_string());
        print_kpi("Input tokens", format_tokens(summary.total_input));
        print_kpi("Output tokens", format_tokens(summary.total_output));
        print_kpi(
            "Tokens saved",
            format!(
                "{} ({:.1}%)",
                format_tokens(summary.total_saved),
                summary.avg_savings_pct
            ),
        );
        // #196: surface filter regressions hidden by the floored savings_pct.
        // Only show when there's actual inflation so clean installs read clean.
        if summary.total_inflation > 0 {
            print_kpi(
                "Tokens inflated",
                format!(
                    "{} (filters emitted more than the raw command)",
                    format_tokens(summary.total_inflation)
                ),
            );
        }
        print_kpi(
            "Total exec time",
            format!(
                "{} (avg {})",
                format_duration(summary.total_time_ms),
                format_duration(summary.avg_time_ms)
            ),
        );
        print_efficiency_meter(summary.avg_savings_pct);
        println!();

        // Warn about hook issues that silently kill savings (stderr, not stdout)
        match hook_check::status() {
            hook_check::HookStatus::Missing => {
                eprintln!(
                    "{}",
                    "[warn] No hook installed — run `contextcrawler init -g` for automatic token savings"
                        .yellow()
                );
                eprintln!();
            }
            hook_check::HookStatus::Outdated => {
                eprintln!(
                    "{}",
                    "[warn] Hook outdated — run `contextcrawler init -g` to update".yellow()
                );
                eprintln!();
            }
            hook_check::HookStatus::Broken => {
                eprintln!(
                    "{}",
                    "[warn] Hook registered but its binary is missing — run `contextcrawler init -g` to repair (you are NOT protected)"
                        .yellow()
                );
                eprintln!();
            }
            hook_check::HookStatus::Ok => {}
        }

        // Lightweight RTK_DISABLED bypass check (best-effort, silent on failure)
        if let Some(warning) = check_ctxcrl_disabled_bypass() {
            eprintln!("{}", warning.yellow());
            eprintln!();
        }

        if !summary.by_command.is_empty() {
            // added: styled section header
            println!("{}", styled("By Command", true));

            // added: dynamic column widths for clean alignment
            let cmd_width = 24usize;
            let impact_width = 10usize;
            let count_width = summary
                .by_command
                .iter()
                .map(|(_, count, _, _, _)| count.to_string().len())
                .max()
                .unwrap_or(5)
                .max(5);
            let saved_width = summary
                .by_command
                .iter()
                .map(|(_, _, saved, _, _)| format_tokens(*saved).len())
                .max()
                .unwrap_or(5)
                .max(5);
            let time_width = summary
                .by_command
                .iter()
                .map(|(_, _, _, _, avg_time)| format_duration(*avg_time).len())
                .max()
                .unwrap_or(6)
                .max(6);

            let table_width = 3
                + 2
                + cmd_width
                + 2
                + count_width
                + 2
                + saved_width
                + 2
                + 6
                + 2
                + time_width
                + 2
                + impact_width;
            println!("{}", "─".repeat(table_width));
            println!(
                "{:>3}  {:<cmd_width$}  {:>count_width$}  {:>saved_width$}  {:>6}  {:>time_width$}  {:<impact_width$}",
                "#", "Command", "Count", "Saved", "Avg%", "Time", "Impact",
                cmd_width = cmd_width, count_width = count_width,
                saved_width = saved_width, time_width = time_width,
                impact_width = impact_width
            );
            println!("{}", "─".repeat(table_width));

            let max_saved = summary
                .by_command
                .iter()
                .map(|(_, _, saved, _, _)| *saved)
                .max()
                .unwrap_or(1);

            for (idx, (cmd, count, saved, pct, avg_time)) in summary.by_command.iter().enumerate() {
                let row_idx = format!("{:>2}.", idx + 1);
                let cmd_cell =
                    style_command_cell(&truncate_for_column(display_cmd(cmd), cmd_width)); // added: colored command
                let count_cell = format!("{:>count_width$}", count, count_width = count_width);
                let saved_cell = format!(
                    "{:>saved_width$}",
                    format_tokens(*saved),
                    saved_width = saved_width
                );
                let pct_plain = format!("{:>6}", format!("{pct:.1}%"));
                let pct_cell = colorize_pct_cell(*pct, &pct_plain); // added: color-coded percentage
                let time_cell = format!(
                    "{:>time_width$}",
                    format_duration(*avg_time),
                    time_width = time_width
                );
                let impact = mini_bar(*saved, max_saved, impact_width); // added: impact bar
                println!(
                    "{}  {}  {}  {}  {}  {}  {}",
                    row_idx, cmd_cell, count_cell, saved_cell, pct_cell, time_cell, impact
                );
            }
            println!("{}", "─".repeat(table_width));
            println!();
        }

        if graph && !summary.by_day.is_empty() {
            println!("{}", styled("Daily Savings (last 30 days)", true)); // added: styled header
            println!("──────────────────────────────────────────────────────────");
            print_ascii_graph(&summary.by_day);
            println!();
        }

        if history {
            let recent = tracker.get_recent_filtered(10, project_scope.as_deref())?; // changed: filtered
            if !recent.is_empty() {
                println!("{}", styled("Recent Commands", true)); // added: styled header
                println!("──────────────────────────────────────────────────────────");
                for rec in recent {
                    let time = rec.timestamp.with_timezone(&Local).format("%m-%d %H:%M");
                    let display = display_cmd(&rec.ctxcrl_cmd);
                    // G7/#100: char-safe truncation — byte slicing panics
                    // when a multibyte char straddles the boundary.
                    let cmd_short = truncate(display, 25);
                    // added: tier indicators by savings level
                    let sign = if rec.savings_pct >= 70.0 {
                        "▲"
                    } else if rec.savings_pct >= 30.0 {
                        "■"
                    } else {
                        "•"
                    };
                    println!(
                        "{} {} {:<25} -{:.0}% ({})",
                        time,
                        sign,
                        cmd_short,
                        rec.savings_pct,
                        format_tokens(rec.saved_tokens)
                    );
                }
                println!();
            }
        }

        if quota {
            const ESTIMATED_PRO_MONTHLY: usize = 6_000_000;

            let (quota_tokens, tier_name) = match tier {
                "pro" => (ESTIMATED_PRO_MONTHLY, "Pro ($20/mo)"),
                "5x" => (ESTIMATED_PRO_MONTHLY * 5, "Max 5x ($100/mo)"),
                "20x" => (ESTIMATED_PRO_MONTHLY * 20, "Max 20x ($200/mo)"),
                _ => (ESTIMATED_PRO_MONTHLY, "Pro ($20/mo)"),
            };

            // Numerator scoped to the last 30 days so it shares a horizon
            // with the monthly quota — dividing lifetime savings by a monthly
            // cap mixes horizons and can read >100%.
            let saved_30d = tracker.tokens_saved_30d()?;
            let quota_pct = (saved_30d as f64 / quota_tokens as f64) * 100.0;

            println!("{}", styled("Monthly Quota Analysis", true)); // added: styled header
            println!("──────────────────────────────────────────────────────────");
            print_kpi("Subscription tier", tier_name.to_string()); // added: KPI style
            print_kpi("Estimated monthly quota", format_tokens(quota_tokens));
            print_kpi(
                "Tokens saved (last 30 days)",
                format_tokens(saved_30d.max(0) as usize),
            );
            print_kpi(
                "Tokens saved (lifetime)",
                format_tokens(summary.total_saved),
            );
            print_kpi("Quota preserved (30-day)", format!("{:.1}%", quota_pct));
            println!();
            println!("Note: Heuristic estimate based on ~44K tokens/5h (Pro baseline)");
            println!("      Actual limits use rolling 5-hour windows, not monthly caps.");
        }

        return Ok(());
    }

    // Time breakdown views
    if all || daily {
        print_daily_full(&tracker, project_scope.as_deref())?; // changed: pass project scope
    }

    if all || weekly {
        print_weekly(&tracker, project_scope.as_deref())?; // changed: pass project scope
    }

    if all || monthly {
        print_monthly(&tracker, project_scope.as_deref())?; // changed: pass project scope
    }

    Ok(())
}

// ── Display helpers (TTY-aware) ── // added: entire section

/// Format text with bold styling (TTY-aware). // added
fn styled(text: &str, strong: bool) -> String {
    if !std::io::stdout().is_terminal() {
        return text.to_string();
    }
    if strong {
        text.bold().green().to_string()
    } else {
        text.to_string()
    }
}

/// Print a key-value pair in KPI layout. // added
fn print_kpi(label: &str, value: String) {
    println!("{:<18} {}", format!("{label}:"), value);
}

/// Colorize percentage based on savings tier (TTY-aware). // added
fn colorize_pct_cell(pct: f64, padded: &str) -> String {
    if !std::io::stdout().is_terminal() {
        return padded.to_string();
    }
    if pct >= 70.0 {
        padded.green().bold().to_string()
    } else if pct >= 40.0 {
        padded.yellow().bold().to_string()
    } else {
        padded.red().bold().to_string()
    }
}

/// Truncate text to fit column width with ellipsis. // added
fn truncate_for_column(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let char_count = text.chars().count();
    if char_count <= width {
        return format!("{:<width$}", text, width = width);
    }
    if width <= 3 {
        return text.chars().take(width).collect();
    }
    let mut out: String = text.chars().take(width - 3).collect();
    out.push_str("...");
    out
}

/// Style command names with cyan+bold (TTY-aware). // added
fn style_command_cell(cmd: &str) -> String {
    if !std::io::stdout().is_terminal() {
        return cmd.to_string();
    }
    cmd.bright_cyan().bold().to_string()
}

/// Render a proportional bar chart segment (TTY-aware). // added
fn mini_bar(value: usize, max: usize, width: usize) -> String {
    if max == 0 || width == 0 {
        return String::new();
    }
    let filled = ((value as f64 / max as f64) * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut bar = "█".repeat(filled);
    bar.push_str(&"░".repeat(width - filled));
    if std::io::stdout().is_terminal() {
        bar.cyan().to_string()
    } else {
        bar
    }
}

/// Print an efficiency meter with colored progress bar (TTY-aware). // added
fn print_efficiency_meter(pct: f64) {
    let width = 24usize;
    let filled = (((pct / 100.0) * width as f64).round() as usize).min(width);
    let meter = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
    if std::io::stdout().is_terminal() {
        let pct_str = format!("{pct:.1}%");
        let colored_pct = if pct >= 70.0 {
            pct_str.green().bold().to_string()
        } else if pct >= 40.0 {
            pct_str.yellow().bold().to_string()
        } else {
            pct_str.red().bold().to_string()
        };
        println!("Efficiency meter: {} {}", meter.green(), colored_pct);
    } else {
        println!("Efficiency meter: {} {:.1}%", meter, pct);
    }
}

/// Resolve project scope from --project flag. // added
fn resolve_project_scope(project: bool) -> Result<Option<String>> {
    if !project {
        return Ok(None);
    }
    let cwd = std::env::current_dir().context("Failed to resolve current working directory")?;
    let canonical = cwd.canonicalize().unwrap_or(cwd);
    Ok(Some(canonical.to_string_lossy().to_string()))
}

/// Shorten long absolute paths for display. // added
fn shorten_path(path: &str) -> String {
    let path_buf = PathBuf::from(path);
    let comps: Vec<String> = path_buf
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    if comps.len() <= 4 {
        return path.to_string();
    }
    let root = comps[0].as_str();
    if root == "/" || root.is_empty() {
        format!("/.../{}/{}", comps[comps.len() - 2], comps[comps.len() - 1])
    } else {
        format!(
            "{}/.../{}/{}",
            root,
            comps[comps.len() - 2],
            comps[comps.len() - 1]
        )
    }
}

fn print_ascii_graph(data: &[(String, usize)]) {
    if data.is_empty() {
        return;
    }

    let max_val = data.iter().map(|(_, v)| *v).max().unwrap_or(1);
    let width = 40;

    for (date, value) in data {
        let date_short = if date.len() >= 10 { &date[5..10] } else { date };

        let bar_len = if max_val > 0 {
            ((*value as f64 / max_val as f64) * width as f64) as usize
        } else {
            0
        };

        let bar: String = "█".repeat(bar_len);
        let spaces: String = " ".repeat(width - bar_len);

        println!(
            "{} │{}{} {}",
            date_short,
            bar,
            spaces,
            format_tokens(*value)
        );
    }
}

fn print_daily_full(tracker: &Tracker, project_scope: Option<&str>) -> Result<()> {
    // changed: add project scope
    let days = tracker.get_all_days_filtered(project_scope)?; // changed: use filtered variant
    print_period_table(&days);
    Ok(())
}

fn print_weekly(tracker: &Tracker, project_scope: Option<&str>) -> Result<()> {
    // changed: add project scope
    let weeks = tracker.get_by_week_filtered(project_scope)?; // changed: use filtered variant
    print_period_table(&weeks);
    Ok(())
}

fn print_monthly(tracker: &Tracker, project_scope: Option<&str>) -> Result<()> {
    // changed: add project scope
    let months = tracker.get_by_month_filtered(project_scope)?; // changed: use filtered variant
    print_period_table(&months);
    Ok(())
}

#[derive(Serialize)]
struct ExportData {
    summary: ExportSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily: Option<Vec<DayStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weekly: Option<Vec<WeekStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    monthly: Option<Vec<MonthStats>>,
}

#[derive(Serialize)]
struct ExportSummary {
    total_commands: usize,
    total_input: usize,
    total_output: usize,
    total_saved: usize,
    total_inflation: usize, // added (#196)
    avg_savings_pct: f64,
    total_time_ms: u64,
    avg_time_ms: u64,
}

fn export_json(
    tracker: &Tracker,
    daily: bool,
    weekly: bool,
    monthly: bool,
    all: bool,
    project_scope: Option<&str>, // added: project scope
) -> Result<()> {
    let summary = tracker
        .get_summary_filtered(project_scope) // changed: use filtered variant
        .context("Failed to load token savings summary from database")?;

    let export = ExportData {
        summary: ExportSummary {
            total_commands: summary.total_commands,
            total_input: summary.total_input,
            total_output: summary.total_output,
            total_saved: summary.total_saved,
            total_inflation: summary.total_inflation, // added (#196)
            avg_savings_pct: summary.avg_savings_pct,
            total_time_ms: summary.total_time_ms,
            avg_time_ms: summary.avg_time_ms,
        },
        daily: if all || daily {
            Some(tracker.get_all_days_filtered(project_scope)?) // changed: use filtered
        } else {
            None
        },
        weekly: if all || weekly {
            Some(tracker.get_by_week_filtered(project_scope)?) // changed: use filtered
        } else {
            None
        },
        monthly: if all || monthly {
            Some(tracker.get_by_month_filtered(project_scope)?) // changed: use filtered
        } else {
            None
        },
    };

    let json = serde_json::to_string_pretty(&export)?;
    println!("{}", json);

    Ok(())
}

fn export_csv(
    tracker: &Tracker,
    daily: bool,
    weekly: bool,
    monthly: bool,
    all: bool,
    project_scope: Option<&str>, // added: project scope
) -> Result<()> {
    if all || daily {
        let days = tracker.get_all_days_filtered(project_scope)?; // changed: use filtered
        println!("# Daily Data");
        println!("date,commands,input_tokens,output_tokens,saved_tokens,savings_pct,total_time_ms,avg_time_ms");
        for day in days {
            println!(
                "{},{},{},{},{},{:.2},{},{}",
                day.date,
                day.commands,
                day.input_tokens,
                day.output_tokens,
                day.saved_tokens,
                day.savings_pct,
                day.total_time_ms,
                day.avg_time_ms
            );
        }
        println!();
    }

    if all || weekly {
        let weeks = tracker.get_by_week_filtered(project_scope)?; // changed: use filtered
        println!("# Weekly Data");
        println!(
            "week_start,week_end,commands,input_tokens,output_tokens,saved_tokens,savings_pct,total_time_ms,avg_time_ms"
        );
        for week in weeks {
            println!(
                "{},{},{},{},{},{},{:.2},{},{}",
                week.week_start,
                week.week_end,
                week.commands,
                week.input_tokens,
                week.output_tokens,
                week.saved_tokens,
                week.savings_pct,
                week.total_time_ms,
                week.avg_time_ms
            );
        }
        println!();
    }

    if all || monthly {
        let months = tracker.get_by_month_filtered(project_scope)?; // changed: use filtered
        println!("# Monthly Data");
        println!("month,commands,input_tokens,output_tokens,saved_tokens,savings_pct,total_time_ms,avg_time_ms");
        for month in months {
            println!(
                "{},{},{},{},{},{:.2},{},{}",
                month.month,
                month.commands,
                month.input_tokens,
                month.output_tokens,
                month.saved_tokens,
                month.savings_pct,
                month.total_time_ms,
                month.avg_time_ms
            );
        }
    }

    Ok(())
}

/// Lightweight scan of recent Claude Code sessions for RTK_DISABLED= overuse.
/// Returns a warning string if bypass rate exceeds 10%, None otherwise.
/// Silently returns None on any error (missing dirs, permission issues, etc.).
fn check_ctxcrl_disabled_bypass() -> Option<String> {
    use crate::discover::provider::{ClaudeProvider, SessionProvider};
    use crate::discover::registry::cmd_has_ctxcrl_disabled_prefix;

    let provider = ClaudeProvider;

    // Quick scan: last 7 days only
    let sessions = provider.discover_sessions(None, Some(7)).ok()?;

    // Early bail if no sessions or too many (avoid slow scan)
    if sessions.is_empty() || sessions.len() > 200 {
        return None;
    }

    let mut total_bash: usize = 0;
    let mut bypassed: usize = 0;

    for session_path in &sessions {
        let extracted = match provider.extract_commands(session_path) {
            Ok(cmds) => cmds,
            Err(_) => continue,
        };

        for ext_cmd in &extracted {
            total_bash += 1;
            if cmd_has_ctxcrl_disabled_prefix(&ext_cmd.command) {
                bypassed += 1;
            }
        }
    }

    if total_bash == 0 {
        return None;
    }

    let pct = (bypassed as f64 / total_bash as f64) * 100.0;
    if pct > 10.0 {
        Some(format!(
            "[warn] {} commands ({:.0}%) used RTK_DISABLED=1 unnecessarily — run `contextcrawler discover` for details",
            bypassed, pct
        ))
    } else {
        None
    }
}

/// Render `gain --weak-filters`: tools ranked by leaked tokens, so the
/// reader can see where a better or new filter would recover the most.
fn show_weak_filters(
    tracker: &Tracker,
    project_scope: Option<&str>,
    all_time: bool,
) -> Result<()> {
    // Default: slice from the latest release boundary so we measure the
    // *current* binary's filter quality, not months of pre-upgrade history.
    // `--all-time` bypasses the slice for cross-version analysis.
    let boundary = if all_time {
        None
    } else {
        tracker
            .latest_boundary_timestamp()
            .context("Failed to read latest release boundary")?
    };

    let weak = tracker
        .get_weak_filters(project_scope, boundary.as_deref())
        .context("Failed to load weak-filter data")?;

    println!(
        "{}",
        styled("ContextCrawler Weak Filters — where tokens leak", true)
    );
    println!("{}", "═".repeat(64));
    println!();
    if let Some(since) = boundary.as_deref() {
        println!(
            "Window: since latest release boundary ({}). Use `--all-time` for lifetime.",
            since
        );
        println!();
    } else if all_time {
        println!("Window: lifetime (all-time).");
        println!();
    }

    if weak.is_empty() {
        // Peer-review #150 (agy): on a pre-existing DB the first invocation
        // of a new binary version writes a boundary row that excludes ALL
        // prior history. The user sees an empty leaderboard despite
        // months of data sitting one --all-time flag away. Surface that.
        if boundary.is_some() {
            let lifetime_runs = tracker
                .get_weak_filters(project_scope, None)
                .map(|w| w.iter().map(|f| f.runs).sum::<usize>())
                .unwrap_or(0);
            if lifetime_runs > 0 {
                println!(
                    "No commands recorded since the latest release boundary."
                );
                println!(
                    "Run some commands or use `--all-time` to see the lifetime view ({} historical runs).",
                    lifetime_runs
                );
                return Ok(());
            }
        }
        println!("No command data recorded yet — run some commands first.");
        return Ok(());
    }

    println!("Tools ranked by leaked tokens (input that reached the model");
    println!("unfiltered). High leak + low savings% = a filter worth building");
    println!("or improving.");
    println!();
    println!(
        "  {:<3} {:<18} {:>7} {:>10} {:>10} {:>9} {:>10}",
        "#", "Tool", "Runs", "Input", "Leaked", "Savings", "Inflated"
    );
    println!("  {}", "─".repeat(72));
    for (idx, w) in weak.iter().take(15).enumerate() {
        // #196: a dash keeps clean rows uncluttered; only inflating filters
        // show a figure, so a regression stands out at a glance.
        let inflated = if w.inflation_tokens > 0 {
            format_tokens(w.inflation_tokens)
        } else {
            "-".to_string()
        };
        println!(
            "  {:<3} {:<18} {:>7} {:>10} {:>10} {:>8.1}% {:>10}",
            format!("{}.", idx + 1),
            truncate(&w.tool, 18),
            w.runs,
            format_tokens(w.input_tokens),
            format_tokens(w.leaked_tokens),
            w.savings_pct,
            inflated,
        );
    }
    println!();
    Ok(())
}

fn show_failures(tracker: &Tracker) -> Result<()> {
    let summary = tracker
        .get_parse_failure_summary()
        .context("Failed to load parse failure data")?;

    if summary.total == 0 {
        println!("No parse failures recorded.");
        println!("This means all commands parsed successfully (or fallback hasn't triggered yet).");
        return Ok(());
    }

    println!("{}", styled("ContextCrawler Parse Failures", true));
    println!("{}", "═".repeat(60));
    println!();

    print_kpi("Total failures", summary.total.to_string());
    print_kpi("Recovery rate", format!("{:.1}%", summary.recovery_rate));
    println!();

    if !summary.top_commands.is_empty() {
        println!("{}", styled("Top Commands (by frequency)", true));
        println!("{}", "─".repeat(60));
        for (cmd, count) in &summary.top_commands {
            let display = display_cmd(cmd);
            // G7/#100: char-safe truncation (see note above).
            let cmd_display = truncate(display, 50);
            println!("  {:>4}x  {}", count, cmd_display);
        }
        println!();
    }

    if !summary.recent.is_empty() {
        println!("{}", styled("Recent Failures (last 10)", true));
        println!("{}", "─".repeat(60));
        for rec in &summary.recent {
            let ts_short = if rec.timestamp.len() >= 16 {
                &rec.timestamp[..16]
            } else {
                &rec.timestamp
            };
            let status = if rec.fallback_succeeded { "ok" } else { "FAIL" };
            // G7/#100: char-safe truncation (see note above).
            let cmd_display = truncate(&rec.raw_command, 40);
            println!("  {} [{}] {}", ts_short, status, cmd_display);
        }
        println!();
    }

    Ok(())
}

/// Prompt the user to confirm a destructive reset operation.
/// Defaults to No in non-interactive (piped) environments.
fn confirm_reset() -> Result<bool> {
    use std::io::{self, BufRead, IsTerminal, Write};

    eprint!("This will permanently delete all tracking data. Continue? [y/N] ");
    io::stderr().flush().ok();

    if !io::stdin().is_terminal() {
        eprintln!("(non-interactive mode, defaulting to N)");
        return Ok(false);
    }

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("Failed to read confirmation")?;

    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // G7/#100: `gain` truncates user-controlled command strings for display.
    // Byte slicing (`&s[..n]`) panics when a multibyte char straddles the
    // boundary; the char-safe `truncate` helper used at each display site
    // must never panic regardless of where the cut falls.
    #[test]
    fn test_gain_truncation_multibyte_no_panic() {
        // Each `é` is 2 bytes; emoji are 4. The 25/40/50-char limits used by
        // `gain` would land mid-codepoint under naive byte slicing.
        let multibyte = "git commit -m \"café 日本語 🚀🚀🚀 résumé déjà vu\"";
        for limit in [25usize, 40, 50] {
            let out = truncate(multibyte, limit);
            // Sanity: result is valid UTF-8 (String guarantees it) and is no
            // longer than the limit in chars.
            assert!(out.chars().count() <= limit);
        }
        // A string whose Nth byte is mid-codepoint at every tested boundary.
        let all_multibyte = "日".repeat(60);
        for limit in [25usize, 40, 50] {
            let _ = truncate(&all_multibyte, limit);
        }
        // display_cmd + truncate together, as the Recent Commands path does.
        let prefixed = format!("contextcrawler git log {}", "日".repeat(40));
        let _ = truncate(display_cmd(&prefixed), 25);
    }
}

#[cfg(test)]
mod sigpipe_regression {
    /// SIGPIPE regression (#startup-crash): `contextcrawler gain` used to
    /// SIGABRT when stdout was a broken pipe. Rust sets SIGPIPE to SIG_IGN
    /// by default, so broken-pipe writes return EPIPE; `println!()` then
    /// panics with "failed printing to stdout", and `panic=abort` turns that
    /// into `abort()`.
    ///
    /// Fix: reset SIGPIPE to SIG_DFL in `main()` so the process terminates
    /// cleanly (exit 141 = 128 + SIGPIPE) rather than generating a crash report.
    ///
    /// This test seeds a temp SQLite DB with 5 tracking rows so `gain` produces
    /// substantial stdout output before the pipe is closed — guaranteeing the
    /// write-to-broken-pipe path is actually exercised. The child must exit 0 or
    /// 141 (SIGPIPE clean), never 134 (SIGABRT).
    #[test]
    #[ignore] // Requires built release binary; run with: cargo test --ignored
    fn gain_no_crash_on_broken_pipe() {
        let release_bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/release/contextcrawler");
        if !release_bin.exists() {
            eprintln!("Skipping: release binary not built yet");
            return;
        }

        // Seed a temp DB so gain produces real stdout output (not "No tracking
        // data yet."). This guarantees the write-to-broken-pipe is exercised.
        let db_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db_path = db_dir.path().join("tracking.db");
        {
            let conn = rusqlite::Connection::open(&db_path)
                .expect("Failed to open temp DB");
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    original_cmd TEXT NOT NULL,
                    ctxcrl_cmd TEXT NOT NULL,
                    project_path TEXT NOT NULL DEFAULT '',
                    input_tokens INTEGER NOT NULL,
                    output_tokens INTEGER NOT NULL,
                    saved_tokens INTEGER NOT NULL,
                    savings_pct REAL NOT NULL,
                    exec_time_ms INTEGER NOT NULL DEFAULT 0
                );",
            )
            .expect("Failed to create schema");
            // Insert enough rows to produce multi-line output that exercises
            // the write path before the pipe is dropped.
            for i in 0..5 {
                conn.execute(
                    "INSERT INTO commands
                        (timestamp, original_cmd, ctxcrl_cmd, project_path,
                         input_tokens, output_tokens, saved_tokens, savings_pct, exec_time_ms)
                     VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, ?7, 12)",
                    rusqlite::params![
                        format!("2026-05-22T0{}:00:00Z", i),
                        "git log",
                        "contextcrawler git log",
                        1000_i64,
                        200_i64,
                        800_i64,
                        80.0_f64,
                    ],
                )
                .expect("Failed to insert row");
            }
        }

        let mut child = std::process::Command::new(&release_bin)
            .arg("gain")
            .env("RTK_DB_PATH", &db_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to spawn contextcrawler gain");
        // Immediately drop the read end of the pipe — creates a broken pipe
        // while the child is mid-write to its populated output.
        drop(child.stdout.take());
        let status = child.wait().expect("Failed to wait for child");
        let code = status.code().unwrap_or(0);
        // 141 = SIGPIPE (clean terminate — expected with output in flight).
        // 0 = flushed before pipe closed (acceptable edge case).
        // 134 = SIGABRT = the bug we fixed. Never acceptable.
        assert_ne!(
            code, 134,
            "contextcrawler gain crashed with SIGABRT — broken pipe not handled"
        );
        // Also assert the process did not exit with a non-signal error code
        // (anything above 1 that isn't a signal exit is suspicious).
        assert!(
            code == 0 || code == 141,
            "contextcrawler gain exited with unexpected code {code} (expected 0=clean or 141=SIGPIPE)"
        );
    }
}
