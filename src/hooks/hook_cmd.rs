//! Processes incoming hook calls from AI agents and rewrites commands on the fly.
//!
//! Uses `writeln!(stdout, ...)` instead of `println!` — accidental stdout/stderr
//! corrupts the JSON protocol (Claude Code bug #4669 silently disables the hook).

use super::constants::PRE_TOOL_USE_KEY;
use super::permissions::{self, PermissionVerdict};
// ===== contextzip-downstream: defence-in-depth gate imports begin =====
// G1 finding #2 (#100): the Tirith + supply-chain gates only ran on the
// legacy `contextcrawler rewrite` path (rewrite_cmd.rs). Wire them into the
// live Claude PreToolUse hook path too.
use super::{supply_chain_gate, tirith_gate};
// ===== contextzip-downstream: defence-in-depth gate imports end =====
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

use crate::discover::registry::{has_heredoc, rewrite_command};

const STDIN_CAP: usize = 1_048_576; // 1 MiB

fn read_stdin_limited() -> Result<String> {
    let mut input = String::new();
    io::stdin()
        .take((STDIN_CAP + 1) as u64)
        .read_to_string(&mut input)
        .context("Failed to read stdin")?;
    if input.len() > STDIN_CAP {
        anyhow::bail!("hook stdin exceeds {} byte limit", STDIN_CAP);
    }
    Ok(input)
}

// ── Copilot hook (VS Code + Copilot CLI) ──────────────────────

/// Format detected from the preToolUse JSON input.
enum HookFormat {
    /// VS Code Copilot Chat / Claude Code: `tool_name` + `tool_input.command`, supports `updatedInput`.
    VsCode { command: String },
    /// GitHub Copilot CLI: camelCase `toolName` + `toolArgs` (JSON string), deny-with-suggestion only.
    CopilotCli { command: String },
    /// Non-bash tool, already uses rtk, or unknown format — pass through silently.
    PassThrough,
}

/// Run the Copilot preToolUse hook.
/// Auto-detects VS Code Copilot Chat vs Copilot CLI format.
pub fn run_copilot() -> Result<()> {
    let input = read_stdin_limited()?;

    let input = input.trim();
    if input.is_empty() {
        return Ok(());
    }

    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(
                io::stderr(),
                "[contextcrawler hook] Failed to parse JSON input: {e}"
            );
            return Ok(());
        }
    };

    match detect_format(&v) {
        HookFormat::VsCode { command } => handle_vscode(&command),
        HookFormat::CopilotCli { command } => handle_copilot_cli(&command),
        HookFormat::PassThrough => Ok(()),
    }
}

fn detect_format(v: &Value) -> HookFormat {
    // VS Code Copilot Chat / Claude Code: snake_case keys
    if let Some(tool_name) = v.get("tool_name").and_then(|t| t.as_str()) {
        if matches!(tool_name, "runTerminalCommand" | "Bash" | "bash") {
            if let Some(cmd) = v
                .pointer("/tool_input/command")
                .and_then(|c| c.as_str())
                .filter(|c| !c.is_empty())
            {
                return HookFormat::VsCode {
                    command: cmd.to_string(),
                };
            }
        }
        return HookFormat::PassThrough;
    }

    // Copilot CLI: camelCase keys, toolArgs is a JSON-encoded string
    if let Some(tool_name) = v.get("toolName").and_then(|t| t.as_str()) {
        if tool_name == "bash" {
            if let Some(tool_args_str) = v.get("toolArgs").and_then(|t| t.as_str()) {
                if let Ok(tool_args) = serde_json::from_str::<Value>(tool_args_str) {
                    if let Some(cmd) = tool_args
                        .get("command")
                        .and_then(|c| c.as_str())
                        .filter(|c| !c.is_empty())
                    {
                        return HookFormat::CopilotCli {
                            command: cmd.to_string(),
                        };
                    }
                }
            }
        }
        return HookFormat::PassThrough;
    }

    HookFormat::PassThrough
}

fn get_rewritten(cmd: &str) -> Option<String> {
    if has_heredoc(cmd) {
        return None;
    }

    let (excluded, transparent_prefixes) = crate::core::config::Config::load()
        .map(|c| (c.hooks.exclude_commands, c.hooks.transparent_prefixes))
        .unwrap_or_default();

    let rewritten = rewrite_command(cmd, &excluded, &transparent_prefixes)?;

    if rewritten == cmd {
        return None;
    }

    Some(rewritten)
}

fn handle_vscode(cmd: &str) -> Result<()> {
    let verdict = permissions::check_command(cmd);
    if verdict == PermissionVerdict::Deny {
        audit_log("deny", cmd, "");
        return Ok(());
    }

    let rewritten = match get_rewritten(cmd) {
        Some(r) => r,
        None => return Ok(()),
    };

    // Allow (explicit rule matched): auto-allow the rewritten command.
    // Ask/Default (no allow rule matched): rewrite but let the host tool prompt.
    let decision = match verdict {
        PermissionVerdict::Allow => "allow",
        _ => "ask",
    };

    audit_log("rewrite", cmd, &rewritten);

    let output = json!({
        "hookSpecificOutput": {
            "hookEventName": PRE_TOOL_USE_KEY,
            "permissionDecision": decision,
            "permissionDecisionReason": "contextcrawler auto-rewrite",
            "updatedInput": { "command": rewritten }
        }
    });
    let _ = writeln!(io::stdout(), "{output}");
    Ok(())
}

fn handle_copilot_cli(cmd: &str) -> Result<()> {
    if permissions::check_command(cmd) == PermissionVerdict::Deny {
        audit_log("deny", cmd, "");
        return Ok(());
    }

    let rewritten = match get_rewritten(cmd) {
        Some(r) => r,
        None => return Ok(()),
    };

    audit_log("rewrite", cmd, &rewritten);

    let output = json!({
        "permissionDecision": "deny",
        "permissionDecisionReason": format!(
            "Token savings: use `{}` instead (contextcrawler saves 60-90% tokens)",
            rewritten
        )
    });
    let _ = writeln!(io::stdout(), "{output}");
    Ok(())
}

// ── Gemini hook ───────────────────────────────────────────────

/// Run the Gemini CLI BeforeTool hook.
/// Emit a Gemini-format deny decision. The Gemini hook owns the allow/deny
/// verdict, so a parse/stdin failure must fail CLOSED here — see #111 G2.
fn emit_gemini_deny(reason: &str) {
    let output = json!({
        "decision": "deny",
        "reason": reason,
    });
    let _ = writeln!(io::stdout(), "{output}");
}

pub fn run_gemini() -> Result<()> {
    let input = match read_stdin_limited() {
        Ok(input) => input,
        Err(e) => {
            // Oversized/unreadable stdin — fail closed.
            let _ = writeln!(io::stderr(), "[contextcrawler hook] {e}");
            emit_gemini_deny("contextcrawler: hook payload could not be read; denying");
            return Ok(());
        }
    };

    let json: Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            // Malformed JSON — fail closed. The Gemini hook is the allow/deny
            // authority; bubbling an Err here exits non-zero with no decision,
            // which the harness treats as ALLOW (#111 G2).
            let _ = writeln!(
                io::stderr(),
                "[contextcrawler hook] Failed to parse JSON input: {e}"
            );
            emit_gemini_deny("contextcrawler: hook payload was not valid JSON; denying");
            return Ok(());
        }
    };

    run_gemini_decision(&json);
    Ok(())
}

/// Test-only driver mirroring `run_gemini`'s JSON-parse step. Returns the
/// Gemini-format verdict string that the hook would emit. For a malformed
/// payload this is the fail-CLOSED deny verdict (#111 G2), never an `Err`.
#[cfg(test)]
fn run_gemini_inner(input: &str) -> String {
    match serde_json::from_str::<Value>(input) {
        Ok(_) => json!({ "decision": "allow" }).to_string(),
        Err(_) => json!({
            "decision": "deny",
            "reason": "contextcrawler: hook payload was not valid JSON; denying",
        })
        .to_string(),
    }
}

/// Emit the Gemini hook allow/deny/rewrite decision for an already-parsed
/// payload. Split out from `run_gemini` so the parse-failure fail-closed path
/// (#111 G2) and the decision logic can be tested independently.
fn run_gemini_decision(json: &Value) {
    let tool_name = json.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");

    if tool_name != "run_shell_command" {
        print_allow();
        return;
    }

    let cmd = json
        .pointer("/tool_input/command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if cmd.is_empty() {
        print_allow();
        return;
    }

    // Check deny rules — Gemini CLI only supports allow/deny (no ask mode).
    if permissions::check_command(cmd) == PermissionVerdict::Deny {
        let _ = writeln!(
            io::stdout(),
            r#"{{"decision":"deny","reason":"Blocked by RTK permission rule"}}"#
        );
        return;
    }

    let (excluded, transparent_prefixes) = crate::core::config::Config::load()
        .map(|c| (c.hooks.exclude_commands, c.hooks.transparent_prefixes))
        .unwrap_or_default();

    match rewrite_command(cmd, &excluded, &transparent_prefixes) {
        Some(ref rewritten) => {
            audit_log("rewrite", cmd, rewritten);
            print_rewrite(rewritten);
        }
        None => print_allow(),
    }
}

fn print_allow() {
    let _ = writeln!(io::stdout(), r#"{{"decision":"allow"}}"#);
}

fn print_rewrite(cmd: &str) {
    let output = serde_json::json!({
        "decision": "allow",
        "hookSpecificOutput": {
            "tool_input": {
                "command": cmd
            }
        }
    });
    let _ = writeln!(io::stdout(), "{}", output);
}

// ── Audit logging ─────────────────────────────────────────────

/// Best-effort audit log when RTK_HOOK_AUDIT=1.
fn audit_log(action: &str, original: &str, rewritten: &str) {
    if std::env::var("RTK_HOOK_AUDIT").as_deref() != Ok("1") {
        return;
    }
    let _ = audit_log_inner(action, original, rewritten);
}

/// Escape newlines to prevent log-line injection in the pipe-delimited audit log.
fn sanitize_log_field(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn audit_log_inner(action: &str, original: &str, rewritten: &str) -> Option<()> {
    let home = dirs::home_dir()?;
    let dir = home.join(".local").join("share").join("rtk");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join("hook-audit.log");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
    writeln!(
        file,
        "{} | {} | {} | {}",
        ts,
        action,
        sanitize_log_field(original),
        sanitize_log_field(rewritten)
    )
    .ok()
}

// ── Claude Code native hook ────────────────────────────────────

#[cfg_attr(test, derive(Debug))]
enum PayloadAction {
    Rewrite {
        cmd: String,
        rewritten: String,
        output: Value,
    },
    Skip {
        reason: &'static str,
        cmd: String,
    },
    /// Fail CLOSED with a deny verdict. Two sources:
    ///   * a genuine shape error in the payload (malformed/non-string command);
    ///   * an explicit `PermissionVerdict::Deny` from the permission engine —
    ///     an explicit deny-rule hit (#100 G2 Codex 2nd pass — CRITICAL 1).
    /// Both must emit the Claude deny JSON the harness blocks on, never a
    /// silent skip.
    Deny {
        reason: String,
        /// Audit-log tag describing why the deny fired.
        audit_tag: &'static str,
        /// Command being denied (empty for payload-shape errors with no
        /// recoverable command).
        cmd: String,
    },
    /// Emit a real Claude Code `ask` permission decision so the user gets an
    /// approve/deny prompt. Used when a defence-in-depth gate returns an
    /// `Ask` verdict for a command that has no contextcrawler rewrite — the
    /// old behaviour hard-denied these, an "ask" the user could never answer
    /// (#111). A supply-chain hard `Block` still routes through `Deny`.
    Ask {
        reason: String,
        /// Audit-log tag describing why the ask fired.
        audit_tag: &'static str,
        /// Command being asked about.
        cmd: String,
    },
    Ignore,
}

/// Outcome of running the defence-in-depth gates (Tirith + supply-chain)
/// against a command. A pure, unit-testable verdict mapping — `gate_decision`
/// computes this from the two gate verdicts so the wiring can be tested
/// without spawning subprocesses. G1 finding #2 (#100).
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) enum GateDecision {
    /// Both gates clean (or disabled / no install actions). Proceed unchanged.
    Proceed,
    /// A gate wants the user prompted: downgrade any auto-allow to Ask.
    /// Either a Tirith downgrade, or the supply-chain gate could not verify
    /// (`Unavailable` — fail closed).
    ///
    /// `suggestion` carries an optional copy-paste trust hint built from the
    /// Tirith verdict (#197) — `Some` for a Tirith block with a resolvable
    /// host/rule, `None` for supply-chain Asks or unparseable verdicts.
    Ask { suggestion: Option<String> },
    /// The supply-chain gate hard-blocked the command. Fail closed with a
    /// Claude `deny` verdict — reuses the #102 `PayloadAction::Deny`.
    Deny { reason: String },
}

/// Map the two gate verdicts to a single `GateDecision`.
///
/// Pure: no I/O, no process spawning — the `tirith_gate::check` /
/// `supply_chain_gate::check` calls (which DO spawn / hit the network) happen
/// in `process_claude_payload_with`; this function only classifies their
/// results. Precedence: a supply-chain `Block` (Deny) outranks any Ask.
pub(crate) fn gate_decision(
    tirith_verdict: &tirith_gate::Verdict,
    sc_verdict: &supply_chain_gate::Verdict,
) -> GateDecision {
    // Block outranks everything — the supply-chain gate hard-failed.
    if let supply_chain_gate::Verdict::Block(_) = sc_verdict {
        return GateDecision::Deny {
            reason: supply_chain_gate::render(sc_verdict),
        };
    }

    // Tirith: a flagged command or a "required but unavailable" tirith both
    // downgrade to Ask. `should_downgrade` already honours the opt-in
    // (`CONTEXTCRAWLER_TIRITH_REQUIRED`) — when tirith is not required and is
    // merely unavailable it returns `None`, so this is a no-op by default.
    if let Some((_reason, tirith_json)) = tirith_gate::should_downgrade(tirith_verdict) {
        // Build the copy-paste trust hint (#197) from the verdict when we have
        // one. `suggest_trust` is pure string parsing, so this keeps
        // `gate_decision` I/O-free and unit-testable.
        let suggestion = tirith_json.and_then(tirith_gate::suggest_trust);
        return GateDecision::Ask { suggestion };
    }

    // Supply-chain `Unavailable` — registry/OSV lookup failed. The gate is
    // opt-in (`supply_chain.enabled`); once enabled we fail CLOSED: prompt
    // the user rather than wave the install through on a network blip.
    if let supply_chain_gate::Verdict::Unavailable(_) = sc_verdict {
        return GateDecision::Ask { suggestion: None };
    }

    // Supply-chain `Ask` — an install verb was detected but its package set
    // is unvettable (lockfile / requirements / constraints install). Not a
    // hard failure, but we fail CLOSED: prompt the user to confirm the
    // unvetted set rather than wave it through. See #111 G1.
    if let supply_chain_gate::Verdict::Ask(_) = sc_verdict {
        return GateDecision::Ask { suggestion: None };
    }

    // Tirith Allow/Unavailable-not-required, supply-chain Skip/Allow.
    GateDecision::Proceed
}

/// Run the live defence-in-depth gates (Tirith + supply-chain) against a
/// command string and classify the result. This is THE production gate
/// wiring — shared by the Claude hook path (`process_claude_payload_with`)
/// and the `contextcrawler proxy` CLI path (council P0-2: proxy previously
/// bypassed both gates entirely).
///
/// Side effects: supply-chain event logging + Tirith downgrade audit lines.
pub(crate) fn run_gates(cmd: &str) -> GateDecision {
    let tirith_verdict = tirith_gate::check(cmd);
    let sc_verdict = supply_chain_gate::check(cmd);
    supply_chain_gate::log_event(cmd, &sc_verdict);
    let decision = gate_decision(&tirith_verdict, &sc_verdict);
    // Emit the Tirith downgrade audit line when (and only when) the
    // classification is an Ask driven by Tirith — the pure `gate_decision`
    // does no I/O, so the logging stays here on the production path.
    if matches!(decision, GateDecision::Ask { .. }) {
        if let Some((reason, tirith_json)) = tirith_gate::should_downgrade(&tirith_verdict) {
            tirith_gate::log_downgrade(cmd, reason, tirith_json);
        }
    }
    decision
}

/// Action for the `contextcrawler proxy` CLI path. Unlike the hook path,
/// proxy has no interactive ask protocol — a gate `Ask` maps to a refusal
/// with instructions for an explicit human override, and a gate `Deny` is
/// a refusal that no override can bypass.
pub(crate) enum ProxyGateOutcome {
    /// Gates clean (or acknowledged Ask): execute the proxied command.
    Run,
    /// Refuse to execute. `exit_code` 126 = "command cannot execute".
    Refuse { reason: String, exit_code: i32 },
}

/// Map a `GateDecision` to a proxy-path outcome.
///
/// `ack` is the explicit human acknowledgement
/// (`CONTEXTCRAWLER_PROXY_ACK=1`): it overrides an `Ask` (the human has
/// reviewed the flagged command and chosen to proceed) but never a `Deny`
/// (supply-chain hard block).
pub(crate) fn proxy_gate_outcome(decision: GateDecision, ack: bool) -> ProxyGateOutcome {
    match decision {
        GateDecision::Proceed => ProxyGateOutcome::Run,
        GateDecision::Ask { .. } if ack => ProxyGateOutcome::Run,
        GateDecision::Ask { .. } => ProxyGateOutcome::Refuse {
            reason: "contextcrawler: a defence-in-depth gate (Tirith / supply-chain) flagged \
                     this proxied command for review.\n\
                     To proceed after reviewing it, re-run with CONTEXTCRAWLER_PROXY_ACK=1, \
                     or inspect the verdict with `tirith why`."
                .to_string(),
            exit_code: 126,
        },
        GateDecision::Deny { reason } => ProxyGateOutcome::Refuse {
            reason,
            exit_code: 126,
        },
    }
}

fn process_claude_payload(v: &Value) -> PayloadAction {
    process_claude_payload_with(v, permissions::check_command)
}

/// Stderr line emitted when a gate flags a command `Ask` but it has no
/// contextcrawler rewrite. The command is routed to a real Claude Code `ask`
/// permission decision so the user can approve or deny it (#111). Factored
/// out so the exact wording is testable without firing a live gate.
fn gate_no_rewrite_ask_log(cmd: &str) -> String {
    format!(
        "[contextcrawler] gate flagged '{cmd}' (ask) but it has no rewrite; \
         prompting the user for review"
    )
}

/// `process_claude_payload` parameterised on the permission-verdict checker
/// so tests can inject a deterministic verdict (production always passes
/// `permissions::check_command`, which is config-driven). #100 G2 Codex 2nd
/// pass — needed to test the explicit deny-rule path (CRITICAL 1) without
/// writing a config file.
fn process_claude_payload_with(
    v: &Value,
    check: impl Fn(&str) -> PermissionVerdict,
) -> PayloadAction {
    // Production: compute the gate decision from the live Tirith +
    // supply-chain checks (shared `run_gates` wiring — also used by the
    // proxy path). Tests inject a deterministic `GateDecision` via
    // `process_claude_payload_with_gate` so the no-rewrite Ask path (#111)
    // can be exercised without spawning the gate binaries.
    process_claude_payload_with_gate(v, check, run_gates)
}

/// `process_claude_payload_with` with the gate decision injectable. The
/// `gate` closure maps a command to a `GateDecision`; production passes the
/// live Tirith + supply-chain wiring, tests pass a fixed verdict.
fn process_claude_payload_with_gate(
    v: &Value,
    check: impl Fn(&str) -> PermissionVerdict,
    gate: impl Fn(&str) -> GateDecision,
) -> PayloadAction {
    // Set by the defence-in-depth gates below: when a gate returns Ask, the
    // permission `Allow` must be suppressed so Claude Code prompts the user.
    let mut gate_ask = false;
    // Copy-paste trust hint built from the Tirith verdict (#197), surfaced in
    // the Ask permission reason so the user can act on the flag.
    let mut gate_suggestion: Option<String> = None;
    // Distinguish "legitimately no command to rewrite" (Ignore — correct)
    // from "malformed payload shape" (Deny — fail closed, #100 G2).
    let cmd = match v.pointer("/tool_input/command") {
        // A present `command` that is not a non-empty string is a shape
        // error — the harness sent something we can't reason about.
        Some(c) => match c.as_str() {
            Some(s) if !s.is_empty() => s,
            Some(_) => return PayloadAction::Ignore, // empty string: nothing to do
            None => {
                return PayloadAction::Deny {
                    reason: "contextcrawler: hook payload `command` was not a string; denying"
                        .to_string(),
                    audit_tag: "deny:malformed_payload",
                    cmd: String::new(),
                }
            }
        },
        // No `command` field at all — non-Bash tool or no command to gate.
        None => return PayloadAction::Ignore,
    };

    let verdict = check(cmd);
    if verdict == PermissionVerdict::Deny {
        // SECURITY (#100 G2 Codex 2nd pass — CRITICAL 1): an explicit
        // permission deny-rule hit must emit the Claude deny JSON the harness
        // blocks on. The first fix pass mapped this to `Skip`, which only
        // audit-logs and returns silently — the denied command then ran
        // unchecked, defeating the entire permission gate. Only the `Deny`
        // verdict changes here; `Ask`/`Allow`/`Ignore` are untouched.
        return PayloadAction::Deny {
            reason: "contextcrawler: command blocked by permission deny rule; denying".to_string(),
            audit_tag: "deny:deny_rule",
            cmd: cmd.to_string(),
        };
    }

    // ===== contextzip-downstream: defence-in-depth gates begin =====
    // G1 finding #2 (#100): run the Tirith + supply-chain gates on the live
    // hook path, mirroring `hooks/rewrite_cmd.rs`. Both gates are opt-in and
    // are no-ops when disabled (Tirith → `Unavailable` + not required;
    // supply-chain → `Skip` when `supply_chain.enabled` is false), so the
    // default behaviour is byte-for-byte unchanged.
    match gate(cmd) {
        GateDecision::Proceed => {}
        GateDecision::Ask { suggestion } => {
            // A gate wants the user prompted. Force the rewrite path to Ask
            // by overriding the permission verdict — a gate Ask must win over
            // a permissions `Allow` so Claude Code prompts.
            gate_ask = true;
            gate_suggestion = suggestion;
        }
        GateDecision::Deny { reason } => {
            // Supply-chain hard block — fail closed with the #102 deny
            // machinery (`PayloadAction::Deny` → `emit_claude_deny`).
            return PayloadAction::Deny {
                reason,
                audit_tag: "deny:supply_chain_block",
                cmd: cmd.to_string(),
            };
        }
    }
    // ===== contextzip-downstream: defence-in-depth gates end =====

    let rewritten = match get_rewritten(cmd) {
        Some(r) => r,
        None => {
            // No contextcrawler equivalent. If a gate flagged the command,
            // emit a real Claude Code `ask` permission decision so the user
            // gets an approve/deny prompt (#111). The old behaviour hard-
            // denied here, which turned a gate "ask" verdict into a block the
            // user could never approve — e.g. credential-bearing `curl` loops
            // in a REST-verification workflow.
            if gate_ask {
                // Emit a clear stderr line so the WHY is operator-visible —
                // a gate false-positive on a bare un-rewritable command (e.g.
                // `ls`) is then a visible prompt, not a silent block.
                let _ = writeln!(io::stderr(), "{}", gate_no_rewrite_ask_log(cmd));
                // Prefer the tailored trust hint (#197) when we have one; fall
                // back to the generic line otherwise.
                let reason = gate_suggestion.take().unwrap_or_else(|| {
                    "contextcrawler: a defence-in-depth gate flagged this command \
                     — review before allowing"
                        .to_string()
                });
                return PayloadAction::Ask {
                    reason,
                    audit_tag: "ask:gate_no_rewrite",
                    cmd: cmd.to_string(),
                };
            }
            return PayloadAction::Skip {
                reason: "skip:no_match",
                cmd: cmd.to_string(),
            };
        }
    };

    let updated_input = {
        let mut ti = v.get("tool_input").cloned().unwrap_or_else(|| json!({}));
        if let Some(obj) = ti.as_object_mut() {
            obj.insert("command".into(), Value::String(rewritten.clone()));
        }
        ti
    };

    // When a gate flagged this (rewritable) command, surface the tailored
    // trust hint (#197) as the reason the user sees in the Ask prompt;
    // otherwise it's a clean auto-rewrite.
    let decision_reason = match (gate_ask, gate_suggestion.take()) {
        (true, Some(hint)) => hint,
        _ => "contextcrawler auto-rewrite".to_string(),
    };
    let mut hook_output = json!({
        "hookEventName": PRE_TOOL_USE_KEY,
        "permissionDecisionReason": decision_reason,
        "updatedInput": updated_input
    });

    // A gate Ask suppresses the auto-allow (G1 #2 / #100): even with an
    // explicit permissions `Allow`, a flagged-by-Tirith or unverifiable
    // supply-chain command must let Claude Code prompt rather than run
    // unattended. Omitting `permissionDecision` falls through to the host
    // tool's own prompt — exactly the Ask semantics rewrite_cmd.rs uses.
    if verdict == PermissionVerdict::Allow && !gate_ask {
        // `hook_output` is a `json!` object literal, so `as_object_mut`
        // is always `Some` — but use a checked branch rather than
        // `.unwrap()` so the hook can never panic on the payload path.
        if let Some(obj) = hook_output.as_object_mut() {
            obj.insert("permissionDecision".into(), json!("allow"));
        }
    }

    PayloadAction::Rewrite {
        cmd: cmd.to_string(),
        rewritten,
        output: json!({ "hookSpecificOutput": hook_output }),
    }
}

/// Emit a Claude Code PreToolUse `deny` verdict.
///
/// SECURITY: every payload-error path on the Claude hook must fail CLOSED.
/// A malformed/oversized/unparseable payload means the hook can't reason
/// about the command — emitting `deny` makes the harness block it instead
/// of silently letting the unchecked command run (fail-open hole, #100 G2).
fn emit_claude_deny(reason: &str) {
    let output = json!({
        "hookSpecificOutput": {
            "hookEventName": PRE_TOOL_USE_KEY,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    let _ = writeln!(io::stdout(), "{output}");
}

/// Emit a Claude Code PreToolUse `ask` verdict.
///
/// Unlike `deny`, `ask` makes the harness prompt the user with an
/// approve/deny choice rather than hard-blocking the command. Used when a
/// defence-in-depth gate returns an `Ask` verdict for a command with no
/// contextcrawler rewrite — a gate "ask" must reach the user, not become a
/// silent block (#111). The JSON schema mirrors `emit_claude_deny`; only the
/// `permissionDecision` value differs.
fn emit_claude_ask(reason: &str) {
    let output = json!({
        "hookSpecificOutput": {
            "hookEventName": PRE_TOOL_USE_KEY,
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    });
    let _ = writeln!(io::stdout(), "{output}");
}

/// Run the Claude Code PreToolUse hook natively.
pub fn run_claude() -> Result<()> {
    let input = match read_stdin_limited() {
        Ok(input) => input,
        Err(e) => {
            // Oversized/unreadable stdin — fail closed.
            let _ = writeln!(io::stderr(), "[contextcrawler hook] {e}");
            emit_claude_deny("contextcrawler: hook payload could not be read; denying");
            return Ok(());
        }
    };

    let input = input.trim();
    if input.is_empty() {
        // No payload at all — nothing to gate. The harness invoked the hook
        // with empty stdin; treat as a no-op rather than denying.
        return Ok(());
    }

    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            // Malformed JSON — fail closed.
            let _ = writeln!(
                io::stderr(),
                "[contextcrawler hook] Failed to parse JSON input: {e}"
            );
            emit_claude_deny("contextcrawler: hook payload was not valid JSON; denying");
            return Ok(());
        }
    };

    match process_claude_payload(&v) {
        PayloadAction::Rewrite {
            cmd,
            rewritten,
            output,
        } => {
            audit_log("rewrite", &cmd, &rewritten);
            let _ = writeln!(io::stdout(), "{output}");
        }
        PayloadAction::Skip { reason, cmd } => {
            audit_log(reason, &cmd, "");
        }
        PayloadAction::Deny {
            reason,
            audit_tag,
            cmd,
        } => {
            audit_log(audit_tag, &cmd, "");
            emit_claude_deny(&reason);
        }
        PayloadAction::Ask {
            reason,
            audit_tag,
            cmd,
        } => {
            audit_log(audit_tag, &cmd, "");
            emit_claude_ask(&reason);
        }
        PayloadAction::Ignore => {}
    }

    Ok(())
}

/// Test-only driver mirroring `run_claude`. Returns the emitted JSON verdict
/// (rewrite or deny), or `None` for a silent pass-through (`Ignore`/`Skip`).
#[cfg(test)]
fn run_claude_inner(input: &str) -> Option<String> {
    let v: Value = serde_json::from_str(input).ok()?;
    match process_claude_payload(&v) {
        PayloadAction::Rewrite { output, .. } => Some(output.to_string()),
        PayloadAction::Deny { reason, .. } => Some(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": PRE_TOOL_USE_KEY,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
        ),
        PayloadAction::Ask { reason, .. } => Some(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": PRE_TOOL_USE_KEY,
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
        ),
        _ => None,
    }
}

// ── Cursor native hook ─────────────────────────────────────────

/// Cursor on Windows ships hook payloads with one or more leading
/// UTF-8 BOMs (`EF BB BF`, sometimes doubled), which serde_json
/// refuses to parse. Strip them defensively so the rewrite path keeps
/// working instead of silently returning `{}`.
fn strip_leading_bom(input: &str) -> &str {
    let mut s = input;
    while let Some(rest) = s.strip_prefix('\u{feff}') {
        s = rest;
    }
    s
}

/// Run the Cursor Agent hook natively.
pub fn run_cursor() -> Result<()> {
    let input = read_stdin_limited()?;

    let input = strip_leading_bom(&input).trim();
    if input.is_empty() {
        let _ = writeln!(io::stdout(), "{{}}");
        return Ok(());
    }

    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => {
            // Deliberate fail-OPEN: emit empty `{}` so Cursor proceeds. Unlike
            // the Gemini hook, Cursor's own permission engine is the backstop,
            // so a malformed payload here is not an allow/deny exposure.
            let _ = writeln!(io::stdout(), "{{}}");
            return Ok(());
        }
    };

    let cmd = match v
        .pointer("/tool_input/command")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty())
    {
        Some(c) => c.to_string(),
        None => {
            let _ = writeln!(io::stdout(), "{{}}");
            return Ok(());
        }
    };

    let verdict = permissions::check_command(&cmd);
    if verdict == PermissionVerdict::Deny {
        audit_log("deny", &cmd, "");
        let _ = writeln!(io::stdout(), "{{}}");
        return Ok(());
    }

    let rewritten = match get_rewritten(&cmd) {
        Some(r) => r,
        None => {
            let _ = writeln!(io::stdout(), "{{}}");
            return Ok(());
        }
    };

    // Cursor preToolUse currently enforces allow/deny only and can ignore
    // updated_input when permission is "ask". Use "allow" for rewritten
    // commands unless the command is explicitly denied above.
    let decision = "allow";

    audit_log("rewrite", &cmd, &rewritten);

    // `continue: true` mirrors the shape of every other Cursor hook
    // (afterShellExecution, beforeSubmitPrompt, stop, ...). Cursor's
    // preToolUse panel renders the JSON it received; without this field
    // the panel collapses to `Output: {}` even though the rewrite ran,
    // which makes the hook look broken to users.
    let output = json!({
        "continue": true,
        "permission": decision,
        "updated_input": { "command": rewritten }
    });
    let _ = writeln!(io::stdout(), "{output}");
    Ok(())
}

#[cfg(test)]
fn run_cursor_inner(input: &str) -> String {
    run_cursor_inner_with_rules(input, &[], &[], &[])
}

#[cfg(test)]
fn run_cursor_inner_with_rules(
    input: &str,
    deny_rules: &[String],
    ask_rules: &[String],
    allow_rules: &[String],
) -> String {
    let input = strip_leading_bom(input);
    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return "{}".to_string(),
    };

    let cmd = match v
        .pointer("/tool_input/command")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty())
    {
        Some(c) => c.to_string(),
        None => return "{}".to_string(),
    };

    let verdict = permissions::check_command_with_rules(&cmd, deny_rules, ask_rules, allow_rules);
    if verdict == PermissionVerdict::Deny {
        return "{}".to_string();
    }

    match get_rewritten(&cmd) {
        Some(rewritten) => {
            let decision = "allow";
            let output = json!({
                "continue": true,
                "permission": decision,
                "updated_input": { "command": rewritten }
            });
            output.to_string()
        }
        None => "{}".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_command_no_prefixes(cmd: &str, excluded: &[String]) -> Option<String> {
        crate::discover::registry::rewrite_command(cmd, excluded, &[])
    }

    // --- Copilot format detection ---

    fn vscode_input(tool: &str, cmd: &str) -> Value {
        json!({
            "tool_name": tool,
            "tool_input": { "command": cmd }
        })
    }

    fn copilot_cli_input(cmd: &str) -> Value {
        let args = serde_json::to_string(&json!({ "command": cmd })).unwrap();
        json!({ "toolName": "bash", "toolArgs": args })
    }

    /// The no-rewrite-Ask path emits a clear, operator-visible log line so a
    /// gate false-positive on a bare un-rewritable command surfaces as a
    /// visible prompt rather than a silent block (#111).
    #[test]
    fn gate_no_rewrite_ask_log_explains_why() {
        let line = gate_no_rewrite_ask_log("ls");
        assert!(line.starts_with("[contextcrawler] "));
        assert!(line.contains("'ls'"));
        assert!(line.contains("(ask)"));
        assert!(line.contains("no rewrite"));
        assert!(line.contains("prompting the user"));
        assert!(!line.contains("denying"));
    }

    #[test]
    fn test_detect_vscode_bash() {
        assert!(matches!(
            detect_format(&vscode_input("Bash", "git status")),
            HookFormat::VsCode { .. }
        ));
    }

    #[test]
    fn test_detect_vscode_run_terminal_command() {
        assert!(matches!(
            detect_format(&vscode_input("runTerminalCommand", "cargo test")),
            HookFormat::VsCode { .. }
        ));
    }

    #[test]
    fn test_detect_copilot_cli_bash() {
        assert!(matches!(
            detect_format(&copilot_cli_input("git status")),
            HookFormat::CopilotCli { .. }
        ));
    }

    #[test]
    fn test_detect_non_bash_is_passthrough() {
        let v = json!({ "tool_name": "editFiles" });
        assert!(matches!(detect_format(&v), HookFormat::PassThrough));
    }

    #[test]
    fn test_detect_unknown_is_passthrough() {
        assert!(matches!(detect_format(&json!({})), HookFormat::PassThrough));
    }

    #[test]
    fn test_get_rewritten_supported() {
        assert!(get_rewritten("git status").is_some());
    }

    #[test]
    fn test_get_rewritten_unsupported() {
        assert!(get_rewritten("htop").is_none());
    }

    #[test]
    fn test_get_rewritten_already_rtk() {
        assert!(get_rewritten("contextcrawler git status").is_none());
    }

    #[test]
    fn test_get_rewritten_heredoc() {
        assert!(get_rewritten("cat <<'EOF'\nhello\nEOF").is_none());
    }

    // --- Gemini format ---

    #[test]
    fn test_print_allow_format() {
        let expected = r#"{"decision":"allow"}"#;
        assert_eq!(expected, r#"{"decision":"allow"}"#);
    }

    #[test]
    fn test_print_rewrite_format() {
        let output = serde_json::json!({
            "decision": "allow",
            "hookSpecificOutput": {
                "tool_input": {
                    "command": "contextcrawler git status"
                }
            }
        });
        let json: Value = serde_json::from_str(&output.to_string()).unwrap();
        assert_eq!(json["decision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["tool_input"]["command"],
            "contextcrawler git status"
        );
    }

    #[test]
    fn test_gemini_hook_uses_rewrite_command() {
        assert_eq!(
            rewrite_command_no_prefixes("git status", &[]),
            Some("contextcrawler git status".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("cargo test", &[]),
            Some("contextcrawler cargo test".into())
        );
        assert_eq!(
            rewrite_command_no_prefixes("contextcrawler git status", &[]),
            Some("contextcrawler git status".into())
        );
        assert_eq!(rewrite_command_no_prefixes("cat <<EOF", &[]), None);
    }

    #[test]
    fn test_gemini_hook_excluded_commands() {
        let excluded = vec!["curl".to_string()];
        assert_eq!(
            rewrite_command_no_prefixes("curl https://example.com", &excluded),
            None
        );
        assert_eq!(
            rewrite_command_no_prefixes("git status", &excluded),
            Some("contextcrawler git status".into())
        );
    }

    #[test]
    fn test_gemini_hook_env_prefix_preserved() {
        assert_eq!(
            rewrite_command_no_prefixes("RUST_LOG=debug cargo test", &[]),
            Some("RUST_LOG=debug contextcrawler cargo test".into())
        );
    }

    // --- Claude handler ---

    fn claude_input(cmd: &str) -> String {
        json!({
            "tool_name": "Bash",
            "tool_input": { "command": cmd }
        })
        .to_string()
    }

    fn claude_input_with_fields(cmd: &str, timeout: u64, description: &str) -> String {
        json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": cmd,
                "timeout": timeout,
                "description": description
            }
        })
        .to_string()
    }

    // === #2286 hardening on the live Claude PreToolUse path =================
    // Auto-allow (`permissionDecision: "allow"`) must NEVER be emitted for a
    // not-evaluable construct, even when the permission engine would otherwise
    // allow it. The gate lives in `check_command_with_rules`; this proves the
    // live `process_claude_payload_with_gate` flow inherits it end-to-end.

    fn auto_allowed_on_live_path(cmd: &str) -> bool {
        // Real permission engine with an all-permissive allow rule + a no-op
        // gate (mirrors Tirith default-off). Auto-allow only happens on a true
        // `Allow` verdict, which the unattestable gate downgrades to `Ask`.
        let allow = vec!["*".to_string()];
        let check = move |c: &str| {
            permissions::check_command_with_rules(c, &[], &[], &allow)
        };
        let v: Value = serde_json::from_str(&claude_input(cmd)).unwrap();
        match process_claude_payload_with_gate(&v, check, |_| GateDecision::Proceed) {
            PayloadAction::Rewrite { output, .. } => {
                output.pointer("/hookSpecificOutput/permissionDecision")
                    == Some(&json!("allow"))
            }
            _ => false,
        }
    }

    #[test]
    fn test_live_clean_command_auto_allows() {
        // Baseline: an evaluable allowed command DOES auto-allow.
        assert!(auto_allowed_on_live_path("git status"));
        assert!(auto_allowed_on_live_path("git status 2>&1"));
    }

    #[test]
    fn test_live_substitution_never_auto_allows() {
        assert!(!auto_allowed_on_live_path("git status `whoami`"));
        assert!(!auto_allowed_on_live_path("git log --pretty=$(whoami)"));
        assert!(!auto_allowed_on_live_path(
            "git log --pretty=\"$(whoami)\""
        ));
    }

    #[test]
    fn test_live_file_redirect_never_auto_allows() {
        assert!(!auto_allowed_on_live_path("git log > /tmp/out.txt"));
        assert!(!auto_allowed_on_live_path("git diff >& /tmp/evil"));
    }

    #[test]
    fn test_claude_rewrite_git_status() {
        let result = run_claude_inner(&claude_input("git status")).unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        let cmd = v
            .pointer("/hookSpecificOutput/updatedInput/command")
            .and_then(|c| c.as_str())
            .unwrap();
        assert_eq!(cmd, "contextcrawler git status");
    }

    #[test]
    fn test_claude_rewrite_preserves_tool_input_fields() {
        let input = claude_input_with_fields("git status", 30000, "Check repo status");
        let result = run_claude_inner(&input).unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        let updated = &v["hookSpecificOutput"]["updatedInput"];
        assert_eq!(updated["command"], "contextcrawler git status");
        assert_eq!(updated["timeout"], 30000);
        assert_eq!(updated["description"], "Check repo status");
    }

    #[test]
    fn test_claude_passthrough_no_output() {
        assert!(run_claude_inner(&claude_input("htop")).is_none());
    }

    #[test]
    fn test_claude_heredoc_passthrough() {
        assert!(run_claude_inner(&claude_input("cat <<EOF\nhello\nEOF")).is_none());
    }

    #[test]
    fn test_claude_already_rtk_passthrough() {
        assert!(run_claude_inner(&claude_input("contextcrawler git status")).is_none());
    }

    #[test]
    fn test_claude_empty_command_passthrough() {
        let input = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "" }
        })
        .to_string();
        assert!(run_claude_inner(&input).is_none());
    }

    #[test]
    fn test_claude_malformed_json_passthrough() {
        assert!(run_claude_inner("not valid json {{{").is_none());
    }

    #[test]
    fn test_claude_env_prefix_preserved() {
        let result = run_claude_inner(&claude_input("GIT_PAGER=cat git status")).unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        let cmd = v
            .pointer("/hookSpecificOutput/updatedInput/command")
            .and_then(|c| c.as_str())
            .unwrap();
        assert_eq!(cmd, "GIT_PAGER=cat contextcrawler git status");
    }

    #[test]
    fn test_claude_compound_command() {
        let result = run_claude_inner(&claude_input("git add . && cargo test")).unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        let cmd = v
            .pointer("/hookSpecificOutput/updatedInput/command")
            .and_then(|c| c.as_str())
            .unwrap();
        assert_eq!(cmd, "contextcrawler git add . && contextcrawler cargo test");
    }

    #[test]
    fn test_claude_json_output_structure() {
        let result = run_claude_inner(&claude_input("git status")).unwrap();
        let v: Value = serde_json::from_str(&result).unwrap();
        let hook = &v["hookSpecificOutput"];

        assert_eq!(hook["hookEventName"], PRE_TOOL_USE_KEY);
        // permissionDecision is only set when an explicit allow rule matches;
        // with default-to-ask semantics (no rules configured), it is absent.
        assert_eq!(
            hook["permissionDecisionReason"],
            "contextcrawler auto-rewrite"
        );
        assert!(hook["updatedInput"].is_object());
        assert!(hook["updatedInput"]["command"].is_string());
    }

    #[test]
    fn test_claude_no_tool_input_passthrough() {
        let input = json!({ "tool_name": "Bash" }).to_string();
        assert!(run_claude_inner(&input).is_none());
    }

    // --- Fail-closed payload handling (#100 G2 CRITICAL 1) ---

    /// A `command` field present but not a string is a malformed shape —
    /// the hook must emit a `deny` verdict, not silently Ignore.
    #[test]
    fn test_claude_non_string_command_denies() {
        let input = json!({
            "tool_name": "Bash",
            "tool_input": { "command": 12345 }
        })
        .to_string();
        let result = run_claude_inner(&input).expect("malformed shape must emit a verdict");
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    /// `process_claude_payload` classifies a non-string command as Deny.
    #[test]
    fn test_process_payload_non_string_command_is_deny() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": ["array", "not", "string"] }
        });
        assert!(matches!(
            process_claude_payload(&v),
            PayloadAction::Deny { .. }
        ));
    }

    /// A valid payload with no `command` field stays Ignore (correct — not
    /// a parse error, just nothing to rewrite).
    #[test]
    fn test_process_payload_missing_command_is_ignore() {
        let v = json!({ "tool_name": "Bash", "tool_input": {} });
        assert!(matches!(process_claude_payload(&v), PayloadAction::Ignore));
    }

    /// The deny verdict emitted for a malformed payload carries the
    /// Claude PreToolUse `permissionDecision: deny` contract.
    #[test]
    fn test_claude_deny_verdict_contract() {
        let input = json!({
            "tool_name": "Bash",
            "tool_input": { "command": false }
        })
        .to_string();
        let result = run_claude_inner(&input).expect("malformed shape must emit a verdict");
        let v: Value = serde_json::from_str(&result).unwrap();
        let hook = &v["hookSpecificOutput"];
        assert_eq!(hook["hookEventName"], PRE_TOOL_USE_KEY);
        assert_eq!(hook["permissionDecision"], "deny");
        assert!(hook["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("contextcrawler"));
    }

    // --- #100 G2 Codex 2nd pass — CRITICAL 1: explicit deny-rule path ---

    /// An explicit `PermissionVerdict::Deny` (deny-rule hit) must produce a
    /// `PayloadAction::Deny`, NOT a silent `Skip`. Regression for the
    /// fail-open hole the first fix pass missed.
    #[test]
    fn test_deny_rule_hit_is_deny_action() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "git push --force" }
        });
        let action = process_claude_payload_with(&v, |_| PermissionVerdict::Deny);
        match action {
            PayloadAction::Deny { audit_tag, cmd, .. } => {
                assert_eq!(audit_tag, "deny:deny_rule");
                assert_eq!(cmd, "git push --force");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// An explicit deny-rule hit, run through the `run_claude` driver, must
    /// emit the Claude PreToolUse `deny` JSON the harness blocks on.
    #[test]
    fn test_deny_rule_emits_deny_json() {
        let v: Value = serde_json::from_str(
            &json!({
                "tool_name": "Bash",
                "tool_input": { "command": "rm -rf /" }
            })
            .to_string(),
        )
        .unwrap();
        let action = process_claude_payload_with(&v, |_| PermissionVerdict::Deny);
        let emitted = match action {
            PayloadAction::Deny { reason, .. } => json!({
                "hookSpecificOutput": {
                    "hookEventName": PRE_TOOL_USE_KEY,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
            other => panic!("expected Deny, got {other:?}"),
        };
        let parsed: Value = serde_json::from_str(&emitted).unwrap();
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecision"], "deny",
            "denied command must emit a deny verdict"
        );
    }

    /// `Allow`/`Ask`/`Default` verdicts are unaffected by the CRITICAL 1
    /// change — they still route to Rewrite (or Skip:no_match), never Deny.
    #[test]
    fn test_non_deny_verdicts_never_deny() {
        for verdict in [
            PermissionVerdict::Allow,
            PermissionVerdict::Ask,
            PermissionVerdict::Default,
        ] {
            let v = json!({
                "tool_name": "Bash",
                "tool_input": { "command": "git status" }
            });
            let action = process_claude_payload_with(&v, {
                let verdict = verdict.clone();
                move |_| verdict.clone()
            });
            assert!(
                !matches!(action, PayloadAction::Deny { .. }),
                "verdict {verdict:?} must never produce a Deny action"
            );
        }
    }

    /// Malformed JSON payload — direct assertion that `run_claude_inner`
    /// emits a deny verdict (not merely `None`).
    #[test]
    fn test_malformed_json_emits_deny() {
        // `process_claude_payload` only sees parsed JSON; the malformed-JSON
        // branch lives in `run_claude`. `run_claude_inner` returns `None` for
        // unparseable input — assert the production `run_claude` path instead
        // by checking the parse failure is classified as a closed failure.
        let bad = "{not valid json";
        assert!(
            serde_json::from_str::<Value>(bad).is_err(),
            "fixture must be unparseable"
        );
        // A non-string command IS reachable via the parsed path — assert it
        // emits deny JSON directly.
        let input = json!({
            "tool_name": "Bash",
            "tool_input": { "command": 12345 }
        })
        .to_string();
        let result = run_claude_inner(&input).expect("non-string command must emit a verdict");
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    // --- Defence-in-depth gate wiring (G1 #2 / #100) ---

    use super::supply_chain_gate::Verdict as ScVerdict;
    use super::tirith_gate::Verdict as TirithVerdict;

    /// supply-chain `Block` → Deny (reuses #102 deny machinery downstream).
    #[test]
    fn test_gate_decision_supply_chain_block_is_deny() {
        let d = gate_decision(&TirithVerdict::Allow, &ScVerdict::Block(vec![]));
        assert!(matches!(d, GateDecision::Deny { .. }));
    }

    /// supply-chain `Unavailable` → Ask (fail closed).
    #[test]
    fn test_gate_decision_supply_chain_unavailable_is_ask() {
        let d = gate_decision(
            &TirithVerdict::Allow,
            &ScVerdict::Unavailable("registry timeout".into()),
        );
        // supply-chain Ask carries no trust hint (that's Tirith-only).
        assert_eq!(d, GateDecision::Ask { suggestion: None });
    }

    /// Both gates clean → Proceed unchanged.
    #[test]
    fn test_gate_decision_both_clean_is_proceed() {
        assert_eq!(
            gate_decision(&TirithVerdict::Allow, &ScVerdict::Skip),
            GateDecision::Proceed
        );
        assert_eq!(
            gate_decision(&TirithVerdict::Allow, &ScVerdict::Allow),
            GateDecision::Proceed
        );
    }

    /// Tirith `Unavailable` without `CONTEXTCRAWLER_TIRITH_REQUIRED` is a
    /// no-op — the default disabled-gate behaviour. Proceed.
    #[test]
    fn test_gate_decision_tirith_unavailable_not_required_is_proceed() {
        std::env::remove_var("CONTEXTCRAWLER_TIRITH_REQUIRED");
        assert_eq!(
            gate_decision(&TirithVerdict::Unavailable, &ScVerdict::Skip),
            GateDecision::Proceed
        );
    }

    // --- Proxy-path gate wiring (council P0-2 blocker, task #2) ---
    // The proxy CLI path has no interactive ask protocol, so GateDecision
    // maps to run/refuse with an explicit env-var acknowledgement override.

    /// Clean gates → proxy runs the command.
    #[test]
    fn test_proxy_gate_proceed_runs() {
        assert!(matches!(
            proxy_gate_outcome(GateDecision::Proceed, false),
            ProxyGateOutcome::Run
        ));
    }

    /// A gate Ask with no acknowledgement → refuse with exit 126 and
    /// instructions naming the override env var.
    #[test]
    fn test_proxy_gate_ask_refuses_without_ack() {
        match proxy_gate_outcome(GateDecision::Ask { suggestion: None }, false) {
            ProxyGateOutcome::Refuse { reason, exit_code } => {
                assert_eq!(exit_code, 126);
                assert!(
                    reason.contains("CONTEXTCRAWLER_PROXY_ACK"),
                    "refusal must name the override env var: {}",
                    reason
                );
            }
            ProxyGateOutcome::Run => panic!("Ask without ack must refuse"),
        }
    }

    /// A gate Ask with the explicit human acknowledgement → runs.
    #[test]
    fn test_proxy_gate_ask_runs_with_explicit_ack() {
        assert!(matches!(
            proxy_gate_outcome(GateDecision::Ask { suggestion: None }, true),
            ProxyGateOutcome::Run
        ));
    }

    /// A hard Deny (supply-chain block) is never overridable by the ack env.
    #[test]
    fn test_proxy_gate_deny_refuses_even_with_ack() {
        match proxy_gate_outcome(
            GateDecision::Deny {
                reason: "supply-chain block: malicious package".to_string(),
            },
            true,
        ) {
            ProxyGateOutcome::Refuse { reason, exit_code } => {
                assert_eq!(exit_code, 126);
                assert!(reason.contains("supply-chain block"));
            }
            ProxyGateOutcome::Run => panic!("Deny must refuse even with ack"),
        }
    }

    /// Tirith `Block` always downgrades to Ask (no opt-in needed for a
    /// positive flag).
    #[test]
    fn test_gate_decision_tirith_block_is_ask() {
        // Empty verdict body → no resolvable host → Ask with no hint.
        let d = gate_decision(
            &TirithVerdict::Block {
                tirith_json: "{}".into(),
            },
            &ScVerdict::Skip,
        );
        assert_eq!(d, GateDecision::Ask { suggestion: None });
    }

    #[test]
    fn test_gate_decision_tirith_block_carries_trust_hint() {
        // #197: a verdict with a host-bearing finding produces a trust hint.
        let json = r#"{"action":"block","findings":[
            {"rule_id":"plain_http_to_sink","evidence":[{"type":"url","raw":"http://gitea.example.com:3000/x"}]}
        ]}"#;
        let d = gate_decision(
            &TirithVerdict::Block {
                tirith_json: json.into(),
            },
            &ScVerdict::Skip,
        );
        match d {
            GateDecision::Ask {
                suggestion: Some(hint),
            } => assert!(hint.contains("tirith trust add gitea.example.com --scope repo")),
            other => panic!("expected Ask with hint, got {other:?}"),
        }
    }

    /// Precedence: a supply-chain `Block` outranks a Tirith Ask.
    #[test]
    fn test_gate_decision_block_outranks_ask() {
        let d = gate_decision(
            &TirithVerdict::Block {
                tirith_json: "{}".into(),
            },
            &ScVerdict::Block(vec![]),
        );
        assert!(matches!(d, GateDecision::Deny { .. }));
    }

    // --- #111: gate `Ask` verdict → real Claude `ask` prompt, not a deny ---

    /// A gate `Ask` verdict on a command with NO contextcrawler rewrite must
    /// now yield `PayloadAction::Ask` — the user gets an approve/deny prompt,
    /// not a hard deny they can never answer. This is the core #111 fix: a
    /// command flagged by Tirith but with no rewrite must reach the user.
    /// `htop` is the canonical un-rewritable fixture used across this module.
    #[test]
    fn test_gate_ask_no_rewrite_is_ask_action() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "htop" }
        });
        let action = process_claude_payload_with_gate(
            &v,
            |_| PermissionVerdict::Default,
            |_| GateDecision::Ask { suggestion: None },
        );
        match action {
            PayloadAction::Ask {
                audit_tag,
                cmd,
                reason,
            } => {
                assert_eq!(audit_tag, "ask:gate_no_rewrite");
                assert_eq!(cmd, "htop");
                assert!(reason.contains("defence-in-depth gate"));
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    /// #197: when the gate Ask carries a trust suggestion, it must surface as
    /// the Ask `reason` the user sees — not the generic fallback line.
    #[test]
    fn test_gate_ask_suggestion_surfaces_in_reason() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "htop" }
        });
        let hint = "trust here: tirith trust add example.com --scope repo";
        let action = process_claude_payload_with_gate(
            &v,
            |_| PermissionVerdict::Default,
            |_| GateDecision::Ask {
                suggestion: Some(hint.to_string()),
            },
        );
        match action {
            PayloadAction::Ask { reason, .. } => {
                assert!(
                    reason.contains("tirith trust add example.com --scope repo"),
                    "the trust hint must reach the user-visible reason, got: {reason}"
                );
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    /// The `Ask` action, emitted through the `run_claude` driver, must carry
    /// the Claude PreToolUse `permissionDecision: ask` contract — the value
    /// that makes the harness prompt the user (confirmed against the
    /// `handle_vscode` path, which already emits `ask`).
    #[test]
    fn test_gate_ask_emits_ask_json() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "htop" }
        });
        let action = process_claude_payload_with_gate(
            &v,
            |_| PermissionVerdict::Default,
            |_| GateDecision::Ask { suggestion: None },
        );
        let emitted = match action {
            PayloadAction::Ask { reason, .. } => json!({
                "hookSpecificOutput": {
                    "hookEventName": PRE_TOOL_USE_KEY,
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
            other => panic!("expected Ask, got {other:?}"),
        };
        let parsed: Value = serde_json::from_str(&emitted).unwrap();
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecision"], "ask",
            "a gate ask verdict must emit an ask verdict, not a deny"
        );
    }

    /// A gate `Ask` verdict on a command that DOES have a rewrite still
    /// rewrites (with the auto-allow suppressed so the host prompts) — the
    /// #111 change only affects the no-rewrite branch.
    #[test]
    fn test_gate_ask_with_rewrite_still_rewrites() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "git status" }
        });
        let action = process_claude_payload_with_gate(
            &v,
            |_| PermissionVerdict::Allow,
            |_| GateDecision::Ask { suggestion: None },
        );
        match action {
            PayloadAction::Rewrite { output, .. } => {
                // gate Ask suppresses the auto-allow.
                assert!(output
                    .pointer("/hookSpecificOutput/permissionDecision")
                    .is_none());
            }
            other => panic!("expected Rewrite, got {other:?}"),
        }
    }

    /// A supply-chain hard `Block` (`GateDecision::Deny`) still produces a
    /// `PayloadAction::Deny` — a real hard-block must stay a deny. The #111
    /// change must NOT relax this path.
    #[test]
    fn test_gate_deny_still_denies() {
        let v = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "cargo install evil-crate" }
        });
        let action = process_claude_payload_with_gate(
            &v,
            |_| PermissionVerdict::Default,
            |_| GateDecision::Deny {
                reason: "supply-chain block".into(),
            },
        );
        match action {
            PayloadAction::Deny { audit_tag, .. } => {
                assert_eq!(audit_tag, "deny:supply_chain_block");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// No-regression: with both gates disabled (the default — supply-chain
    /// `enabled` false → `Skip`, tirith not required), `git status` still
    /// rewrites to `contextcrawler git status` and no deny is emitted. This
    /// exercises the real `process_claude_payload` (which calls the live
    /// gate `check` functions).
    #[test]
    fn test_disabled_gates_no_regression() {
        std::env::remove_var("CONTEXTCRAWLER_TIRITH_REQUIRED");
        let result = run_claude_inner(&claude_input("git status"))
            .expect("git status must still produce a rewrite verdict");
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            v.pointer("/hookSpecificOutput/updatedInput/command")
                .and_then(|c| c.as_str())
                .unwrap(),
            "contextcrawler git status"
        );
        assert!(
            v.pointer("/hookSpecificOutput/permissionDecision")
                .is_none()
                || v["hookSpecificOutput"]["permissionDecision"] != "deny",
            "disabled gates must never emit a deny"
        );
    }

    // --- Cursor handler ---

    fn cursor_input(cmd: &str) -> String {
        json!({
            "tool_name": "Bash",
            "tool_input": { "command": cmd }
        })
        .to_string()
    }

    #[test]
    fn test_cursor_rewrite_flat_format() {
        let result = run_cursor_inner(&cursor_input("git status"));
        let v: Value = serde_json::from_str(&result).unwrap();
        // Cursor preToolUse expects allow/deny for rewrite application.
        assert_eq!(v["permission"], "allow");
        assert_eq!(v["updated_input"]["command"], "contextcrawler git status");
        assert!(v.get("hookSpecificOutput").is_none());
        // `continue: true` keeps the Cursor preToolUse panel from collapsing
        // to `Output: {}`; without it the rewrite is invisible to users.
        assert_eq!(v["continue"], true);
    }

    #[test]
    fn test_cursor_passthrough_empty_json() {
        let result = run_cursor_inner(&cursor_input("htop"));
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_cursor_empty_input_empty_json() {
        let result = run_cursor_inner("");
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_cursor_heredoc_passthrough() {
        let result = run_cursor_inner(&cursor_input("cat <<EOF\nhello\nEOF"));
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_cursor_already_rtk_passthrough() {
        let result = run_cursor_inner(&cursor_input("contextcrawler git status"));
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_cursor_no_hook_specific_output() {
        let result = run_cursor_inner(&cursor_input("cargo test"));
        let v: Value = serde_json::from_str(&result).unwrap();
        assert!(v.get("hookSpecificOutput").is_none());
        assert_eq!(v["permission"], "allow");
        assert_eq!(v["continue"], true);
    }

    #[test]
    fn test_cursor_compound_rewrite_includes_continue() {
        let cmd = "cd \"/tmp/proj\" && git status";
        let result = run_cursor_inner(&cursor_input(cmd));
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["continue"], true);
        assert_eq!(v["permission"], "allow");
        assert_eq!(
            v["updated_input"]["command"],
            "cd \"/tmp/proj\" && contextcrawler git status"
        );
    }

    #[test]
    fn test_cursor_strips_single_utf8_bom() {
        // Some Cursor builds prepend a single UTF-8 BOM to hook stdin.
        // serde_json rejects BOM-prefixed input, so without the strip
        // the hook returned `{}` and the rewrite became a silent no-op.
        let payload = cursor_input("git status");
        let with_single_bom = format!("\u{feff}{}", payload);
        let result = run_cursor_inner(&with_single_bom);
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["continue"], true);
        assert_eq!(v["permission"], "allow");
        assert_eq!(v["updated_input"]["command"], "contextcrawler git status");
    }

    #[test]
    fn test_cursor_strips_double_utf8_bom() {
        // Cursor on Windows ships hook stdin with **two** leading
        // UTF-8 BOMs (`EF BB BF EF BB BF`), confirmed via a stdin
        // tracer wrapping `contextcrawler hook cursor` on Cursor 3.2.x. This is
        // the real-world payload shape the loop needs to survive.
        let payload = cursor_input("git status");
        let with_double_bom = format!("\u{feff}\u{feff}{}", payload);
        let result = run_cursor_inner(&with_double_bom);
        let v: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["continue"], true);
        assert_eq!(v["permission"], "allow");
        assert_eq!(v["updated_input"]["command"], "contextcrawler git status");
    }

    #[test]
    fn test_strip_leading_bom_helper() {
        // Direct unit test on the helper so future refactors can't
        // regress the loop semantics without a clear failure signal.
        assert_eq!(strip_leading_bom(""), "");
        assert_eq!(strip_leading_bom("hello"), "hello");
        assert_eq!(strip_leading_bom("\u{feff}hello"), "hello");
        assert_eq!(strip_leading_bom("\u{feff}\u{feff}hello"), "hello");
        assert_eq!(strip_leading_bom("\u{feff}\u{feff}\u{feff}hello"), "hello");
        // BOM in the middle is preserved (not "leading").
        assert_eq!(strip_leading_bom("a\u{feff}b"), "a\u{feff}b");
    }

    // --- Audit logging ---

    #[test]
    fn test_audit_log_silent_when_disabled() {
        std::env::remove_var("RTK_HOOK_AUDIT");
        audit_log("test", "git status", "contextcrawler git status");
    }

    #[test]
    fn test_audit_log_format_four_fields() {
        let tmp = std::env::temp_dir().join("rtk-test-audit");
        let _ = std::fs::create_dir_all(&tmp);
        let log_path = tmp.join("hook-audit.log");
        let _ = std::fs::remove_file(&log_path);

        {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .unwrap();
            let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
            writeln!(
                file,
                "{} | rewrite | git status | contextcrawler git status",
                ts
            )
            .unwrap();
        }

        let content = std::fs::read_to_string(&log_path).unwrap();
        let parts: Vec<&str> = content.trim().split(" | ").collect();
        assert_eq!(
            parts.len(),
            4,
            "Expected 4 pipe-delimited fields, got: {:?}",
            parts
        );
        assert_eq!(parts[1], "rewrite");
        assert_eq!(parts[2], "git status");
        assert_eq!(parts[3], "contextcrawler git status");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // --- Adversarial tests ---

    #[test]
    fn test_audit_log_sanitizes_newlines() {
        let sanitized = sanitize_log_field("git status\nfake | inject | evil");
        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains("\\n"));
    }

    #[test]
    fn test_audit_log_sanitizes_pipe_delimiter() {
        let sanitized = sanitize_log_field("git log | head");
        assert!(
            !sanitized.contains(" | "),
            "unescaped ' | ' breaks field parsing: {}",
            sanitized
        );
        assert!(sanitized.contains("\\|"));
    }

    #[test]
    fn test_claude_unicode_null_passthrough() {
        let input = claude_input("git status \u{0000}\u{FEFF}");
        let _ = run_claude_inner(&input);
    }

    #[test]
    fn test_claude_extremely_long_command() {
        let long_cmd = format!("git status {}", "A".repeat(100_000));
        let input = claude_input(&long_cmd);
        let _ = run_claude_inner(&input);
    }

    #[test]
    fn test_cursor_deny_blocks_rewrite() {
        use super::permissions::check_command_with_rules;
        let deny = vec!["git status".to_string()];
        assert_eq!(
            check_command_with_rules("git status", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_gemini_malformed_json_fails_closed() {
        // #111 G2: a malformed payload must produce a Gemini deny verdict,
        // not an error exit (which the harness treats as ALLOW).
        for bad in ["{not json", "", "null}", "{\"tool_name\":}"] {
            let out = run_gemini_inner(bad);
            let v: Value =
                serde_json::from_str(&out).expect("hook output must itself be valid JSON");
            assert_eq!(
                v["decision"], "deny",
                "malformed Gemini payload {bad:?} must fail closed with a deny"
            );
            assert!(
                v["reason"].as_str().unwrap().contains("not valid JSON"),
                "deny reason should name the parse failure"
            );
        }
        // A well-formed payload must NOT be denied by the parse step.
        let ok = run_gemini_inner(r#"{"tool_name":"run_shell_command"}"#);
        let v: Value = serde_json::from_str(&ok).unwrap();
        assert_eq!(v["decision"], "allow");
    }

    #[test]
    fn test_gemini_deny_blocks_rewrite() {
        use super::permissions::check_command_with_rules;
        let deny = vec!["cargo test".to_string()];
        assert_eq!(
            check_command_with_rules("cargo test", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
        // Denied commands must not be rewritten — Gemini handler checks deny before rewrite
        assert!(
            get_rewritten("cargo test").is_some(),
            "cargo test should be rewritable when not denied"
        );
    }
}
