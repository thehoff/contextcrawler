//! Translates a raw shell command into its ContextCrawler-optimized equivalent.

use super::permissions::{check_command, PermissionVerdict};
use super::{hook_cmd, supply_chain_gate, tirith_gate};
use crate::discover::registry;
use std::io::Write;

/// Run the `contextcrawler rewrite` command.
///
/// Prints the ContextCrawler-rewritten command to stdout and exits with a code that tells
/// the caller how to handle permissions:
///
/// | Exit | Stdout   | Meaning                                                       |
/// |------|----------|---------------------------------------------------------------|
/// | 0    | rewritten| Rewrite allowed — hook may auto-allow the rewritten command.  |
/// | 1    | (none)   | No equivalent, Default verdict — hook passes through.         |
/// | 2    | (none)   | Deny rule matched — hook defers to Claude Code native deny.   |
/// | 3    | original | Ask verdict, no rewrite (#2286) — original cmd, host prompts. |
/// | 3    | original | Gate flagged, no rewrite (#192) — original cmd, host prompts. |
/// | 3    | rewritten| Ask rule matched — hook rewrites but lets Claude Code prompt. |
/// | 3    | rewritten| Gate flagged, rewritten cmd, host prompts.                   |
pub fn run(cmd: &str) -> anyhow::Result<()> {
    let (excluded, transparent_prefixes) = crate::core::config::Config::load()
        .map(|c| (c.hooks.exclude_commands, c.hooks.transparent_prefixes))
        .unwrap_or_default();

    // SECURITY: check deny/ask BEFORE rewrite so non-wrappable commands are also covered.
    let verdict = check_command(cmd);

    if verdict == PermissionVerdict::Deny {
        std::process::exit(2);
    }

    // SECURITY (#192): run Tirith + supply-chain gates on the raw command
    // before deciding whether it is rewritable. The old legacy path only ran
    // these gates inside the `Some(rewritten)` arm, so non-rewritable commands
    // skipped both gates and fell through as host passthrough.
    let gate_decision = run_rewrite_gates(cmd);

    match registry::rewrite_command(cmd, &excluded, &transparent_prefixes) {
        Some(rewritten) => match verdict {
            PermissionVerdict::Allow => {
                apply_gate_decision(gate_decision, &rewritten);

                print!("{}", rewritten);
                let _ = std::io::stdout().flush();
                Ok(())
            }
            PermissionVerdict::Ask | PermissionVerdict::Default => {
                apply_gate_decision(gate_decision, &rewritten);
                print!("{}", rewritten);
                let _ = std::io::stdout().flush();
                std::process::exit(3);
            }
            PermissionVerdict::Deny => {
                // Deny is already handled with `exit(2)` before this match.
                // Reaching here would mean the verdict changed underneath
                // us — fail CLOSED (exit 2 = deny) rather than panic, so a
                // hook panic can never leave the agent's command unchecked.
                std::process::exit(2);
            }
        },
        None => {
            apply_gate_decision(gate_decision, cmd);
            // No ContextCrawler equivalent. SECURITY (#2286): a permission
            // `Ask` verdict on a non-rewritable command must still force a
            // prompt — exiting 1 (passthrough) lets the host auto-allow it via
            // its own rule (e.g. `git status $(whoami)` under `Bash(git:*)`).
            // Print the original command unchanged (ask/passthrough convention)
            // and exit 3 (ask). Only a genuine no-verdict (Default) passes
            // through at exit 1, where Claude Code evaluates its own rules.
            if verdict == PermissionVerdict::Ask {
                print!("{}", cmd);
                let _ = std::io::stdout().flush();
                std::process::exit(3);
            }
            std::process::exit(1);
        }
    }
}

fn run_rewrite_gates(cmd: &str) -> hook_cmd::GateDecision {
    let tirith_verdict = tirith_gate::check(cmd);
    let sc_verdict = supply_chain_gate::check(cmd);
    supply_chain_gate::log_event(cmd, &sc_verdict);
    let decision = hook_cmd::gate_decision(&tirith_verdict, &sc_verdict);
    if matches!(decision, hook_cmd::GateDecision::Ask { .. }) {
        if let Some((reason, tirith_json)) = tirith_gate::should_downgrade(&tirith_verdict) {
            tirith_gate::log_downgrade(cmd, reason, tirith_json);
        }
    }
    decision
}

#[cfg(test)]
fn gate_exit_code(decision: &hook_cmd::GateDecision) -> Option<i32> {
    match decision {
        hook_cmd::GateDecision::Proceed => None,
        hook_cmd::GateDecision::Ask { .. } => Some(3),
        hook_cmd::GateDecision::Deny { .. } => Some(3),
    }
}

fn apply_gate_decision(decision: hook_cmd::GateDecision, ask_stdout: &str) {
    match decision {
        hook_cmd::GateDecision::Proceed => {}
        hook_cmd::GateDecision::Ask { suggestion } => {
            eprintln!(
                "[contextcrawler] a defence-in-depth gate flagged this command; \
                 downgrading auto-allow to Ask."
            );
            if let Some(hint) = suggestion {
                eprintln!("{hint}");
            }
            print!("{ask_stdout}");
            let _ = std::io::stdout().flush();
            std::process::exit(3);
        }
        hook_cmd::GateDecision::Deny { reason } => {
            eprintln!("{reason}");
            print!("{ask_stdout}");
            let _ = std::io::stdout().flush();
            std::process::exit(3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_command_no_prefixes(cmd: &str) -> Option<String> {
        registry::rewrite_command(cmd, &[], &[])
    }

    #[test]
    fn test_run_supported_command_succeeds() {
        assert!(rewrite_command_no_prefixes("git status").is_some());
    }

    #[test]
    fn test_run_unsupported_returns_none() {
        assert!(rewrite_command_no_prefixes("htop").is_none());
    }

    #[test]
    fn test_run_already_rtk_returns_some() {
        assert_eq!(
            rewrite_command_no_prefixes("rtk git status"),
            Some("rtk git status".into())
        );
    }

    /// SECURITY: Verify the exit code protocol for permission verdicts.
    ///
    /// The bash hook (.claude/hooks/rtk-rewrite.sh) interprets exit codes as:
    ///   0 → auto-allow (sets permissionDecision: "allow")
    ///   1 → passthrough (no ContextCrawler equivalent)
    ///   2 → deny (let Claude Code handle natively)
    ///   3 → ask (rewrite but omit permissionDecision, forcing user prompt)
    ///
    /// CRITICAL: PermissionVerdict::Default MUST map to exit 3 (ask), NOT exit 0.
    /// If Default were mapped to exit 0, any command without an explicit permission
    /// rule would be auto-allowed — bypassing Claude Code's least-privilege default.
    /// See: https://github.com/rtk-ai/rtk/issues/1155
    mod exit_code_protocol {
        use super::registry;
        use crate::hooks::permissions::{check_command_with_rules, PermissionVerdict};

        /// Exit code that `run()` returns for each verdict:
        ///   Allow  → 0 (exit Ok(()))
        ///   Ask    → 3 (process::exit(3))
        ///   Default→ 3 (process::exit(3)) — grouped with Ask
        ///   Deny   → 2 (process::exit(2)) — handled before rewrite match
        fn expected_exit_code(verdict: &PermissionVerdict) -> i32 {
            match verdict {
                PermissionVerdict::Allow => 0,
                PermissionVerdict::Deny => 2,
                PermissionVerdict::Ask => 3,
                PermissionVerdict::Default => 3, // MUST be 3, not 0!
            }
        }

        #[test]
        fn test_default_verdict_maps_to_ask_exit_code() {
            // When no rules match, verdict is Default → exit code must be 3 (ask).
            let verdict = check_command_with_rules("git status", &[], &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Default);
            assert_eq!(
                expected_exit_code(&verdict),
                3,
                "Default verdict MUST exit with code 3 (ask), not 0 (allow)"
            );
        }

        #[test]
        fn test_allow_verdict_maps_to_allow_exit_code() {
            let allow = vec!["git *".to_string()];
            let verdict = check_command_with_rules("git status", &[], &[], &allow);
            assert_eq!(verdict, PermissionVerdict::Allow);
            assert_eq!(expected_exit_code(&verdict), 0);
        }

        #[test]
        fn test_ask_verdict_maps_to_ask_exit_code() {
            let ask = vec!["git push".to_string()];
            let verdict = check_command_with_rules("git push origin main", &[], &ask, &[]);
            assert_eq!(verdict, PermissionVerdict::Ask);
            assert_eq!(expected_exit_code(&verdict), 3);
        }

        #[test]
        fn test_deny_verdict_maps_to_deny_exit_code() {
            let deny = vec!["rm -rf".to_string()];
            let verdict = check_command_with_rules("rm -rf /tmp/test", &deny, &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Deny);
            assert_eq!(expected_exit_code(&verdict), 2);
        }

        #[test]
        fn test_no_auto_allow_bypass_for_unrecognized_commands() {
            // SECURITY: A command with no permission rules and no matching allow rule
            // must NOT be auto-allowed. This is the core of issue #1155.
            // Even though `git status` can be rewritten to `rtk git status`,
            // the absence of an allow rule means Default → exit 3 → ask.
            let verdict = check_command_with_rules("git status", &[], &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Default);

            // Verify the rewrite exists (so the hook would output it),
            // but the exit code forces user confirmation.
            assert!(registry::rewrite_command("git status", &[], &[]).is_some());
            assert_eq!(expected_exit_code(&verdict), 3);
        }

        #[test]
        fn test_default_never_equals_allow() {
            // Sentinel: ensure Default and Allow are distinct enum variants.
            // If this ever fails, the entire permission model is broken.
            assert_ne!(PermissionVerdict::Default, PermissionVerdict::Allow);
        }

        // === #2286: the `None` (non-rewritable) arm must consult the verdict ===
        // `run()` calls `std::process::exit`, so the arm is not directly
        // unit-testable; this mirrors its decision logic exactly. The bug was
        // that a non-rewritable command exited 1 (passthrough → host auto-allow)
        // even on an `Ask` verdict. An `Ask` verdict must now exit 3 (ask);
        // only Default still passes through at exit 1.
        fn no_rewrite_exit_code(verdict: &PermissionVerdict) -> i32 {
            match verdict {
                PermissionVerdict::Deny => 2, // handled before the match
                PermissionVerdict::Ask => 3,  // #2286: force a prompt
                PermissionVerdict::Allow | PermissionVerdict::Default => 1,
            }
        }

        #[test]
        fn test_no_rewrite_ask_verdict_maps_to_ask_exit() {
            // `notarealcmd $(cat secret)` is non-rewritable AND carries an
            // UNSAFE substitution (reads file contents), so the verdict is Ask
            // regardless of rules — must exit 3, not 1. (A safe payload like
            // `$(whoami)` is now attestable and would exit 1; see #2286 follow-up.)
            let verdict = check_command_with_rules("notarealcmd $(cat secret)", &[], &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Ask);
            assert!(registry::rewrite_command("notarealcmd $(cat secret)", &[], &[]).is_none());
            assert_eq!(
                no_rewrite_exit_code(&verdict),
                3,
                "non-rewritable Ask verdict MUST exit 3 (ask), not 1 (passthrough) (#2286)"
            );
        }

        #[test]
        fn test_no_rewrite_default_verdict_still_passthrough() {
            // Benign non-rewritable command (Default verdict) must still exit 1
            // so the host evaluates its own rules — no over-escalation.
            let verdict = check_command_with_rules("notarealcmd --flag", &[], &[], &[]);
            assert_eq!(verdict, PermissionVerdict::Default);
            assert!(registry::rewrite_command("notarealcmd --flag", &[], &[]).is_none());
            assert_eq!(no_rewrite_exit_code(&verdict), 1);
        }
    }

    /// SECURITY: the supply-chain gate must fail CLOSED. A `Block` verdict
    /// AND an `Unavailable` verdict (registry timeout / OSV outage / TOML
    /// parse error) both downgrade the auto-allow to Ask (exit 3). Only
    /// `Skip` / `Allow` proceed silently. If `Unavailable` were treated as
    /// a silent allow, every transient network failure would wave installs
    /// through — fail-open. See issue #100 (G1).
    mod supply_chain_fail_closed {
        use crate::hooks::hook_cmd::{gate_decision, GateDecision};
        use crate::hooks::supply_chain_gate::Verdict;
        use crate::hooks::tirith_gate;

        /// The exit code `run()` applies for a given supply-chain verdict
        /// once the upstream permission verdict is Allow.
        ///   Skip / Allow   → 0 (proceed, auto-allow)
        ///   Block          → 3 (ask — legacy bridge cannot emit native deny)
        ///   Ask            → 3 (ask — install set unvettable, fail closed)
        ///   Unavailable    → 3 (ask — gate could not verify, fail closed)
        fn supply_chain_exit_code(v: &Verdict) -> i32 {
            match gate_decision(&tirith_gate::Verdict::Allow, v) {
                GateDecision::Proceed => 0,
                GateDecision::Ask { .. } => 3,
                GateDecision::Deny { .. } => 3,
            }
        }

        #[test]
        fn unavailable_downgrades_to_ask_not_allow() {
            let v = Verdict::Unavailable("registry timeout".into());
            assert_eq!(
                supply_chain_exit_code(&v),
                3,
                "Unavailable MUST downgrade to Ask (3), never silently allow (0)"
            );
        }

        #[test]
        fn block_maps_to_ask_in_legacy_bridge() {
            let v = Verdict::Block(vec![]);
            assert_eq!(supply_chain_exit_code(&v), 3);
        }

        #[test]
        fn ask_downgrades_to_ask_not_allow() {
            // An unvettable install (lockfile / requirements file) must
            // downgrade the auto-allow to Ask, never silently proceed.
            let v = Verdict::Ask(vec![]);
            assert_eq!(
                supply_chain_exit_code(&v),
                3,
                "Ask MUST downgrade to Ask (3), never silently allow (0)"
            );
        }

        #[test]
        fn allow_and_skip_proceed() {
            assert_eq!(supply_chain_exit_code(&Verdict::Allow), 0);
            assert_eq!(supply_chain_exit_code(&Verdict::Skip), 0);
        }
    }

    mod legacy_gate_exit_protocol {
        use crate::hooks::hook_cmd::GateDecision;

        #[test]
        fn non_rewritable_gate_ask_maps_to_ask_exit() {
            assert_eq!(
                super::gate_exit_code(&GateDecision::Ask { suggestion: None }),
                Some(3),
                "legacy non-rewritable gate Ask must force a host prompt, not passthrough"
            );
        }

        #[test]
        fn gate_deny_maps_to_ask_exit() {
            assert_eq!(
                super::gate_exit_code(&GateDecision::Deny {
                    reason: "blocked".into()
                }),
                Some(3),
                "legacy gate Deny must prompt because exit 2 only delegates to native deny rules"
            );
        }

        #[test]
        fn clean_gate_has_no_exit_override() {
            assert_eq!(super::gate_exit_code(&GateDecision::Proceed), None);
        }
    }
}
