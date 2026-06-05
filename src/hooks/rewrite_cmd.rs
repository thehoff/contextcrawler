//! Translates a raw shell command into its RTK-optimized equivalent.

use super::permissions::{check_command, PermissionVerdict};
use crate::discover::registry;
use std::io::Write;

// ===== contextzip-downstream: supply-chain gate import begin =====
use super::supply_chain_gate;
// ===== contextzip-downstream: supply-chain gate import end =====

// ===== contextzip-downstream: Tirith pre-execution gate begin =====
// Gate logic lives in `super::tirith_gate` so both this path and the
// modern `rtk hook claude` path (hook_cmd.rs) share one implementation.
use super::tirith_gate;
// ===== contextzip-downstream: Tirith pre-execution gate end =====

/// Run the `contextcrawler rewrite` command.
///
/// Prints the ContextCrawler-rewritten command to stdout and exits with a code that tells
/// the caller how to handle permissions:
///
/// | Exit | Stdout   | Meaning                                                       |
/// |------|----------|---------------------------------------------------------------|
/// | 0    | rewritten| Rewrite allowed — hook may auto-allow the rewritten command.  |
/// | 1    | (none)   | No ContextCrawler equivalent — hook passes through unchanged. |
/// | 2    | (none)   | Deny rule matched — hook defers to Claude Code native deny.   |
/// | 3    | rewritten| Ask rule matched — hook rewrites but lets Claude Code prompt. |
pub fn run(cmd: &str) -> anyhow::Result<()> {
    let (excluded, transparent_prefixes) = crate::core::config::Config::load()
        .map(|c| (c.hooks.exclude_commands, c.hooks.transparent_prefixes))
        .unwrap_or_default();

    // SECURITY: check deny/ask BEFORE rewrite so non-wrappable commands are also covered.
    let verdict = check_command(cmd);

    if verdict == PermissionVerdict::Deny {
        std::process::exit(2);
    }

    match registry::rewrite_command(cmd, &excluded, &transparent_prefixes) {
        Some(rewritten) => match verdict {
            PermissionVerdict::Allow => {
                // ===== contextzip-downstream: Tirith gate fires here =====
                let tirith_verdict = tirith_gate::check(cmd);
                if let Some((reason, tirith_json)) =
                    tirith_gate::should_downgrade(&tirith_verdict)
                {
                    eprintln!(
                        "[contextcrawler] Tirith {}; downgrading auto-allow to Ask.",
                        if reason == "tirith_block" {
                            "flagged the command"
                        } else {
                            "required but unavailable"
                        }
                    );
                    // Surface the copy-paste trust hint (#197) so the operator
                    // can allowlist the host without digging through logs.
                    if let Some(hint) = tirith_json.and_then(tirith_gate::suggest_trust) {
                        eprintln!("{hint}");
                    }
                    tirith_gate::log_downgrade(cmd, reason, tirith_json);
                    print!("{}", rewritten);
                    let _ = std::io::stdout().flush();
                    std::process::exit(3);
                }
                // ===== contextzip-downstream: end Tirith gate =====

                // ===== contextzip-downstream: supply-chain gate fires here =====
                // SECURITY: a `Block` verdict (failed gate) AND an
                // `Unavailable` verdict (registry/OSV lookup failed) both
                // downgrade the auto-allow to Ask. Treating `Unavailable`
                // as a silent allow would be fail-open: every network
                // timeout or OSV outage would wave installs straight
                // through. The gate is opt-in (`supply_chain.enabled`), so
                // once a user has turned it on we fail CLOSED on error.
                let sc_verdict = supply_chain_gate::check(cmd);
                supply_chain_gate::log_event(cmd, &sc_verdict);
                match &sc_verdict {
                    supply_chain_gate::Verdict::Block(_) => {
                        eprintln!("{}", supply_chain_gate::render(&sc_verdict));
                        print!("{}", rewritten);
                        let _ = std::io::stdout().flush();
                        std::process::exit(3);
                    }
                    supply_chain_gate::Verdict::Unavailable(_) => {
                        eprintln!("{}", supply_chain_gate::render(&sc_verdict));
                        eprintln!(
                            "[contextcrawler] supply-chain gate could not verify; \
                             downgrading auto-allow to Ask."
                        );
                        print!("{}", rewritten);
                        let _ = std::io::stdout().flush();
                        std::process::exit(3);
                    }
                    supply_chain_gate::Verdict::Ask(_) => {
                        // Install verb detected but its package set is
                        // unvettable (lockfile / requirements file). Fail
                        // closed: downgrade the auto-allow to Ask.
                        eprintln!("{}", supply_chain_gate::render(&sc_verdict));
                        print!("{}", rewritten);
                        let _ = std::io::stdout().flush();
                        std::process::exit(3);
                    }
                    supply_chain_gate::Verdict::Skip | supply_chain_gate::Verdict::Allow => {}
                }
                // ===== contextzip-downstream: end supply-chain gate =====


                print!("{}", rewritten);
                let _ = std::io::stdout().flush();
                Ok(())
            }
            PermissionVerdict::Ask | PermissionVerdict::Default => {
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
            // No ContextCrawler equivalent. Exit 1 = passthrough.
            // Claude Code independently evaluates its own ask rules on the original cmd.
            std::process::exit(1);
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
    }

    /// SECURITY: the supply-chain gate must fail CLOSED. A `Block` verdict
    /// AND an `Unavailable` verdict (registry timeout / OSV outage / TOML
    /// parse error) both downgrade the auto-allow to Ask (exit 3). Only
    /// `Skip` / `Allow` proceed silently. If `Unavailable` were treated as
    /// a silent allow, every transient network failure would wave installs
    /// through — fail-open. See issue #100 (G1).
    mod supply_chain_fail_closed {
        use crate::hooks::supply_chain_gate::Verdict;

        /// The exit code `run()` applies for a given supply-chain verdict
        /// once the upstream permission verdict is Allow.
        ///   Skip / Allow   → 0 (proceed, auto-allow)
        ///   Block          → 3 (ask — gate failed)
        ///   Ask            → 3 (ask — install set unvettable, fail closed)
        ///   Unavailable    → 3 (ask — gate could not verify, fail closed)
        fn supply_chain_exit_code(v: &Verdict) -> i32 {
            match v {
                Verdict::Skip | Verdict::Allow => 0,
                Verdict::Block(_) => 3,
                Verdict::Ask(_) => 3,
                Verdict::Unavailable(_) => 3,
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
        fn block_still_downgrades_to_ask() {
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
}
