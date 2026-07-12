//! Hook installation and lifecycle management for AI coding agents.

pub mod constants;
pub mod hook_audit_cmd;
pub mod hook_check;
#[deny(clippy::print_stdout, clippy::print_stderr)]
pub mod hook_cmd;
pub mod init;
pub mod integrity;
pub mod permissions;
pub mod rewrite_cmd;
pub mod trust;
pub mod verify_cmd;
// downstream:
pub mod supply_chain_gate;
pub mod tirith_gate;

/// Test-only helpers shared across the hook test modules.
#[cfg(test)]
pub(crate) mod test_env {
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    const VAR: &str = "CONTEXTCRAWLER_TRUST_UNATTESTABLE";

    /// Serialises env-var mutation across the (few) hook tests that drive the
    /// live path, which reads `CONTEXTCRAWLER_TRUST_UNATTESTABLE` from ambient
    /// env. Without this, the operator's overnight `=1` leaks in and flips
    /// attestation asserts (#209).
    ///
    /// NOTE (council #209, mmax): the 4-arg `check_command_with_rules` reads
    /// this var WITHOUT taking `ENV_LOCK`. That is safe today because every
    /// env-sensitive test either pins `trusted` explicitly via
    /// `check_command_with_rules_trusted(.., false)` or takes this guard — so
    /// nothing races the remove/restore. Any NEW test that exercises the
    /// ambient-env wrapper and is sensitive to its value must route through
    /// this guard too.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that pins `CONTEXTCRAWLER_TRUST_UNATTESTABLE` to a known
    /// state for the duration of a test, restoring the prior value on drop so
    /// the process env is left exactly as found. Holds a process-wide lock, so
    /// env-sensitive tests never race each other.
    pub(crate) struct TrustEnvGuard {
        _lock: MutexGuard<'static, ()>,
        // OsString (not String) so a non-UTF-8 prior value round-trips exactly
        // on restore (council #209, codex).
        prior: Option<OsString>,
    }

    impl TrustEnvGuard {
        /// Force the untrusted default (variable removed) for this test.
        pub(crate) fn untrusted() -> Self {
            let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let prior = std::env::var_os(VAR);
            std::env::remove_var(VAR);
            Self { _lock, prior }
        }
    }

    impl Drop for TrustEnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(VAR, v),
                None => std::env::remove_var(VAR),
            }
        }
    }
}
