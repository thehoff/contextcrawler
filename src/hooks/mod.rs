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
    use std::sync::{Mutex, MutexGuard};

    /// Serialises env-var mutation across the (few) hook tests that drive the
    /// live path, which reads `CONTEXTCRAWLER_TRUST_UNATTESTABLE` from ambient
    /// env. Without this, the operator's overnight `=1` leaks in and flips
    /// attestation asserts (#209).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that pins `CONTEXTCRAWLER_TRUST_UNATTESTABLE` to a known
    /// state for the duration of a test, restoring the prior value on drop so
    /// the process env is left exactly as found. Holds a process-wide lock, so
    /// env-sensitive tests never race each other.
    pub(crate) struct TrustEnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior: Option<String>,
    }

    impl TrustEnvGuard {
        /// Force the untrusted default (variable removed) for this test.
        pub(crate) fn untrusted() -> Self {
            let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let prior = std::env::var("CONTEXTCRAWLER_TRUST_UNATTESTABLE").ok();
            std::env::remove_var("CONTEXTCRAWLER_TRUST_UNATTESTABLE");
            Self { _lock, prior }
        }
    }

    impl Drop for TrustEnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var("CONTEXTCRAWLER_TRUST_UNATTESTABLE", v),
                None => std::env::remove_var("CONTEXTCRAWLER_TRUST_UNATTESTABLE"),
            }
        }
    }
}
