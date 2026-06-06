//! Back-compat environment-variable access.
//!
//! The canonical env-var prefix is `CTXCRL_`. The legacy `RTK_` prefix is still
//! honoured as a fallback so existing setups keep working, but it is
//! **deprecated and will be removed in a future release**. This module is the
//! ONLY place the old `RTK_` prefix survives at runtime — every read site goes
//! through here, asks for the canonical `CTXCRL_` name, and the helper silently
//! falls back to the `RTK_` name when the canonical one is unset.

/// Translate a canonical `CTXCRL_*` name to its legacy `RTK_*` equivalent.
fn legacy_name(canonical: &str) -> String {
    canonical.replacen("CTXCRL_", "RTK_", 1)
}

/// Read an env var by its canonical `CTXCRL_` name, falling back to the legacy
/// `RTK_` name. The canonical name always wins when both are set.
pub fn env_var(canonical: &str) -> Option<String> {
    std::env::var(canonical)
        .ok()
        .or_else(|| std::env::var(legacy_name(canonical)).ok())
}

/// True when the canonical (or legacy) var is set to exactly `"1"`.
pub fn env_flag(canonical: &str) -> bool {
    env_var(canonical).as_deref() == Some("1")
}

/// True when the canonical (or legacy) var is present with any value.
pub fn env_present(canonical: &str) -> bool {
    env_var(canonical).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialise env-mutating tests: the process env is global shared state.
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn canonical_name_wins() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("CTXCRL_ENVTEST_WIN", "new");
        std::env::set_var("RTK_ENVTEST_WIN", "old");
        assert_eq!(env_var("CTXCRL_ENVTEST_WIN").as_deref(), Some("new"));
        std::env::remove_var("CTXCRL_ENVTEST_WIN");
        std::env::remove_var("RTK_ENVTEST_WIN");
    }

    #[test]
    fn legacy_fallback_works() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CTXCRL_ENVTEST_LEGACY");
        std::env::set_var("RTK_ENVTEST_LEGACY", "old");
        assert_eq!(env_var("CTXCRL_ENVTEST_LEGACY").as_deref(), Some("old"));
        std::env::remove_var("RTK_ENVTEST_LEGACY");
    }

    #[test]
    fn flag_honours_both_prefixes() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CTXCRL_ENVTEST_FLAG");
        std::env::remove_var("RTK_ENVTEST_FLAG");
        assert!(!env_flag("CTXCRL_ENVTEST_FLAG"));
        std::env::set_var("RTK_ENVTEST_FLAG", "1");
        assert!(env_flag("CTXCRL_ENVTEST_FLAG"));
        std::env::set_var("CTXCRL_ENVTEST_FLAG", "1");
        assert!(env_flag("CTXCRL_ENVTEST_FLAG"));
        std::env::remove_var("CTXCRL_ENVTEST_FLAG");
        std::env::remove_var("RTK_ENVTEST_FLAG");
    }

    #[test]
    fn present_detects_either() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("CTXCRL_ENVTEST_PRESENT");
        std::env::remove_var("RTK_ENVTEST_PRESENT");
        assert!(!env_present("CTXCRL_ENVTEST_PRESENT"));
        std::env::set_var("RTK_ENVTEST_PRESENT", "");
        assert!(env_present("CTXCRL_ENVTEST_PRESENT"));
        std::env::remove_var("RTK_ENVTEST_PRESENT");
    }
}
