//! Shared guards for file paths that commonly contain local secrets.

use anyhow::{bail, Result};
use std::ffi::OsStr;
use std::path::Path;

pub const SENSITIVE_ENV_OVERRIDE: &str = "CONTEXTCRAWLER_ALLOW_SENSITIVE_ENV_READ";

pub fn is_sensitive_env_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };

    if !is_dotenv_secret_name(name) {
        return false;
    }

    !is_documented_safe_dotenv_name(name)
}

pub fn ensure_not_sensitive_env_path(path: &Path, surface: &str) -> Result<()> {
    if is_sensitive_env_path(path) {
        bail!(
            "contextcrawler: refusing to read sensitive env file `{}` via {}. \
             Use `{}`=1 only when you intentionally need raw secret-file contents. \
             Safe templates such as .env.example, .env.sample, and .env.template are allowed.",
            path.display(),
            surface,
            SENSITIVE_ENV_OVERRIDE
        );
    }
    Ok(())
}

pub fn sensitive_env_override_enabled() -> bool {
    std::env::var(SENSITIVE_ENV_OVERRIDE).as_deref() == Ok("1")
}

fn is_dotenv_secret_name(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.")
}

fn is_documented_safe_dotenv_name(name: &str) -> bool {
    name == ".env.example"
        || name == ".env.sample"
        || name == ".env.template"
        || name.ends_with(".example")
        || name.ends_with(".sample")
        || name.ends_with(".template")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_secret_dotenv_names() {
        for path in [".env", ".env.local", ".env.production", "dir/.env.test"] {
            assert!(is_sensitive_env_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn allows_documented_template_names() {
        for path in [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.production.example",
            "dir/.env.local.template",
        ] {
            assert!(!is_sensitive_env_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn ignores_non_dotenv_names() {
        for path in [".envrc", "env", "README.env", "dotenv"] {
            assert!(!is_sensitive_env_path(Path::new(path)), "{path}");
        }
    }
}
