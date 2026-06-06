//! Filters Prettier output to show only files that need formatting.

use crate::core::runner::{self, RunOptions};
use crate::core::utils::{
    check_forbidden_node_args, check_forbidden_node_config_args, package_manager_exec,
};
use anyhow::{anyhow, Result};

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    // Issue #37.
    check_forbidden_node_args(args).map_err(|m| anyhow!(m))?;
    // CMD-I2: deny `--config`/`-c` pointing at an executed JS/TS module
    // (prettier require()s a .js config → planted-file RCE). Data-only
    // .json/.yaml configs and auto-discovery remain available.
    check_forbidden_node_config_args(args).map_err(|m| anyhow!(m))?;

    let mut cmd = package_manager_exec("prettier");

    for arg in args {
        cmd.arg(arg);
    }

    if verbose > 0 {
        eprintln!("Running: prettier {}", args.join(" "));
    }

    runner::run_filtered(
        cmd,
        "prettier",
        &args.join(" "),
        filter_prettier_output,
        // On a non-zero exit (prettier error, syntax error, missing file) show
        // the raw output instead of a filtered "all formatted" claim (#100,
        // G5#6).
        RunOptions::stdout_only().early_exit_on_failure(),
    )
}

/// Filter Prettier output - show only files that need formatting
pub fn filter_prettier_output(output: &str) -> String {
    // #221: empty or whitespace-only output means prettier didn't run
    if output.trim().is_empty() {
        return "Error: prettier produced no output".to_string();
    }

    let mut files_to_format: Vec<String> = Vec::new();
    let mut files_checked = 0;
    let mut is_check_mode = true;

    for line in output.lines() {
        let trimmed = line.trim();

        // Detect check mode vs write mode
        if trimmed.contains("Checking formatting") {
            is_check_mode = true;
        }

        // Count files that need formatting (check mode)
        if !trimmed.is_empty()
            && !trimmed.starts_with("Checking")
            && !trimmed.starts_with("All matched")
            && !trimmed.starts_with("Code style")
            && !trimmed.contains("[warn]")
            && !trimmed.contains("[error]")
            && (trimmed.ends_with(".ts")
                || trimmed.ends_with(".tsx")
                || trimmed.ends_with(".js")
                || trimmed.ends_with(".jsx")
                || trimmed.ends_with(".json")
                || trimmed.ends_with(".md")
                || trimmed.ends_with(".css")
                || trimmed.ends_with(".scss"))
        {
            files_to_format.push(trimmed.to_string());
        }

        // Count total files checked
        if trimmed.contains("All matched files use Prettier") {
            if let Some(count_str) = trimmed.split_whitespace().next() {
                if let Ok(count) = count_str.parse::<usize>() {
                    files_checked = count;
                }
            }
        }
    }

    // Check if all files are formatted
    if files_to_format.is_empty() && output.contains("All matched files use Prettier") {
        return "Prettier: All files formatted correctly".to_string();
    }

    // Check if files were written (write mode)
    if output.contains("modified") || output.contains("formatted") {
        is_check_mode = false;
    }

    let mut result = String::new();

    let has_success_marker = output.contains("All matched files use Prettier");

    if is_check_mode {
        // Check mode: show files that need formatting
        if files_to_format.is_empty() {
            // Only claim success when prettier actually printed its positive
            // marker. Output that matched no filename heuristic AND carried no
            // success marker (e.g. a prettier error) must be shown raw rather
            // than mislabelled as formatted (#100, G5#6).
            if has_success_marker {
                result.push_str("Prettier: All files formatted correctly\n");
            } else {
                return output.trim().to_string();
            }
        } else {
            result.push_str(&format!(
                "Prettier: {} files need formatting\n",
                files_to_format.len()
            ));

            for (i, file) in files_to_format.iter().take(10).enumerate() {
                result.push_str(&format!("{}. {}\n", i + 1, file));
            }

            if files_to_format.len() > 10 {
                result.push_str(&format!(
                    "\n... +{} more files\n",
                    files_to_format.len() - 10
                ));
            }

            if files_checked > 0 {
                result.push_str(&format!(
                    "\n{} files already formatted\n",
                    files_checked - files_to_format.len()
                ));
            }
        }
    } else {
        // Write mode: show what was formatted
        result.push_str(&format!(
            "Prettier: {} files formatted\n",
            files_to_format.len()
        ));
    }

    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_all_formatted() {
        let output = r#"
Checking formatting...
All matched files use Prettier code style!
        "#;
        let result = filter_prettier_output(output);
        assert!(result.contains("Prettier"));
        assert!(result.contains("All files formatted correctly"));
    }

    #[test]
    fn test_filter_files_need_formatting() {
        let output = r#"
Checking formatting...
src/components/ui/button.tsx
src/lib/auth/session.ts
src/pages/dashboard.tsx
Code style issues found in the above file(s). Forgot to run Prettier?
        "#;
        let result = filter_prettier_output(output);
        assert!(result.contains("3 files need formatting"));
        assert!(result.contains("button.tsx"));
        assert!(result.contains("session.ts"));
    }

    #[test]
    fn test_filter_many_files() {
        let mut output = String::from("Checking formatting...\n");
        for i in 0..15 {
            output.push_str(&format!("src/file{}.ts\n", i));
        }
        let result = filter_prettier_output(&output);
        assert!(result.contains("15 files need formatting"));
        assert!(result.contains("... +5 more files"));
    }

    // --- #221: empty output should not say "All files formatted" ---

    #[test]
    fn test_filter_empty_output() {
        let result = filter_prettier_output("");
        assert!(result.contains("Error"));
        assert!(!result.contains("All files formatted"));
    }

    #[test]
    fn test_filter_whitespace_only_output() {
        let result = filter_prettier_output("   \n\n  ");
        assert!(result.contains("Error"));
        assert!(!result.contains("All files formatted"));
    }

    // --- #100 G5#6: error output must not be mislabelled as "all formatted" ---

    #[test]
    fn test_filter_error_output_not_marked_success() {
        // A prettier error whose lines match no filename heuristic and carry
        // no success marker must be shown raw, not "All files formatted".
        let output = "[error] foo.ts: SyntaxError: Unexpected token (3:5)\n\
                      [error] Could not resolve config";
        let result = filter_prettier_output(output);
        assert!(
            !result.contains("All files formatted correctly"),
            "error output must not be labelled as success, got: {}",
            result
        );
        assert!(result.contains("SyntaxError"));
    }

    #[test]
    fn test_filter_unrecognised_output_shown_raw() {
        let output = "some unexpected prettier diagnostic line";
        let result = filter_prettier_output(output);
        assert!(!result.contains("All files formatted correctly"));
        assert!(result.contains("unexpected prettier diagnostic"));
    }
}
