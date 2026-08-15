//! Integration tests for the git wrapper hardening (issue #35).
//!
//! Each test invokes the built `contextcrawler` binary with one of the
//! known git env-var or `-c` RCE vectors armed, then asserts that the
//! attacker-controlled marker payload never ran. The marker mechanism is
//! the same shape used in PR #33 for the rg hardening: a shell script
//! that, if executed, would create a sentinel file in a tempdir. We
//! then check for the absence of the sentinel.
//!
//! These tests deliberately exercise the BUILT binary (via
//! `CARGO_BIN_EXE_contextcrawler`) rather than calling the helpers
//! in-process, because the hardening lives at the spawn boundary —
//! the only way to confirm it actually severs the env is to spawn
//! a real child with the env set.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contextcrawler"))
}

/// Build a `Command` that runs the contextcrawler binary inside `cwd`
/// (which should be a git repo so `git diff` / `git status` etc. don't
/// short-circuit before the env-driven hook fires).
fn ccrawl_in(cwd: &std::path::Path) -> Command {
    let mut c = Command::new(binary_path());
    c.current_dir(cwd);
    // Empty PATH-adjacent env-var noise; preserve PATH so git is findable.
    if let Ok(path) = std::env::var("PATH") {
        c.env_clear();
        c.env("PATH", path);
        if let Ok(home) = std::env::var("HOME") {
            c.env("HOME", home);
        }
    }
    // Issue #91 — sentinel for release-built spawned binary. MUST be set
    // AFTER env_clear() above (env_clear wipes everything including this).
    c.env("CONTEXTCRAWLER_TEST_MODE", "1");
    c
}

/// Create a throwaway git repo with one commit so `git diff HEAD~1` and
/// friends have something to diff. Returns the tempdir handle (which
/// must be kept alive to keep the dir on disk) and its path.
fn make_repo() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create tempdir for repo");
    let path = dir.path().to_path_buf();

    // git init + minimal commit. Use Command directly (not contextcrawler)
    // so the setup itself can't be confused with the system under test.
    //
    // Pass `-c commit.gpgsign=false -c tag.gpgsign=false` on every git call
    // (issue #57). Without it the fixture inherits the developer's global
    // `commit.gpgsign=true` and silently fails on workstations where the
    // signing agent (1Password, gpg-agent, ssh-agent) is unavailable or
    // locked — the entire test suite then dies on `make_repo()` with
    // "1Password: agent returned an error" and reports the cause as the
    // security test, not the fixture. Isolating with these flags keeps
    // the test hermetic against the host's git config.
    let run = |args: &[&str]| {
        let mut full_args: Vec<&str> = vec![
            "-c", "commit.gpgsign=false",
            "-c", "tag.gpgsign=false",
        ];
        full_args.extend_from_slice(args);
        let status = Command::new("git")
            .args(&full_args)
            .current_dir(&path)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git command runs");
        assert!(
            status.status.success(),
            "git {:?} failed: stderr={}",
            full_args,
            String::from_utf8_lossy(&status.stderr)
        );
    };

    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    // Belt-and-braces: also pin signing off via local config, so any
    // future helper that forgets the -c flags still gets a hermetic
    // commit. Cheap insurance.
    run(&["config", "commit.gpgsign", "false"]);
    run(&["config", "tag.gpgsign", "false"]);
    fs::write(path.join("a.txt"), "hello\n").unwrap();
    run(&["add", "a.txt"]);
    run(&["commit", "-q", "-m", "init"]);
    fs::write(path.join("a.txt"), "hello world\n").unwrap();
    run(&["add", "a.txt"]);
    run(&["commit", "-q", "-m", "update"]);

    (dir, path)
}

/// Write an executable shell script at `path` that `touch`es `marker`
/// when run. Returns the script path. On non-unix platforms this test
/// is skipped at the call site.
#[cfg(unix)]
fn make_marker_script(dir: &std::path::Path, marker: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("evil.sh");
    let body = format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display());
    fs::write(&script, body).expect("write script");
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).expect("chmod +x script");
    script
}

#[test]
#[cfg(unix)]
fn git_external_diff_env_is_stripped() {
    let _guard = common::env_lock();
    let (repo, repo_path) = make_repo();
    let marker = repo.path().join("MARKER_external_diff");
    let script = make_marker_script(repo.path(), &marker);

    // Pre-PoC sanity: run raw git with the var set, confirm the marker
    // *does* get written (i.e. our PoC is real). If this fails the test
    // is unsound — surface that loudly rather than silently passing.
    let _ = fs::remove_file(&marker);
    let raw = Command::new("git")
        .args(["diff", "HEAD~1"])
        .current_dir(&repo_path)
        .env("GIT_EXTERNAL_DIFF", &script)
        .output()
        .expect("raw git diff runs");
    assert!(
        marker.exists(),
        "PoC sanity check failed: raw `git diff` with GIT_EXTERNAL_DIFF set \
         did NOT touch the marker, so this test cannot prove anything. \
         git stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );

    // Now the real test: same env, same args, but through contextcrawler.
    let _ = fs::remove_file(&marker);
    let out = ccrawl_in(&repo_path)
        .args(["git", "diff"])
        .env("GIT_EXTERNAL_DIFF", &script)
        .output()
        .expect("contextcrawler git diff runs");
    assert!(
        !marker.exists(),
        "contextcrawler git diff still executed GIT_EXTERNAL_DIFF helper. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg(unix)]
fn git_config_count_env_injection_is_stripped() {
    let _guard = common::env_lock();
    let (repo, repo_path) = make_repo();
    let marker = repo.path().join("MARKER_config_count");
    let script = make_marker_script(repo.path(), &marker);

    // PoC sanity: raw git with GIT_CONFIG_COUNT=1 + KEY_0=diff.external
    // + VALUE_0=<script> triggers the helper. If not, the env-var
    // injection vector we're claiming to neutralize isn't actually
    // reachable on this platform and the test is moot.
    let _ = fs::remove_file(&marker);
    let raw = Command::new("git")
        .args(["diff", "HEAD~1"])
        .current_dir(&repo_path)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "diff.external")
        .env("GIT_CONFIG_VALUE_0", script.to_str().unwrap())
        .output()
        .expect("raw git diff runs");
    assert!(
        marker.exists(),
        "PoC sanity check failed: raw `git diff` with GIT_CONFIG_COUNT injection \
         did NOT touch the marker. Stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );

    let _ = fs::remove_file(&marker);
    let out = ccrawl_in(&repo_path)
        .args(["git", "diff"])
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "diff.external")
        .env("GIT_CONFIG_VALUE_0", script.to_str().unwrap())
        .output()
        .expect("contextcrawler git diff runs");
    assert!(
        !marker.exists(),
        "contextcrawler git diff still honored GIT_CONFIG_COUNT injection. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg(unix)]
fn git_config_global_env_pointing_at_evil_gitconfig_is_stripped() {
    let _guard = common::env_lock();
    let (repo, repo_path) = make_repo();
    let marker = repo.path().join("MARKER_config_global");
    let script = make_marker_script(repo.path(), &marker);

    // Fixture .gitconfig that sets diff.external = <script>.
    let cfg = repo.path().join("evil.gitconfig");
    fs::write(
        &cfg,
        format!("[diff]\n    external = {}\n", script.display()),
    )
    .expect("write evil gitconfig");

    // PoC sanity.
    let _ = fs::remove_file(&marker);
    let raw = Command::new("git")
        .args(["diff", "HEAD~1"])
        .current_dir(&repo_path)
        .env("GIT_CONFIG_GLOBAL", &cfg)
        // Some git builds also consult GIT_CONFIG_SYSTEM; explicitly
        // unset it to avoid noise.
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("raw git diff runs");
    assert!(
        marker.exists(),
        "PoC sanity check failed: raw `git diff` with GIT_CONFIG_GLOBAL injection \
         did NOT touch the marker. stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );

    let _ = fs::remove_file(&marker);
    let out = ccrawl_in(&repo_path)
        .args(["git", "diff"])
        .env("GIT_CONFIG_GLOBAL", &cfg)
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("contextcrawler git diff runs");
    assert!(
        !marker.exists(),
        "contextcrawler git diff still honored GIT_CONFIG_GLOBAL injection. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn c_diff_external_arg_is_rejected_with_deny_error() {
    // No need to actually be in a repo — the deny check fires before
    // git is spawned. Use a tempdir for cwd to avoid mutating whatever
    // tree the test is run from.
    let _guard = common::env_lock();
    let dir = tempfile::tempdir().expect("tempdir");
    let out = ccrawl_in(dir.path())
        .args(["git", "-c", "diff.external=/tmp/evil.sh", "diff"])
        .output()
        .expect("contextcrawler git runs");

    assert!(
        !out.status.success(),
        "contextcrawler must reject -c diff.external=… with non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("contextcrawler") && stderr.contains("#35"),
        "stderr must explain why and reference issue #35. got={:?}",
        stderr
    );
}

// ---- #111 G4: transport-flag denylist on subcommand + passthrough args -----
//
// `check_forbidden_git_args` was only wired into the global `--config-override`
// synthesis in main.rs. The per-subcommand `args` (and the OsString args that
// flow to `run_passthrough` for unmodelled subcommands like `clone`) reached
// git unvalidated, so `--upload-pack` / `--receive-pack` / `--exec-path` were
// forwarded straight through → arbitrary-binary execution (issue #35). These
// assert each spawn path now rejects the denied flags before git is spawned.

/// Assert a contextcrawler git invocation is rejected with the standard
/// deny error: non-zero exit and a stderr message naming contextcrawler
/// and referencing issue #35.
fn assert_git_args_rejected(cwd: &std::path::Path, args: &[&str]) {
    let out = ccrawl_in(cwd)
        .args(args)
        .output()
        .expect("contextcrawler git runs");
    assert!(
        !out.status.success(),
        "contextcrawler must reject {:?} with a non-zero exit. stdout={:?} stderr={:?}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("contextcrawler") && stderr.contains("#35"),
        "stderr for {:?} must explain why and reference issue #35. got={:?}",
        args,
        stderr
    );
}

#[test]
fn git_fetch_upload_pack_arg_is_rejected() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    assert_git_args_rejected(
        &repo_path,
        &["git", "fetch", "--upload-pack=/tmp/evil", "origin"],
    );
}

#[test]
fn git_push_receive_pack_arg_is_rejected() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    assert_git_args_rejected(
        &repo_path,
        &["git", "push", "--receive-pack=/tmp/evil", "origin", "main"],
    );
}

#[test]
fn git_clone_passthrough_upload_pack_arg_is_rejected() {
    // `clone` is unmodelled — it routes through `run_passthrough`, which
    // takes OsString args. Confirm the denylist fires on that path too.
    let _guard = common::env_lock();
    let dir = tempfile::tempdir().expect("tempdir");
    assert_git_args_rejected(
        dir.path(),
        &[
            "git",
            "clone",
            "--upload-pack=/tmp/evil",
            "https://example.invalid/repo.git",
        ],
    );
}

#[test]
fn benign_git_fetch_is_not_rejected_by_denylist() {
    // `git fetch origin` against a repo with no `origin` remote fails at
    // git's network/remote layer, NOT at the denylist. The denylist must
    // not be the thing that stops it: assert stderr does not carry the
    // contextcrawler deny message.
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    let out = ccrawl_in(&repo_path)
        .args(["git", "fetch", "origin"])
        .output()
        .expect("contextcrawler git fetch runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "benign `git fetch origin` must not trip the transport-flag denylist. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        stderr
    );
}

#[test]
fn benign_git_status_still_succeeds() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    let out = ccrawl_in(&repo_path)
        .args(["git", "status"])
        .output()
        .expect("contextcrawler git status runs");
    assert!(
        out.status.success(),
        "contextcrawler git status (no attack args) must still succeed. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- #111 G4 follow-up: value-taking option operands are not flags ---------
//
// `check_forbidden_git_args` rejected any token textually shaped like a
// forbidden transport flag, even when the token was the VALUE of a
// value-taking option (`-m`, `-F`, ...). A commit whose message happened to
// be `--upload-pack=x` was blocked before `run_commit` ran. The scanner now
// skips the operand after a recognised value-taking option.

#[test]
fn git_commit_message_shaped_like_forbidden_flag_is_not_rejected() {
    // `-m --upload-pack=x` — the second token is the commit MESSAGE.
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    std::fs::write(repo_path.join("f.txt"), "x").expect("write file");
    let staged = ccrawl_in(&repo_path)
        .args(["git", "add", "f.txt"])
        .output()
        .expect("git add runs");
    assert!(staged.status.success(), "git add must succeed");
    let out = ccrawl_in(&repo_path)
        .args(["git", "commit", "-m", "--upload-pack=x"])
        .output()
        .expect("contextcrawler git commit runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "`git commit -m --upload-pack=x` — the token is the message, not a \
         flag — must not trip the denylist. stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        stderr
    );
    assert!(
        out.status.success(),
        "the commit itself must succeed. stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        stderr
    );
}

#[test]
fn git_commit_message_exactly_exec_path_is_not_rejected() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    std::fs::write(repo_path.join("g.txt"), "y").expect("write file");
    let staged = ccrawl_in(&repo_path)
        .args(["git", "add", "g.txt"])
        .output()
        .expect("git add runs");
    assert!(staged.status.success(), "git add must succeed");
    let out = ccrawl_in(&repo_path)
        .args(["git", "commit", "-m", "--exec-path"])
        .output()
        .expect("contextcrawler git commit runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "`git commit -m --exec-path` must not trip the denylist. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        stderr
    );
}

#[test]
fn git_commit_attached_message_shaped_like_forbidden_flag_is_not_rejected() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    std::fs::write(repo_path.join("h.txt"), "z").expect("write file");
    let staged = ccrawl_in(&repo_path)
        .args(["git", "add", "h.txt"])
        .output()
        .expect("git add runs");
    assert!(staged.status.success(), "git add must succeed");
    let out = ccrawl_in(&repo_path)
        .args(["git", "commit", "--message=--receive-pack"])
        .output()
        .expect("contextcrawler git commit runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to forward"),
        "`git commit --message=--receive-pack` must not trip the denylist. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        stderr
    );
}

#[test]
fn git_commit_normal_message_still_works() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    std::fs::write(repo_path.join("i.txt"), "w").expect("write file");
    let staged = ccrawl_in(&repo_path)
        .args(["git", "add", "i.txt"])
        .output()
        .expect("git add runs");
    assert!(staged.status.success(), "git add must succeed");
    let out = ccrawl_in(&repo_path)
        .args(["git", "commit", "-m", "normal message"])
        .output()
        .expect("contextcrawler git commit runs");
    assert!(
        out.status.success(),
        "`git commit -m \"normal message\"` must still succeed. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- G4/#100: git exit-code propagation ------------------------------------
//
// run_status (compact), run_stash (list/show) and run_worktree (list) applied
// the output filter BEFORE checking git's exit code. A non-zero git exit was
// absorbed and the caller saw apparent success. These tests run each path in
// a NON-repo tempdir — git exits 128 — and assert contextcrawler propagates a
// non-zero exit instead of reporting success.

/// A bare tempdir that is deliberately NOT a git repo. git invoked here
/// exits non-zero ("fatal: not a git repository").
fn non_repo_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create non-repo tempdir")
}

#[test]
fn git_status_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "status"])
        .output()
        .expect("contextcrawler git status runs");
    assert!(
        !out.status.success(),
        "git status outside a repo must propagate a non-zero exit, not be \
         filtered into apparent success. stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_stash_list_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "stash", "list"])
        .output()
        .expect("contextcrawler git stash list runs");
    assert!(
        !out.status.success(),
        "git stash list outside a repo must propagate a non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_stash_show_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "stash", "show"])
        .output()
        .expect("contextcrawler git stash show runs");
    assert!(
        !out.status.success(),
        "git stash show outside a repo must propagate a non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn git_worktree_list_propagates_failure_exit_code() {
    let _guard = common::env_lock();
    let dir = non_repo_dir();
    let out = ccrawl_in(dir.path())
        .args(["git", "worktree", "list"])
        .output()
        .expect("contextcrawler git worktree list runs");
    assert!(
        !out.status.success(),
        "git worktree list outside a repo must propagate a non-zero exit. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn benign_git_log_still_succeeds() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();
    let out = ccrawl_in(&repo_path)
        .args(["git", "log", "-3", "--oneline"])
        .output()
        .expect("contextcrawler git log runs");
    assert!(
        out.status.success(),
        "contextcrawler git log -3 --oneline must still succeed. \
         stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// #239: `git stash -q` (bare quiet push) and `git stash --quiet` must not
/// hit clap's `unexpected argument` parse failure. Before the fix, `-q`
/// before the positional `[SUBCOMMAND]` was rejected by clap, the clap
/// error text was emitted, and the command fell back to raw passthrough at
/// 0 savings.
///
/// Runs in a throwaway repo so the bare `stash -q` cannot touch the
/// developer's real stash stack.
#[test]
fn git_stash_quiet_flag_parses_without_clap_error() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();

    // Bare quiet push: no stash entries exist yet in this fresh repo, so
    // git prints "No local changes to save" and exits 0 — the assertion is
    // that the command ran at all, with NO clap error text.
    let out = ccrawl_in(&repo_path)
        .args(["git", "stash", "-q"])
        .output()
        .expect("contextcrawler git stash -q runs");
    assert!(
        out.status.success(),
        "git stash -q must succeed, stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
        "stash -q must not emit a clap parse error: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Long form.
    let out = ccrawl_in(&repo_path)
        .args(["git", "stash", "--quiet"])
        .output()
        .expect("contextcrawler git stash --quiet runs");
    assert!(
        out.status.success(),
        "git stash --quiet must succeed, stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
        "stash --quiet must not emit a clap parse error: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A stashed change must exist for list -q to be meaningful; the
    // subcommand form routes -q through trailing args (already worked) and
    // must keep working now that -q is also a clap flag.
    let out = ccrawl_in(&repo_path)
        .args(["git", "stash", "list", "-q"])
        .output()
        .expect("contextcrawler git stash list -q runs");
    assert!(
        out.status.success(),
        "git stash list -q must succeed, stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
        "stash list -q must not emit a clap parse error: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// #238: a clap parse failure on a KNOWN subcommand that is not a real
/// binary must show the clap error with a non-zero exit, never fall back
/// to exec'ing the subcommand name as a binary.
///
/// `read` is a contextcrawler subcommand and a shell builtin — there is no
/// `read` binary to fall back to, so the old path emitted
/// "No such file or directory" and (on some paths) exited 0, reporting a
/// total failure as success. `read FILE --max-lines 2 --tail-lines 3`
/// triggers a clap conflict (the two window flags are mutually exclusive).
#[test]
fn read_parse_conflict_shows_clap_error_not_binary_exec() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();

    let out = ccrawl_in(&repo_path)
        .args(["read", "a.txt", "--max-lines", "2", "--tail-lines", "3"])
        .output()
        .expect("contextcrawler read with conflicting flags runs");
    assert!(
        !out.status.success(),
        "conflicting read flags must exit non-zero, got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "clap conflict message expected, stderr={stderr}"
    );
    assert!(
        !stderr.contains("No such file or directory"),
        "must not try to exec `read` as a binary, stderr={stderr}"
    );
    assert!(
        !stderr.contains("Failed to resolve"),
        "must not take the binary-resolution fallback path, stderr={stderr}"
    );
}

/// #238 companion: an unknown subcommand (genuinely foreign) still falls
/// back to raw execution — the fix must not break graceful degradation
/// for real external commands.
#[test]
fn foreign_subcommand_still_falls_back_to_raw_exec() {
    let _guard = common::env_lock();
    let (_repo, repo_path) = make_repo();

    let out = ccrawl_in(&repo_path)
        .args(["bash", "-c", "echo FOREIGN_FALLBACK_OK"])
        .output()
        .expect("contextcrawler bash -c runs");
    assert!(
        out.status.success(),
        "foreign command must fall back to raw exec, stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("FOREIGN_FALLBACK_OK"),
        "foreign command output must reach the caller"
    );
}
